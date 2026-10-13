import json
import traceback
from pathlib import Path

from . import agent, checks, db, report
from .catalogue import CATALOGUE_BY_ID
from .config import BASE_DIR
from .scope import Scope, ScopeError, body_snippet

# checks where a failed result is worth showing but a human should decide if it counts
SOFT_CHECKS = {"server_info_disclosure", "robots_disclosure", "rate_limit", "http_methods"}


def collect_recon(scope):
    base = scope.get("/")
    options = scope.request("OPTIONS", "/")
    head = scope.request("HEAD", "/")
    observations = {
        "root_status": base.status_code,
        "root_content_type": base.headers.get("Content-Type", ""),
        "server_header": base.headers.get("Server", ""),
        "powered_by": base.headers.get("X-Powered-By", ""),
        "allow_header": options.headers.get("Allow", ""),
        "head_status": head.status_code,
        "body_start": body_snippet(base, 300),
    }
    return {"target": scope.origin, "https": scope.is_https, "observations": observations}


def _evidence_excerpt(evidence, limit=600):
    parts = []
    if isinstance(evidence.get("status"), int):
        parts.append(f"status {evidence['status']}")
    for key in ("body", "body_snippet", "body_start"):
        value = evidence.get(key)
        if isinstance(value, str) and value.strip():
            parts.append(value)
            break
    if not parts:
        parts.append(json.dumps(evidence, default=str))
    return " ".join(parts)[:limit]


def _write_evidence(evidence_dir, check_id, payload):
    path = evidence_dir / f"{check_id}.json"
    try:
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    except OSError:
        return None
    try:
        # store the path relative to the project so the report and the ui stay readable
        return path.relative_to(BASE_DIR).as_posix()
    except ValueError:
        return path.as_posix()


def _run_checks(run_id, target, cfg, only_checks, on_progress=None):
    def stage(message):
        # the stage is stored so the dashboard can show it, and handed to the cli so a
        # terminal run is not silent for two minutes
        db.set_run_stage(cfg["db_path"], run_id, message)
        if on_progress:
            on_progress(message)

    stage("checking the target")
    scope = Scope(
        target,
        cfg["allowed_targets"],
        max_requests=cfg["max_requests_per_run"],
        delay_ms=cfg["request_delay_ms"],
        timeout=cfg["request_timeout"],
    )
    recon = collect_recon(scope)

    if only_checks:
        plan = agent.manual_plan(only_checks, cfg)
    else:
        stage("planning the checks")
        plan = agent.plan_checks(recon, cfg)
    db.set_run_plan(cfg["db_path"], run_id, plan)

    evidence_dir = Path(cfg["evidence_dir"]) / str(run_id)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    if on_progress:
        on_progress(f"planned {len(plan['checks'])} check(s) from {plan['source']}")

    candidates = []
    total = len(plan["checks"])
    for index, item in enumerate(plan["checks"], start=1):
        entry = CATALOGUE_BY_ID[item["id"]]
        stage(f"running {item['id']} ({index} of {total})")
        requests_before = scope.requests_sent
        try:
            outcome = checks.CHECKS[item["id"]](scope, cfg)
        except ScopeError as exc:
            outcome = {"result": "error", "detail": str(exc), "evidence": {"note": "the check did not complete"}}
        except Exception as exc:
            # one broken check should not throw away the results of the others
            outcome = {
                "result": "error",
                "detail": f"{type(exc).__name__}: {exc}",
                "evidence": {"traceback": traceback.format_exc()},
            }
        requests_used = scope.requests_sent - requests_before

        payload = {"target": scope.origin, "check": item["id"], "reason": item["reason"], **outcome["evidence"]}
        evidence_path = _write_evidence(evidence_dir, item["id"], payload)
        result = outcome["result"]
        detail = outcome["detail"]
        if result == "failed" and evidence_path is None:
            # no evidence on disk means no finding, the run can only record that it failed to record
            result = "error"
            detail = f"{detail} (the evidence file could not be written, so no finding was created)"

        db.add_check_result(
            cfg["db_path"], run_id,
            check_id=item["id"],
            name=entry["name"],
            severity=entry["severity"],
            result=result,
            detail=detail,
            reason=item["reason"],
            evidence_path=evidence_path,
            requests_used=requests_used,
        )
        if result == "failed":
            candidates.append(
                {
                    "check_id": item["id"],
                    "entry": entry,
                    "detail": detail,
                    "evidence_path": evidence_path,
                    "excerpt": _evidence_excerpt(outcome["evidence"]),
                }
            )

    if candidates:
        stage(f"writing up {len(candidates)} finding(s)")

    explanations = agent.explain_findings(
        [
            {
                "check_id": item["check_id"],
                "name": item["entry"]["name"],
                "severity": item["entry"]["severity"],
                "detail": item["detail"],
                "evidence_excerpt": item["excerpt"],
            }
            for item in candidates
        ],
        cfg,
    )

    for item in candidates:
        entry = item["entry"]
        explanation = explanations.get(item["check_id"], {})
        impact = explanation.get("impact") or (
            "not written by the model. read the evidence file and decide the impact before reporting this."
        )
        remediation = explanation.get("remediation") or f"{entry['fix']} (catalogue text)"
        db.add_finding(
            cfg["db_path"], run_id,
            check_id=item["check_id"],
            title=entry["name"],
            severity=entry["severity"],
            status="needs_review" if item["check_id"] in SOFT_CHECKS else "confirmed",
            evidence_path=item["evidence_path"],
            description=f"{item['detail']}. this was recorded by the runner from the responses above, not by the model.",
            impact=impact,
            remediation=remediation,
            model_generated=1 if explanation else 0,
        )

    results = db.get_check_results(cfg["db_path"], run_id)
    findings = db.get_findings(cfg["db_path"], run_id)
    summary = agent.summarise(scope.origin, results, len(findings), cfg)

    if on_progress:
        on_progress("writing the report")
    db.finish_run(
        cfg["db_path"], run_id,
        status="finished",
        summary=summary["text"],
        summary_source="model" if summary["model_generated"] else "runner",
        request_count=scope.requests_sent,
    )
    _save_report(run_id, plan, results, findings, cfg)
    return run_id


def _save_report(run_id, plan, results, findings, cfg):
    run = db.get_run(cfg["db_path"], run_id)
    try:
        report.write_report(run, plan, results, findings, cfg)
    except OSError as exc:
        db.finish_run(
            cfg["db_path"], run_id,
            status="finished",
            summary=run["summary"],
            summary_source=run["summary_source"],
            request_count=run["request_count"],
            error=f"the report file could not be written: {exc}",
        )


def _fail(cfg, run_id, message):
    db.finish_run(cfg["db_path"], run_id, status="failed", error=message)
    # a failed run still gets a report, so the dashboard has something to show
    _save_report(
        run_id,
        report.parse_plan(db.get_run(cfg["db_path"], run_id)),
        db.get_check_results(cfg["db_path"], run_id),
        db.get_findings(cfg["db_path"], run_id),
        cfg,
    )


def create_run(target, notes, cfg):
    db.init_db(cfg["db_path"])
    model_label = cfg["deepseek_model"] if not agent.is_mock(cfg) else "mock agent (no api calls)"
    return db.create_run(cfg["db_path"], target, notes, model_label)


def execute_run(run_id, target, cfg, only_checks=None, on_progress=None):
    # errors are recorded on the run instead of raised, so a broken run still shows up in the dashboard
    try:
        _run_checks(run_id, target, cfg, only_checks, on_progress)
    except (ScopeError, agent.AgentError) as exc:
        _fail(cfg, run_id, str(exc))
    except Exception as exc:
        _fail(cfg, run_id, f"unexpected error: {type(exc).__name__}: {exc}")
    return run_id


def run_pipeline(target, notes, cfg, only_checks=None, on_progress=None):
    run_id = create_run(target, notes, cfg)
    return execute_run(run_id, target, cfg, only_checks, on_progress)
