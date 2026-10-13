import json
import traceback
from pathlib import Path

import requests

from . import agent, checks, db, report
from .catalogue import CATALOGUE, CATALOGUE_BY_ID, unmet_requirement
from .config import BASE_DIR
from .recon import collect_recon
from .scope import Scope, ScopeError

# the two results that produce a finding. failed means the check demonstrated the condition,
# needs_review means it only observed something consistent with it, and the finding keeps that
# distinction so the report never presents a suspicion as a confirmed vulnerability.
FINDING_RESULTS = ("failed", "needs_review")


def _approve_plan(items, remaining, profile, cfg, already_run):
    """the deterministic gate between the model and the network.

    the model proposes catalogue ids, this decides which of them may actually run: the id has
    to be in the catalogue, still available, inside the per run limit, and its prerequisites
    have to have been observed on the target. anything else is refused here, in python.
    """
    approved = []
    blocked = []
    over_limit = []
    room = max(0, cfg["max_checks_per_run"] - already_run)
    for item in items:
        check_id = item["id"]
        if check_id not in remaining:
            continue
        if len(approved) >= room:
            over_limit.append({"id": check_id, "reason": "over the per run check limit"})
            continue
        unmet = unmet_requirement(CATALOGUE_BY_ID[check_id], profile)
        if unmet:
            blocked.append({"id": check_id, "reason": unmet})
            continue
        approved.append(item)
    return approved, blocked, over_limit


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
        ca_bundle=cfg["ca_bundle"],
    )
    try:
        recon = collect_recon(scope, cfg)
    except requests.exceptions.SSLError as exc:
        # a certificate problem is a connection problem, not a weakness in the target
        raise ScopeError(f"TLS certificate verification failed for {scope.origin}: {exc}") from exc
    except requests.exceptions.ConnectionError as exc:
        # ConnectTimeout subclasses both ConnectionError and Timeout, so this has to come first
        # or a refused or unreachable host gets reported as a slow one
        raise ScopeError(f"could not connect to {scope.origin}: {exc}") from exc
    except requests.exceptions.Timeout as exc:
        raise ScopeError(
            f"{scope.origin} did not answer within {cfg['request_timeout']}s, so the run was stopped: {exc}"
        ) from exc
    except ScopeError as exc:
        raise ScopeError(
            f"reconnaissance used up the request budget ({exc}), so raise MAX_REQUESTS_PER_RUN"
        ) from exc

    profile = recon["profile"]
    db.set_run_profile(cfg["db_path"], run_id, profile)
    # the checks read the observed facts from here, so a login check knows which request format
    # the target actually speaks and which field names its form uses
    cfg["profile"] = profile
    if on_progress:
        on_progress(
            f"target looks like {profile['application_shape']} with a {profile['login_shape']} login"
        )

    evidence_dir = Path(cfg["evidence_dir"]) / str(run_id)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    candidates = []
    results_so_far = []
    rounds = []
    skipped = []
    remaining = [entry["id"] for entry in CATALOGUE]
    checks_run = 0
    round_number = 0

    while remaining and round_number < cfg["max_iterations"]:
        if scope.requests_sent >= scope.max_requests:
            if on_progress:
                on_progress("request budget reached, stopping")
            break
        round_number += 1

        if only_checks and round_number == 1:
            plan = agent.manual_plan(only_checks, cfg, remaining)
        else:
            stage(f"planning round {round_number}")
            plan = agent.plan_checks(recon, cfg, remaining, results_so_far, round_number)

        approved, blocked, over_limit = _approve_plan(plan["checks"], remaining, profile, cfg, checks_run)
        skipped += plan["skipped"] + over_limit

        for item in blocked:
            # a check whose prerequisites were never observed gets an honest not_applicable row
            entry = CATALOGUE_BY_ID[item["id"]]
            remaining.remove(item["id"])
            stage(f"skipping {item['id']}: prerequisites not met")
            db.add_check_result(
                cfg["db_path"], run_id,
                check_id=item["id"],
                name=entry["name"],
                severity=entry["severity"],
                result="not_applicable",
                detail=item["reason"],
                reason="prerequisites not met",
                round_number=round_number,
            )
            results_so_far.append({"id": item["id"], "result": "not_applicable", "detail": item["reason"]})

        if not approved:
            if on_progress:
                on_progress("nothing left that can run against this target")
            break

        rounds.append(
            {
                "round": round_number,
                "source": plan["source"],
                "note": plan.get("note", ""),
                "done": plan["done"],
                "checks": [{"id": item["id"], "reason": item["reason"]} for item in approved],
            }
        )
        db.set_run_plan(cfg["db_path"], run_id, _report_plan(rounds, skipped))
        if on_progress:
            on_progress(f"round {round_number}: {len(approved)} check(s) from {plan['source']}")

        total = len(approved)
        for index, item in enumerate(approved, start=1):
            entry = CATALOGUE_BY_ID[item["id"]]
            remaining.remove(item["id"])
            checks_run += 1
            stage(f"running {item['id']} ({index} of {total})")
            requests_before = scope.requests_sent
            try:
                outcome = checks.CHECKS[item["id"]](scope, cfg)
            except ScopeError as exc:
                outcome = {"result": "error", "detail": str(exc), "evidence": {"note": "the check did not complete"}}
            except requests.exceptions.SSLError as exc:
                outcome = {
                    "result": "error",
                    "detail": f"TLS certificate verification failed, so this check could not run: {exc}",
                    "evidence": {"note": "the request was refused by the local tls trust settings"},
                }
            except requests.exceptions.ConnectionError as exc:
                outcome = {
                    "result": "error",
                    "detail": f"the connection failed, so this check could not run: {exc}",
                    "evidence": {"note": "the target could not be reached"},
                }
            except requests.exceptions.Timeout as exc:
                # after ConnectionError, because ConnectTimeout is both
                outcome = {
                    "result": "error",
                    "detail": f"the request timed out after {cfg['request_timeout']}s, so this check could not run: {exc}",
                    "evidence": {"note": "the target did not answer in time"},
                }
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
            if result in FINDING_RESULTS and evidence_path is None:
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
                round_number=round_number,
            )
            results_so_far.append({"id": item["id"], "result": result, "detail": detail[:160]})
            if result in FINDING_RESULTS:
                candidates.append(
                    {
                        "check_id": item["id"],
                        "entry": entry,
                        "result": result,
                        "detail": detail,
                        "evidence_path": evidence_path,
                        "excerpt": _evidence_excerpt(outcome["evidence"]),
                    }
                )

        if plan["done"]:
            if on_progress and plan.get("note"):
                on_progress(f"stopping: {plan['note']}")
            break

    skipped += [{"id": check_id, "reason": "never planned"} for check_id in remaining]

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
            # the check already said how strong its own evidence was, so that carries into the finding
            status="confirmed" if item["result"] == "failed" else "needs_review",
            evidence_path=item["evidence_path"],
            description=f"{item['detail']}. this was recorded by the runner from the responses above, not by the model.",
            impact=impact,
            remediation=remediation,
            model_generated=1 if explanation else 0,
        )

    results = db.get_check_results(cfg["db_path"], run_id)
    findings = db.get_findings(cfg["db_path"], run_id)
    summary = agent.summarise(scope.origin, results, len(findings), cfg)

    final_plan = _report_plan(rounds, skipped)
    db.set_run_plan(cfg["db_path"], run_id, final_plan)

    if on_progress:
        on_progress("writing the report")
    db.finish_run(
        cfg["db_path"], run_id,
        status="finished",
        summary=summary["text"],
        summary_source="model" if summary["model_generated"] else "runner",
        request_count=scope.requests_sent,
    )
    _save_report(run_id, final_plan, results, findings, cfg)
    return run_id


def _report_plan(rounds, skipped):
    """the plan as the report needs it: what was asked for, in which round, and what was not run."""
    return {
        "source": rounds[0]["source"] if rounds else "none",
        "rounds": [{"round": item["round"], "note": item["note"], "done": item["done"]} for item in rounds],
        "checks": [
            {"id": check["id"], "reason": check["reason"], "round": item["round"]}
            for item in rounds
            for check in item["checks"]
        ],
        "skipped": skipped,
    }


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
