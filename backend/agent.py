import json

import requests

from .catalogue import CATALOGUE_BY_ID, model_summary
from .scope import body_snippet

DEEPSEEK_URL = "https://api.deepseek.com/chat/completions"

PLAN_SYSTEM_PROMPT = (
    "you choose which web application security checks to run against one authorised lab target. "
    "pick ids from the list you are given and never invent a check id. "
    "you choose what to test, the runner decides what the result is. "
    "answer with json only."
)

EXPLAIN_SYSTEM_PROMPT = (
    "you write up web security findings for a student lab report. "
    "the result and the evidence were recorded by the test runner before you see them. "
    "do not change a result, do not add a finding, and do not claim anything the evidence does not show. "
    "answer with json only."
)

SUMMARY_SYSTEM_PROMPT = (
    "you write a short factual summary of a web security test run for a student lab report. "
    "only use the numbers and results you are given and do not exaggerate. "
    "answer with json only."
)


class AgentError(Exception):
    pass


def is_mock(cfg):
    return bool(cfg["mock_agent"])


def _chat(cfg, system_prompt, user_prompt):
    if not cfg["deepseek_api_key"]:
        raise AgentError("DEEPSEEK_API_KEY is empty, set it in .env or run with mock mode")
    payload = {
        "model": cfg["deepseek_model"],
        "temperature": 0,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    headers = {"Authorization": f"Bearer {cfg['deepseek_api_key']}"}
    try:
        response = requests.post(DEEPSEEK_URL, json=payload, headers=headers, timeout=(10, 60))
    except requests.RequestException as exc:
        raise AgentError(f"could not reach the deepseek api: {exc}") from exc
    if response.status_code != 200:
        raise AgentError(f"deepseek answered {response.status_code}: {body_snippet(response, 300)}")
    try:
        content = response.json()["choices"][0]["message"]["content"]
    except (KeyError, IndexError, ValueError) as exc:
        raise AgentError(f"unexpected response shape from deepseek: {exc}") from exc
    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:
        raise AgentError(f"deepseek did not answer with json: {exc}") from exc


def _validated_checks(items, cfg):
    planned = []
    skipped = []
    seen = set()
    for item in items:
        check_id = str(item.get("id", "")).strip()
        reason = str(item.get("reason", "")).strip()
        if check_id not in CATALOGUE_BY_ID:
            skipped.append({"id": check_id, "reason": "not in the catalogue"})
            continue
        if check_id in seen:
            continue
        seen.add(check_id)
        planned.append({"id": check_id, "reason": reason})
    limit = cfg["max_checks_per_run"]
    if len(planned) > limit:
        skipped += [{"id": item["id"], "reason": "over the per run check limit"} for item in planned[limit:]]
        planned = planned[:limit]
    return planned, skipped


def mock_plan(cfg):
    planned = [{"id": entry["id"], "reason": "mock agent, every catalogue check is planned"} for entry in model_summary()]
    return {"source": "mock", "checks": planned[: cfg["max_checks_per_run"]], "skipped": []}


def manual_plan(check_ids, cfg):
    planned, skipped = _validated_checks([{"id": check_id, "reason": "requested with --only"} for check_id in check_ids], cfg)
    return {"source": "manual", "checks": planned, "skipped": skipped}


def plan_checks(recon, cfg):
    if is_mock(cfg):
        return mock_plan(cfg)
    prompt = json.dumps(
        {
            "task": "pick the checks worth running against this target",
            "target": recon["target"],
            "https": recon["https"],
            "recon": recon["observations"],
            "available_checks": model_summary(),
            "answer_format": {"checks": [{"id": "an id from available_checks", "reason": "one short sentence"}]},
        },
        indent=2,
    )
    answer = _chat(cfg, PLAN_SYSTEM_PROMPT, prompt)
    planned, skipped = _validated_checks(answer.get("checks", []), cfg)
    if not planned:
        raise AgentError("the model did not return any usable check ids")
    return {"source": "model", "checks": planned, "skipped": skipped}


def explain_findings(items, cfg):
    # items: [{"check_id", "name", "severity", "detail", "evidence_excerpt"}]
    # returns {check_id: {"impact", "remediation"}} and never raises, because a failed
    # explanation should not remove a finding that already has recorded evidence
    if not items or is_mock(cfg) or not cfg["deepseek_api_key"]:
        return {}
    prompt = json.dumps(
        {
            "task": "for each finding write a short impact and a short remediation, referring to the evidence",
            "findings": items,
            "answer_format": {"explanations": [{"id": "check id", "impact": "1 to 2 sentences",
                                                "remediation": "1 to 2 sentences"}]},
        },
        indent=2,
    )
    try:
        answer = _chat(cfg, EXPLAIN_SYSTEM_PROMPT, prompt)
    except AgentError:
        return {}
    explanations = {}
    for item in answer.get("explanations", []):
        check_id = str(item.get("id", "")).strip()
        if check_id in {entry["check_id"] for entry in items}:
            explanations[check_id] = {
                "impact": str(item.get("impact", "")).strip(),
                "remediation": str(item.get("remediation", "")).strip(),
            }
    return explanations


def summarise(target, results, finding_count, cfg):
    counts = {}
    for result in results:
        counts[result["result"]] = counts.get(result["result"], 0) + 1
    breakdown = ", ".join(f"{count} {name}" for name, count in sorted(counts.items()))
    if is_mock(cfg) or not cfg["deepseek_api_key"]:
        return {
            "text": f"{len(results)} checks were run against {target}: {breakdown}. "
                    f"{finding_count} of them produced a finding. this summary was written by the runner, "
                    "not by the model.",
            "model_generated": False,
        }
    prompt = json.dumps(
        {
            "task": "summarise this test run in 2 to 4 sentences",
            "target": target,
            "check_totals": counts,
            "findings": finding_count,
            "results": [{"id": r["check_id"], "result": r["result"], "detail": r["detail"]} for r in results],
            "answer_format": {"summary": "2 to 4 factual sentences"},
        },
        indent=2,
    )
    try:
        answer = _chat(cfg, SUMMARY_SYSTEM_PROMPT, prompt)
    except AgentError:
        return {
            "text": f"{len(results)} checks were run against {target}: {breakdown}. "
                    f"{finding_count} of them produced a finding. the model summary was unavailable.",
            "model_generated": False,
        }
    text = str(answer.get("summary", "")).strip()
    if not text:
        return {"text": f"{len(results)} checks were run against {target}: {breakdown}.", "model_generated": False}
    return {"text": text, "model_generated": True}
