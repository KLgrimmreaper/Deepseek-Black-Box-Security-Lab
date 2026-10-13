import threading
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import db, report
from .catalogue import CATALOGUE, CATALOGUE_BY_ID
from .config import BASE_DIR, load_config
from .runner import create_run, execute_run
from .scope import Scope, ScopeError

app = FastAPI(title="deepseek black-box security lab")


class NewRun(BaseModel):
    target: str
    notes: str = ""


@app.get("/api/health")
def health():
    config = load_config()
    return {
        "status": "ok",
        "mock_agent": config["mock_agent"],
        "has_api_key": bool(config["deepseek_api_key"]),
        "model": config["deepseek_model"],
        "allowed_targets": config["allowed_targets"],
        "max_requests_per_run": config["max_requests_per_run"],
        "checks": len(CATALOGUE),
    }


@app.get("/api/checks")
def list_checks():
    return {"checks": CATALOGUE}


@app.post("/api/runs")
def start_run(payload: NewRun):
    config = load_config()
    target = payload.target.strip()
    try:
        # validate before a worker thread is started, so a bad target comes back as a 400
        Scope(target, config["allowed_targets"])
    except ScopeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    run_id = create_run(target, payload.notes, config)
    # the run blocks on http and sqlite, so it goes in its own thread and the dashboard polls the db
    thread = threading.Thread(target=execute_run, args=(run_id, target, config), daemon=True)
    thread.start()
    return {"run_id": run_id, "status": "started"}


@app.get("/api/runs")
def get_runs():
    config = load_config()
    return {"runs": db.list_runs(config["db_path"])}


@app.get("/api/runs/{run_id}")
def get_run(run_id: int):
    config = load_config()
    run = db.get_run(config["db_path"], run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"run {run_id} does not exist")
    return {
        "run": run,
        "plan": report.parse_plan(run),
        "results": db.get_check_results(config["db_path"], run_id),
        "findings": db.get_findings(config["db_path"], run_id),
    }


@app.get("/api/runs/{run_id}/report", response_class=PlainTextResponse)
def get_report(run_id: int):
    config = load_config()
    run = db.get_run(config["db_path"], run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"run {run_id} does not exist")
    path = Path(config["reports_dir"]) / f"run_{run_id}.md"
    if path.exists():
        return path.read_text(encoding="utf-8")
    # a run that is still going has no report file yet
    return report.render_report(
        run,
        report.parse_plan(run),
        db.get_check_results(config["db_path"], run_id),
        db.get_findings(config["db_path"], run_id),
    )


@app.get("/api/runs/{run_id}/evidence/{check_id}", response_class=PlainTextResponse)
def get_evidence(run_id: int, check_id: str):
    if check_id not in CATALOGUE_BY_ID:
        # only ids from the catalogue are readable, so the path can never be talked out of the evidence folder
        raise HTTPException(status_code=404, detail=f"{check_id} is not a check in the catalogue")
    config = load_config()
    path = Path(config["evidence_dir"]) / str(run_id) / f"{check_id}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"no evidence file for {check_id} in run {run_id}")
    return path.read_text(encoding="utf-8")


frontend_dist = BASE_DIR / "frontend" / "dist"
if frontend_dist.exists():
    # after npm run build the dashboard is served from the same origin as the api
    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="dashboard")
