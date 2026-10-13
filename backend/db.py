import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT NOT NULL,
  status TEXT NOT NULL,
  stage TEXT NOT NULL DEFAULT '',
  model TEXT NOT NULL DEFAULT '',
  notes TEXT NOT NULL DEFAULT '',
  summary TEXT NOT NULL DEFAULT '',
  summary_source TEXT NOT NULL DEFAULT '',
  planned_json TEXT NOT NULL DEFAULT '{}',
  request_count INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  started_at TEXT NOT NULL,
  finished_at TEXT
);

CREATE TABLE IF NOT EXISTS check_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  check_id TEXT NOT NULL,
  name TEXT NOT NULL,
  severity TEXT NOT NULL,
  result TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT '',
  evidence_path TEXT,
  requests_used INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  check_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT NOT NULL,
  evidence_path TEXT NOT NULL,
  description TEXT NOT NULL,
  impact TEXT NOT NULL DEFAULT '',
  remediation TEXT NOT NULL DEFAULT '',
  model_generated INTEGER NOT NULL DEFAULT 0
);
"""


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(db_path):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def db_connection(db_path):
    conn = connect(db_path)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path):
    with db_connection(db_path) as conn:
        # the api runs a test in a worker thread while the dashboard polls the same file
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(SCHEMA)


def create_run(db_path, target, notes, model):
    with db_connection(db_path) as conn:
        cursor = conn.execute(
            "INSERT INTO runs (target, status, stage, model, notes, started_at) VALUES (?, ?, ?, ?, ?, ?)",
            (target, "running", "starting", model, notes, now()),
        )
        return cursor.lastrowid


def set_run_stage(db_path, run_id, stage):
    with db_connection(db_path) as conn:
        conn.execute("UPDATE runs SET stage = ? WHERE id = ?", (stage, run_id))


def set_run_plan(db_path, run_id, planned):
    with db_connection(db_path) as conn:
        conn.execute("UPDATE runs SET planned_json = ? WHERE id = ?", (json.dumps(planned), run_id))


def finish_run(db_path, run_id, status, summary="", summary_source="", request_count=0, error=None):
    with db_connection(db_path) as conn:
        conn.execute(
            "UPDATE runs SET status = ?, stage = '', summary = ?, summary_source = ?, request_count = ?, "
            "error = ?, finished_at = ? WHERE id = ?",
            (status, summary, summary_source, request_count, error, now(), run_id),
        )


def add_check_result(db_path, run_id, check_id, name, severity, result, detail="", reason="",
                     evidence_path=None, requests_used=0):
    with db_connection(db_path) as conn:
        conn.execute(
            "INSERT INTO check_results (run_id, check_id, name, severity, result, detail, reason, evidence_path,"
            " requests_used) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, check_id, name, severity, result, detail, reason, evidence_path, requests_used),
        )


def add_finding(db_path, run_id, check_id, title, severity, status, evidence_path, description,
                impact="", remediation="", model_generated=0):
    with db_connection(db_path) as conn:
        conn.execute(
            "INSERT INTO findings (run_id, check_id, title, severity, status, evidence_path, description, impact,"
            " remediation, model_generated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, check_id, title, severity, status, evidence_path, description, impact, remediation,
             int(model_generated)),
        )


def get_run(db_path, run_id):
    with db_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        return dict(row) if row else None


def list_runs(db_path, limit=50):
    with db_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT runs.*, (SELECT COUNT(*) FROM findings WHERE findings.run_id = runs.id) AS finding_count "
            "FROM runs ORDER BY runs.id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]


def get_check_results(db_path, run_id):
    with db_connection(db_path) as conn:
        rows = conn.execute("SELECT * FROM check_results WHERE run_id = ? ORDER BY id", (run_id,)).fetchall()
        return [dict(row) for row in rows]


def get_findings(db_path, run_id):
    with db_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM findings WHERE run_id = ? ORDER BY CASE severity "
            "WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END, id",
            (run_id,),
        ).fetchall()
        return [dict(row) for row in rows]
