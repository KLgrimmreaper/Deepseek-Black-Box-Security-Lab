import os
import sqlite3

from backend import db
from backend.config import load_config


def make_db(tmp_path):
    cfg = load_config({"db_path": tmp_path / "lab.db"})
    db.init_db(cfg["db_path"])
    return cfg["db_path"]


def test_the_liveness_check_agrees_with_reality():
    # this process is alive, and a pid that never existed is not
    assert db._pid_alive(os.getpid()) is True
    assert db._pid_alive(999999) is False
    assert db._pid_alive(None) is False


def test_a_run_left_by_a_dead_process_is_closed_on_the_next_start(tmp_path):
    db_path = make_db(tmp_path)
    run_id = db.create_run(db_path, "http://localhost:3000", "", "mock agent")
    # pretend the process that owned it is gone
    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE runs SET pid = ? WHERE id = ?", (999999, run_id))

    assert db.mark_interrupted_runs(db_path) == 1

    run = db.get_run(db_path, run_id)
    assert run["status"] == "failed"
    assert run["stage"] == ""
    assert run["error"] == db.INTERRUPTED_MESSAGE
    assert run["finished_at"] is not None


def test_a_run_owned_by_a_live_process_is_left_alone(tmp_path):
    db_path = make_db(tmp_path)
    # a run started by this very process is still live, for example a cli run in another terminal
    run_id = db.create_run(db_path, "http://localhost:3000", "", "mock agent")

    assert db.mark_interrupted_runs(db_path) == 0
    assert db.get_run(db_path, run_id)["status"] == "running"


def test_finished_runs_are_never_touched(tmp_path):
    db_path = make_db(tmp_path)
    run_id = db.create_run(db_path, "http://localhost:3000", "", "mock agent")
    db.finish_run(db_path, run_id, status="finished", summary="done", request_count=3)
    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE runs SET pid = ? WHERE id = ?", (999999, run_id))

    assert db.mark_interrupted_runs(db_path) == 0
    run = db.get_run(db_path, run_id)
    assert run["status"] == "finished"
    assert run["summary"] == "done"


def test_a_new_run_records_the_current_process(tmp_path):
    db_path = make_db(tmp_path)
    run_id = db.create_run(db_path, "http://localhost:3000", "", "mock agent")
    assert db.get_run(db_path, run_id)["pid"] == os.getpid()


def test_an_older_database_without_the_pid_column_still_opens(tmp_path):
    db_path = make_db(tmp_path)
    # rebuild the table the way it looked before the pid column existed
    with sqlite3.connect(db_path) as conn:
        conn.execute("ALTER TABLE runs DROP COLUMN pid")
        conn.execute(
            "INSERT INTO runs (target, status, stage, model, notes, started_at) "
            "VALUES ('http://localhost:3000', 'running', 'running robots_disclosure (1 of 1)', 'mock agent', '', '2026-01-01T00:00:00+00:00')"
        )

    db.init_db(db_path)  # this is what the api does at startup

    with sqlite3.connect(db_path) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(runs)")}
    assert "pid" in columns

    # the row from the old database has no pid, so it cannot be running any more
    assert db.mark_interrupted_runs(db_path) == 1
    assert db.get_run(db_path, 1)["status"] == "failed"
