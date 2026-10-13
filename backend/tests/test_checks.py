from pathlib import Path

from backend import db
from backend.catalogue import catalogue_ids
from backend.checks import CHECKS
from backend.config import BASE_DIR, load_config
from backend.runner import run_pipeline
from backend.tests.fake_target import FakeTarget


def make_config(target, tmp_path, **overrides):
    settings = {
        "allowed_targets": [target],
        "mock_agent": True,
        "request_delay_ms": 0,
        "db_path": tmp_path / "lab.db",
        "evidence_dir": tmp_path / "evidence",
        "reports_dir": tmp_path / "reports",
        "credentials": ["admin@example.com:fakepass1", "nobody@example.com:wrong-password"],
    }
    settings.update(overrides)
    return load_config(settings)


def test_every_catalogue_entry_has_a_check_function():
    # catches the case where a check is added to one list and forgotten in the other
    assert sorted(catalogue_ids()) == sorted(CHECKS.keys())


def test_sloppy_target_fails_the_expected_checks(tmp_path):
    target = FakeTarget(hardened=False)
    try:
        cfg = make_config(target.origin, tmp_path)
        run_id = run_pipeline(target.origin, "test run", cfg, only_checks=catalogue_ids())
        results = {row["check_id"]: row for row in db.get_check_results(cfg["db_path"], run_id)}

        failed = {check_id for check_id, row in results.items() if row["result"] == "failed"}
        assert failed == {
            "security_headers",
            "server_info_disclosure",
            "cookie_flags",
            "cors_policy",
            "http_methods",
            "robots_disclosure",
            "sensitive_paths",
            "error_disclosure",
            "sql_injection_login",
            "reflected_xss",
            "open_redirect",
            "weak_credentials",
            "rate_limit",
        }
        assert db.get_run(cfg["db_path"], run_id)["status"] == "finished"
    finally:
        target.stop()


def test_hardened_target_passes_the_expected_checks(tmp_path):
    target = FakeTarget(hardened=True)
    try:
        cfg = make_config(target.origin, tmp_path)
        run_id = run_pipeline(target.origin, "hardened run", cfg, only_checks=catalogue_ids())
        results = {row["check_id"]: row for row in db.get_check_results(cfg["db_path"], run_id)}

        for check_id in [
            "security_headers",
            "server_info_disclosure",
            "cookie_flags",
            "cors_policy",
            "http_methods",
            "sensitive_paths",
            "error_disclosure",
            "sql_injection_login",
            "reflected_xss",
            "open_redirect",
            "weak_credentials",
            "rate_limit",
        ]:
            assert results[check_id]["result"] == "passed", f"{check_id}: {results[check_id]['detail']}"
        assert db.get_findings(cfg["db_path"], run_id) == []
    finally:
        target.stop()


def test_spa_fallback_is_not_reported_as_an_exposed_path(tmp_path):
    target = FakeTarget(hardened=False)
    try:
        cfg = make_config(target.origin, tmp_path)
        run_id = run_pipeline(target.origin, "", cfg, only_checks=["sensitive_paths"])
        row = db.get_check_results(cfg["db_path"], run_id)[0]
        evidence = (tmp_path / "evidence" / str(run_id) / "sensitive_paths.json").read_text(encoding="utf-8")

        assert row["result"] == "failed"
        assert "/admin" in evidence
        assert "client side route" in evidence
        assert '"path": "/.env"' in evidence
    finally:
        target.stop()


def test_failed_check_without_evidence_is_recorded_as_error(tmp_path, monkeypatch):
    from backend import runner

    target = FakeTarget(hardened=False)
    try:
        cfg = make_config(target.origin, tmp_path)
        # a failed check whose evidence cannot be written must not become a finding
        monkeypatch.setattr(runner, "_write_evidence", lambda *args, **kwargs: None)
        run_id = run_pipeline(target.origin, "", cfg, only_checks=["security_headers"])

        results = db.get_check_results(cfg["db_path"], run_id)
        assert results[0]["result"] == "error"
        assert "evidence file could not be written" in results[0]["detail"]
        assert db.get_findings(cfg["db_path"], run_id) == []
    finally:
        target.stop()


def test_findings_point_at_evidence_that_exists(tmp_path):
    target = FakeTarget(hardened=False)
    try:
        cfg = make_config(target.origin, tmp_path)
        run_id = run_pipeline(target.origin, "", cfg, only_checks=["security_headers", "sql_injection_login"])
        findings = db.get_findings(cfg["db_path"], run_id)

        assert findings
        for finding in findings:
            path = Path(finding["evidence_path"])
            if not path.is_absolute():
                path = BASE_DIR / path
            assert path.exists(), f"{finding['evidence_path']} was recorded but is not on disk"
            assert finding["status"] == "confirmed"
    finally:
        target.stop()


def test_report_is_written_and_separates_model_text_from_results(tmp_path):
    target = FakeTarget(hardened=False)
    try:
        cfg = make_config(target.origin, tmp_path)
        run_id = run_pipeline(target.origin, "report check", cfg, only_checks=["security_headers"])
        text = (tmp_path / "reports" / f"run_{run_id}.md").read_text(encoding="utf-8")

        assert f"# black-box test report, run {run_id}" in text
        assert target.origin in text
        assert "| `security_headers` | low | failed |" in text
        assert "recorded by the runner" in text
        assert "catalogue fallback" in text
        assert "\u2014" not in text
    finally:
        target.stop()
