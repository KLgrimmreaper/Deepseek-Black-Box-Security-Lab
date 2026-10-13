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
        "ca_bundle": "",
    }
    settings.update(overrides)
    return load_config(settings)


def canned_recon(origin, https=False, **profile_overrides):
    """a recon result that skips the network, for tests that only care about a later step."""
    profile = {
        "root_status": 200,
        "root_content_type": "application/json",
        "unknown_path_status": 404,
        "unknown_path_returns_app_shell": False,
        "allow_header": "GET, OPTIONS, HEAD",
        "head_status": 200,
        "application_shape": "json_api",
        "login_shape": "json",
        "login_form": None,
        "login_probe": {
            "path": "/rest/user/login",
            "source": "configured",
            "status": 401,
            "content_type": "application/json",
            "json_response": True,
            "accepted": False,
        },
        "search_endpoint": {"path": "/rest/products/search", "status": 200, "present": True},
        "untrusted": {"title": "", "server_header": "", "powered_by": ""},
    }
    profile.update(profile_overrides)
    return {"target": origin, "https": https, "profile": profile}


def run_checks(target, cfg, only=None):
    run_id = run_pipeline(target.origin, "test run", cfg, only_checks=only or catalogue_ids())
    results = {row["check_id"]: row for row in db.get_check_results(cfg["db_path"], run_id)}
    return run_id, results


def test_every_catalogue_entry_has_a_check_function():
    # catches the case where a check is added to one list and forgotten in the other
    assert sorted(catalogue_ids()) == sorted(CHECKS.keys())


def test_the_vocabulary_is_the_one_the_runner_understands():
    # the runner only turns these two into findings, everything else is not a claim about the target
    from backend.runner import FINDING_RESULTS

    assert FINDING_RESULTS == ("failed", "needs_review")


def test_a_sloppy_target_gives_twelve_failures_and_one_observation(tmp_path):
    target = FakeTarget(hardened=False)
    try:
        cfg = make_config(target.origin, tmp_path)
        run_id, results = run_checks(target, cfg)

        counts = {}
        for row in results.values():
            counts[row["result"]] = counts.get(row["result"], 0) + 1

        # everything except rate limiting is demonstrated by a response, and rate limiting
        # cannot be demonstrated to be absent by ten requests, so it stays an observation
        assert counts == {"failed": 12, "needs_review": 1}
        assert results["rate_limit"]["result"] == "needs_review"

        findings = db.get_findings(cfg["db_path"], run_id)
        assert len(findings) == 13
        assert sum(1 for finding in findings if finding["status"] == "confirmed") == 12
        assert sum(1 for finding in findings if finding["status"] == "needs_review") == 1
        assert db.get_run(cfg["db_path"], run_id)["status"] == "finished"
    finally:
        target.stop()


def test_a_hardened_target_reports_no_findings(tmp_path):
    target = FakeTarget(hardened=True)
    try:
        cfg = make_config(target.origin, tmp_path)
        run_id, results = run_checks(target, cfg)

        counts = {}
        for row in results.values():
            counts[row["result"]] = counts.get(row["result"], 0) + 1

        # this target throttles logins after three attempts, so the credential list runs into a
        # 429 and that check reports error rather than claiming the passwords were refused
        assert counts == {"passed": 11, "not_applicable": 1, "error": 1}
        assert results["robots_disclosure"]["result"] == "not_applicable"
        assert results["weak_credentials"]["result"] == "error"
        assert "throttling" in results["weak_credentials"]["detail"]
        assert db.get_findings(cfg["db_path"], run_id) == []
    finally:
        target.stop()


def test_spa_fallback_is_not_reported_as_an_exposed_path(tmp_path):
    target = FakeTarget(hardened=True)
    try:
        cfg = make_config(target.origin, tmp_path)
        run_id, results = run_checks(target, cfg, only=["sensitive_paths"])
        evidence = (tmp_path / "evidence" / str(run_id) / "sensitive_paths.json").read_text(encoding="utf-8")

        # /admin answers 200 with the app shell in both modes, and must not be reported
        assert results["sensitive_paths"]["result"] == "passed"
        assert "/admin" in evidence
        assert "client side route" in evidence
    finally:
        target.stop()


def test_failed_check_without_evidence_is_recorded_as_error(tmp_path, monkeypatch):
    from backend import runner

    target = FakeTarget(hardened=False)
    try:
        cfg = make_config(target.origin, tmp_path)
        # a failed check whose evidence cannot be written must not become a finding
        monkeypatch.setattr(runner, "_write_evidence", lambda *args, **kwargs: None)
        run_id, results = run_checks(target, cfg, only=["security_headers"])

        assert results["security_headers"]["result"] == "error"
        assert "evidence file could not be written" in results["security_headers"]["detail"]
        assert db.get_findings(cfg["db_path"], run_id) == []
    finally:
        target.stop()


def test_findings_point_at_evidence_that_exists(tmp_path):
    target = FakeTarget(hardened=False)
    try:
        cfg = make_config(target.origin, tmp_path)
        run_id, _ = run_checks(target, cfg, only=["security_headers", "sql_injection_login"])
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
        run_id, _ = run_checks(target, cfg, only=["security_headers"])
        text = (tmp_path / "reports" / f"run_{run_id}.md").read_text(encoding="utf-8")

        assert f"# black-box test report, run {run_id}" in text
        assert target.origin in text
        assert "| `security_headers` | low | failed |" in text
        assert "recorded by the runner" in text
        assert "catalogue fallback" in text
        assert "\u2014" not in text
    finally:
        target.stop()
