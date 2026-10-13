import socket

import pytest

from backend import db, runner
from backend.runner import run_pipeline
from backend.tests.fake_target import CA_FILE, FakeTarget
from backend.tests.test_checks import make_config, run_checks


def test_an_https_target_with_the_lab_ca_is_tested_normally(tmp_path):
    target = FakeTarget(hardened=True, tls=True)
    try:
        cfg = make_config(target.origin, tmp_path, ca_bundle=str(CA_FILE))
        run_id, results = run_checks(target, cfg, only=["security_headers", "cookie_flags"])

        assert target.origin.startswith("https://")
        assert results["security_headers"]["result"] == "passed"
        assert results["cookie_flags"]["result"] == "passed"
        # hsts is required over https, and the hardened target sends it
        assert "strict-transport-security" not in results["security_headers"]["detail"]
        assert db.get_run(cfg["db_path"], run_id)["status"] == "finished"
    finally:
        target.stop()


def test_an_untrusted_certificate_fails_the_run_without_inventing_findings(tmp_path):
    target = FakeTarget(hardened=False, tls=True)
    try:
        # no ca bundle, so the self signed certificate is not trusted
        cfg = make_config(target.origin, tmp_path, ca_bundle="")
        run_id = run_pipeline(target.origin, "", cfg)

        run = db.get_run(cfg["db_path"], run_id)
        assert run["status"] == "failed"
        assert "TLS certificate verification failed" in run["error"]
        assert db.get_findings(cfg["db_path"], run_id) == []
        assert db.get_check_results(cfg["db_path"], run_id) == []
    finally:
        target.stop()


def test_a_tls_failure_inside_a_check_is_an_error_not_a_finding(tmp_path, monkeypatch):
    target = FakeTarget(hardened=False, tls=True)
    try:
        cfg = make_config(target.origin, tmp_path, ca_bundle="")
        # pretend the recon worked, so the failure happens inside the check itself
        monkeypatch.setattr(
            runner, "collect_recon", lambda scope: {"target": scope.origin, "https": True, "observations": {}}
        )
        run_id, results = run_checks(target, cfg, only=["security_headers"])

        assert results["security_headers"]["result"] == "error"
        assert "TLS certificate verification failed" in results["security_headers"]["detail"]
        assert db.get_findings(cfg["db_path"], run_id) == []
    finally:
        target.stop()


def test_a_timeout_inside_a_check_is_an_error_not_a_finding(tmp_path, monkeypatch):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)  # accepts and never answers
    origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
    try:
        cfg = make_config(origin, tmp_path, request_timeout=1)
        monkeypatch.setattr(
            runner, "collect_recon", lambda scope: {"target": scope.origin, "https": False, "observations": {}}
        )
        run_id, results = run_checks_against(origin, cfg, ["security_headers"])

        assert results["security_headers"]["result"] == "error"
        assert "timed out" in results["security_headers"]["detail"]
        assert db.get_findings(cfg["db_path"], run_id) == []
    finally:
        listener.close()


def run_checks_against(origin, cfg, only):
    run_id = run_pipeline(origin, "", cfg, only_checks=only)
    results = {row["check_id"]: row for row in db.get_check_results(cfg["db_path"], run_id)}
    return run_id, results


def test_the_budget_still_holds_over_https(tmp_path):
    target = FakeTarget(hardened=False, tls=True)
    try:
        cfg = make_config(target.origin, tmp_path, ca_bundle=str(CA_FILE), max_requests_per_run=4)
        # sensitive_paths needs 17 requests, so it has to stop at the budget instead
        run_id, results = run_checks(target, cfg, only=["sensitive_paths"])

        run = db.get_run(cfg["db_path"], run_id)
        assert run["request_count"] == 4
        assert results["sensitive_paths"]["result"] == "error"
        assert "budget" in results["sensitive_paths"]["detail"]
    finally:
        target.stop()


def test_a_redirect_over_https_is_still_not_followed(tmp_path):
    target = FakeTarget(hardened=False, tls=True)
    try:
        cfg = make_config(target.origin, tmp_path, ca_bundle=str(CA_FILE))
        run_id, _ = run_checks(target, cfg, only=["open_redirect"])

        evidence = (tmp_path / "evidence" / str(run_id) / "open_redirect.json").read_text(encoding="utf-8")
        assert "evil.example" in evidence
        # 3 recon requests plus 3 probes, and not one redirect hop was followed
        assert db.get_run(cfg["db_path"], run_id)["request_count"] == 6
    finally:
        target.stop()


@pytest.mark.parametrize("bad_target", ["https://", "https:///path"])
def test_malformed_https_targets_are_refused(bad_target):
    from backend.scope import Scope, ScopeError

    with pytest.raises(ScopeError):
        Scope(bad_target, ["https://localhost:443"])
