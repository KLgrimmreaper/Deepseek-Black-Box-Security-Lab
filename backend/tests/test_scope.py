import pytest

from backend import db
from backend.config import load_config
from backend.runner import run_pipeline
from backend.scope import Scope, ScopeError, body_snippet
from backend.tests.fake_target import FakeTarget


def test_target_has_to_match_the_allowlist_exactly():
    allowed = ["http://localhost:3000"]
    Scope("http://localhost:3000/", allowed)
    for target in ["http://localhost:3001", "http://127.0.0.1:3000", "http://localhost:3000.evil.example", "localhost:3000", ""]:
        with pytest.raises(ScopeError):
            Scope(target, allowed)


def test_run_refuses_a_target_outside_the_allowlist(tmp_path):
    cfg = load_config(
        {
            "allowed_targets": ["http://localhost:3000"],
            "db_path": tmp_path / "lab.db",
            "evidence_dir": tmp_path / "evidence",
            "reports_dir": tmp_path / "reports",
        }
    )
    run_id = run_pipeline("http://example.com", "", cfg)

    run = db.get_run(cfg["db_path"], run_id)
    assert run["status"] == "failed"
    assert "ALLOWED_TARGETS" in run["error"]
    assert db.get_check_results(cfg["db_path"], run_id) == []


def test_request_budget_is_enforced():
    target = FakeTarget()
    try:
        scope = Scope(target.origin, [target.origin], max_requests=2, delay_ms=0)
        scope.get("/")
        scope.get("/")
        with pytest.raises(ScopeError):
            scope.get("/")
        assert scope.requests_sent == 2
    finally:
        target.stop()


def test_requests_cannot_leave_the_target_host():
    target = FakeTarget()
    try:
        scope = Scope(target.origin, [target.origin], delay_ms=0)
        with pytest.raises(ScopeError):
            scope.get("http://evil.example/steal")
        # a protocol relative path counts as a path on the target, not as another host
        response = scope.get("//evil.example/path")
        assert response.status_code == 404
        assert response.request.url.startswith(target.origin)
    finally:
        target.stop()


def test_request_delay_is_applied():
    target = FakeTarget()
    try:
        scope = Scope(target.origin, [target.origin], delay_ms=60)
        scope.get("/")
        scope.get("/")
        assert scope.requests_sent == 2
    finally:
        target.stop()


def test_body_snippet_keeps_responses_small():
    response = type("FakeResponse", (), {"text": "a" * 100})()
    snippet = body_snippet(response, limit=10)

    assert snippet.startswith("a" * 10)
    assert "90 more characters" in snippet
