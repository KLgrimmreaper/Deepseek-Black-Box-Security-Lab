import socket

import pytest
import requests

from backend import db
from backend.config import load_config
from backend.runner import run_pipeline
from backend.scope import Scope, ScopeError, body_snippet
from backend.tests.fake_target import CA_FILE, FakeTarget


def free_port():
    # bind and release, so the port is very likely still unused when the test connects
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_target_has_to_match_the_allowlist_exactly():
    allowed = ["http://localhost:3000"]
    Scope("http://localhost:3000/", allowed)
    for target in [
        "http://localhost:3001",
        "http://127.0.0.1:3000",
        "http://localhost:3000.evil.example",
        "localhost:3000",
        "",
    ]:
        with pytest.raises(ScopeError):
            Scope(target, allowed)


def test_malformed_targets_are_refused_without_sending_anything():
    allowed = ["http://localhost:3000"]
    for target in [
        "ftp://localhost:3000",
        "http://",
        "://localhost:3000",
        "http://user:pass@localhost:3000@evil.example",
    ]:
        with pytest.raises(ScopeError):
            Scope(target, allowed)


def test_a_path_in_the_target_is_ignored_and_the_origin_is_used():
    # the runner only ever talks to the origin, so a pasted deep link is not an escape
    scope = Scope("http://localhost:3000/some/deep/link?x=1", ["http://localhost:3000"])
    assert scope.origin == "http://localhost:3000"


def test_the_scheme_is_part_of_the_match():
    # https and http on the same port are different targets, not interchangeable
    with pytest.raises(ScopeError):
        Scope("https://localhost:3000", ["http://localhost:3000"])
    Scope("https://localhost:3000", ["https://localhost:3000"])


def test_a_refused_request_costs_no_budget_and_is_never_sent():
    target = FakeTarget()
    try:
        scope = Scope(target.origin, [target.origin], delay_ms=0)
        with pytest.raises(ScopeError):
            scope.get("http://evil.example/steal")
        assert scope.requests_sent == 0

        scope.get("/")
        assert scope.requests_sent == 1
    finally:
        target.stop()


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


def test_failed_requests_still_count_against_the_budget():
    # nothing is listening, so every attempt raises a connection error, and each one
    # still has to cost budget or a dead target could be hammered for free
    origin = f"http://127.0.0.1:{free_port()}"
    scope = Scope(origin, [origin], max_requests=2, delay_ms=0, timeout=2)

    for _ in range(2):
        with pytest.raises(requests.exceptions.ConnectionError):
            scope.get("/")
    assert scope.requests_sent == 2

    with pytest.raises(ScopeError):
        scope.get("/")


def test_a_timed_out_request_still_counts_against_the_budget():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)  # accepts the connection and never answers
    origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
    try:
        scope = Scope(origin, [origin], max_requests=1, delay_ms=0, timeout=1)
        with pytest.raises(requests.exceptions.Timeout):
            scope.get("/")
        assert scope.requests_sent == 1
        with pytest.raises(ScopeError):
            scope.get("/")
    finally:
        listener.close()


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


def test_redirects_are_not_followed_off_host():
    from urllib.parse import quote

    target = FakeTarget()
    try:
        scope = Scope(target.origin, [target.origin], delay_ms=0)
        response = scope.get("/?to=" + quote("https://evil.example/dsh", safe=""))

        assert response.status_code == 302
        assert response.headers["Location"] == "https://evil.example/dsh"
        # one request means the redirect was recorded and never followed
        assert scope.requests_sent == 1
    finally:
        target.stop()


def test_a_ca_bundle_that_does_not_exist_is_refused():
    with pytest.raises(ScopeError) as error:
        Scope("https://localhost:3000", ["https://localhost:3000"], ca_bundle="backend/tests/certs/nope.pem")
    assert "CA_BUNDLE" in str(error.value)
    # the real test ca is accepted
    Scope("https://localhost:3000", ["https://localhost:3000"], ca_bundle=str(CA_FILE))


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
