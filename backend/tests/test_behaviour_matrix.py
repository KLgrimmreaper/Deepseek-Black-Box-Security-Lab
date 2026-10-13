"""a labelled behaviour matrix for the checks.

each row says what the target does and what the check has to return, and the label is written
next to the behaviour by hand rather than taken from the check. that is the point: if a check
starts claiming more than its evidence supports, the label here disagrees and the row fails.

this is not a precision and recall benchmark. the target and the labels come from the same
person, so recall is true by construction here. what it does prove is that each check returns
the documented result and the documented finding status for a known target behaviour, and that
the cases which used to be over-claimed now land in needs_review instead of confirmed.
"""

import pytest

from backend import db
from backend.runner import run_pipeline
from backend.tests.fake_target import CA_FILE, FakeTarget
from backend.tests.test_checks import make_config

# the finding status each result has to produce, and None means "no finding at all"
FINDING_STATUS = {"failed": "confirmed", "needs_review": "needs_review"}

CASES = [
    # sensitive paths: only content served to an unauthenticated request is a finding
    {
        "name": "sloppy target serves /.env and /metrics",
        "target": {},
        "check": "sensitive_paths",
        "expect": "failed",
    },
    {
        "name": "hardened target exposes nothing, and /admin is the app shell",
        "target": {"hardened": True},
        "check": "sensitive_paths",
        "expect": "passed",
    },
    {
        "name": "sensitive paths exist but answer 403",
        "target": {"restricted_paths": True},
        "check": "sensitive_paths",
        "expect": "needs_review",
    },
    # cors: a reflected origin with credentials is actionable, a wildcard alone is not proven
    {
        "name": "an arbitrary origin is reflected with allow-credentials",
        "target": {"cors_mode": "reflect_credentials"},
        "check": "cors_policy",
        "expect": "failed",
    },
    {
        "name": "an arbitrary origin is reflected without allow-credentials",
        "target": {"cors_mode": "reflect_only"},
        "check": "cors_policy",
        "expect": "needs_review",
    },
    {
        "name": "access-control-allow-origin is a wildcard",
        "target": {"cors_mode": "wildcard"},
        "check": "cors_policy",
        "expect": "needs_review",
    },
    {
        "name": "no cors headers at all",
        "target": {"hardened": True},
        "check": "cors_policy",
        "expect": "passed",
    },
    # reflected input: only an html response can run a script tag
    {
        "name": "a script tag is reflected raw in an html response",
        "target": {},
        "check": "reflected_xss",
        "expect": "failed",
    },
    {
        "name": "a script tag is reflected raw in a json response",
        "target": {"json_reflection": True},
        "check": "reflected_xss",
        "expect": "needs_review",
    },
    {
        "name": "the payload comes back encoded",
        "target": {"hardened": True},
        "check": "reflected_xss",
        "expect": "passed",
    },
    {
        "name": "the search parameter is not reflected at all",
        "target": {"search_reflects": False},
        "check": "reflected_xss",
        "expect": "not_applicable",
    },
    # cookies: a consent cookie is not a session cookie
    {
        "name": "a session cookie is set without secure flags",
        "target": {"page_cookie": "session"},
        "check": "cookie_flags",
        "expect": "failed",
    },
    {
        "name": "only a consent cookie is set, without secure flags",
        "target": {"page_cookie": "consent"},
        "check": "cookie_flags",
        "expect": "needs_review",
    },
    {
        "name": "the session cookie has secure, httponly and samesite",
        "target": {"hardened": True},
        "check": "cookie_flags",
        "expect": "passed",
    },
    {
        "name": "no cookie is set at all",
        "target": {"page_cookie": "none"},
        "check": "cookie_flags",
        "expect": "not_applicable",
    },
    # http methods: trace answering is proven, a method listed in allow is not
    {
        "name": "trace answers with 200",
        "target": {"methods": "trace_and_advertise"},
        "check": "http_methods",
        "expect": "failed",
    },
    {
        "name": "options advertises put and delete but trace is refused",
        "target": {"methods": "advertise_only"},
        "check": "http_methods",
        "expect": "needs_review",
    },
    {
        "name": "only get and head are offered",
        "target": {"methods": "clean"},
        "check": "http_methods",
        "expect": "passed",
    },
    {
        "name": "the options response has no allow header",
        "target": {"methods": "no_allow"},
        "check": "http_methods",
        "expect": "not_applicable",
    },
    # rate limiting: throttling can be proven, its absence cannot
    {
        "name": "ten quick logins with no throttling of any kind",
        "target": {},
        "check": "rate_limit",
        "expect": "needs_review",
    },
    {
        "name": "logins get slower without a 429",
        "target": {"delayed_throttle": True},
        "check": "rate_limit",
        "expect": "needs_review",
    },
    {
        "name": "the account is locked partway through",
        "target": {"lockout_after": 3},
        "check": "rate_limit",
        "expect": "needs_review",
    },
    {
        "name": "logins are throttled with 429",
        "target": {"hardened": True},
        "check": "rate_limit",
        "expect": "passed",
    },
    # the checks that already drew the right line
    {"name": "sloppy target has no security headers", "target": {}, "check": "security_headers", "expect": "failed"},
    {
        "name": "hardened target has every security header",
        "target": {"hardened": True},
        "check": "security_headers",
        "expect": "passed",
    },
    {"name": "server software is disclosed", "target": {}, "check": "server_info_disclosure", "expect": "failed"},
    {
        "name": "no server software is disclosed",
        "target": {"hardened": True},
        "check": "server_info_disclosure",
        "expect": "passed",
    },
    {"name": "robots.txt lists paths", "target": {}, "check": "robots_disclosure", "expect": "failed"},
    {
        "name": "there is no robots.txt",
        "target": {"hardened": True},
        "check": "robots_disclosure",
        "expect": "not_applicable",
    },
    {"name": "a stack trace is returned", "target": {}, "check": "error_disclosure", "expect": "failed"},
    {
        "name": "malformed input gives a generic error",
        "target": {"hardened": True},
        "check": "error_disclosure",
        "expect": "passed",
    },
    {
        "name": "the login accepts a sql injection payload",
        "target": {},
        "check": "sql_injection_login",
        "expect": "failed",
    },
    {
        "name": "the login rejects the payload and the baseline",
        "target": {"hardened": True},
        "check": "sql_injection_login",
        "expect": "passed",
    },
    {"name": "a demo password is accepted", "target": {}, "check": "weak_credentials", "expect": "failed"},
    {
        "name": "no demo password is accepted",
        "target": {"hardened": True},
        "check": "weak_credentials",
        "expect": "passed",
    },
    {"name": "a redirect parameter points off site", "target": {}, "check": "open_redirect", "expect": "failed"},
    {
        "name": "no redirect parameter points off site",
        "target": {"hardened": True},
        "check": "open_redirect",
        "expect": "passed",
    },
]


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_check_behaviour_matches_the_label(case, tmp_path):
    ca_bundle = str(CA_FILE) if case.get("ca_bundle") == "lab" else ""
    target = FakeTarget(**case["target"])
    try:
        cfg = make_config(target.origin, tmp_path, ca_bundle=ca_bundle)
        run_id = run_pipeline(target.origin, case["name"], cfg, only_checks=[case["check"]])
        row = db.get_check_results(cfg["db_path"], run_id)[0]
        findings = db.get_findings(cfg["db_path"], run_id)

        assert row["result"] == case["expect"], f"{case['name']}: {row['result']} because {row['detail']}"

        expected_status = FINDING_STATUS.get(case["expect"])
        if expected_status is None:
            assert findings == [], f"{case['name']} should not create a finding"
        else:
            assert len(findings) == 1, f"{case['name']} should create exactly one finding"
            assert findings[0]["status"] == expected_status
            assert findings[0]["evidence_path"]
    finally:
        target.stop()


def test_a_dead_host_is_a_failed_run_not_a_finding(tmp_path):
    # a run level row: nothing is listening, so there is no check result to label
    import socket

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"

    cfg = make_config(origin, tmp_path, request_timeout=2)
    run_id = run_pipeline(origin, "dead host", cfg)
    run = db.get_run(cfg["db_path"], run_id)

    assert run["status"] == "failed"
    assert "could not connect" in run["error"]
    assert db.get_findings(cfg["db_path"], run_id) == []


def test_the_matrix_covers_every_check():
    covered = {case["check"] for case in CASES}
    from backend.catalogue import catalogue_ids

    assert covered == set(catalogue_ids())
