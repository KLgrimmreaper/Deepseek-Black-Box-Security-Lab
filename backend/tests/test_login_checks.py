"""the login checks across every kind of login the mock applications can present.

this is the table that matters for trustworthiness. a row that expects `passed` is a claim that
the check really did rule the issue out, so every row also asserts that nothing was reported as
clean when the endpoint gave no usable signal.
"""

import pytest

from backend import db
from backend.catalogue import unmet_requirement
from backend.tests.fake_target import FakeTarget
from backend.tests.test_checks import make_config, run_checks

LOGIN_CHECKS = ["sql_injection_login", "weak_credentials", "rate_limit"]

# (name, target options, expected result per check, expected to be a finding)
CASES = [
    (
        "json login api that is vulnerable",
        {},
        {"sql_injection_login": "failed", "weak_credentials": "failed", "rate_limit": "needs_review"},
    ),
    (
        "json login api that refuses everything",
        {"login_error_html": True, "hardened": True},
        {"sql_injection_login": "passed", "weak_credentials": "error", "rate_limit": "passed"},
    ),
    (
        "html form login that is vulnerable",
        {"form_login": True},
        {"sql_injection_login": "failed", "weak_credentials": "failed", "rate_limit": "needs_review"},
    ),
    (
        "html form login that refuses everything",
        {"form_login": True, "hardened": True},
        {"sql_injection_login": "passed", "weak_credentials": "passed", "rate_limit": "needs_review"},
    ),
    (
        "html form that answers 200 to every attempt",
        {"form_login": True, "form_ambiguous": True},
        {"sql_injection_login": "error", "weak_credentials": "error", "rate_limit": "needs_review"},
    ),
    (
        "html form with fields that cannot be mapped",
        {"form_login": True, "form_fields": ("user_id", "secret")},
        {
            "sql_injection_login": "not_applicable",
            "weak_credentials": "not_applicable",
            "rate_limit": "not_applicable",
        },
    ),
    (
        "html form that posts to another host",
        {"form_login": True, "form_action": "https://evil.example/login"},
        {
            "sql_injection_login": "not_applicable",
            "weak_credentials": "not_applicable",
            "rate_limit": "not_applicable",
        },
    ),
    (
        "an authentication flow we cannot satisfy",
        {"login_unsupported": True},
        {"sql_injection_login": "error", "weak_credentials": "error", "rate_limit": "error"},
    ),
    (
        "no login endpoint at the configured path",
        {"hardened": True, "login_missing": True},
        {
            "sql_injection_login": "not_applicable",
            "weak_credentials": "not_applicable",
            "rate_limit": "not_applicable",
        },
    ),
]

# a passed result is only allowed where the check really could tell refusal from acceptance
MAY_NOT_PASS = {
    "html form that answers 200 to every attempt",
    "an authentication flow we cannot satisfy",
    "html form with fields that cannot be mapped",
    "html form that posts to another host",
    "no login endpoint at the configured path",
}


def build_target(options):
    settings = dict(options)
    # login_missing is not a target option, it just means point LOGIN_PATH somewhere absent
    settings.pop("login_missing", None)
    return FakeTarget(**settings)


@pytest.mark.parametrize("name,options,expected", CASES, ids=[case[0] for case in CASES])
def test_login_checks_agree_with_the_target(name, options, expected, tmp_path):
    target = build_target(options)
    try:
        cfg = make_config(target.origin, tmp_path)
        if options.get("login_missing"):
            cfg["login_path"] = "/no/such/login/here"
        run_id, results = run_checks(target, cfg, only=LOGIN_CHECKS)

        for check_id, wanted in expected.items():
            got = results[check_id]["result"]
            assert got == wanted, f"{name}: {check_id} was {got} because {results[check_id]['detail']}"

        if name in MAY_NOT_PASS:
            assert not any(row["result"] == "passed" for row in results.values()), name

        # a finding only ever comes from failed or needs_review, and every finding has evidence
        findings = db.get_findings(cfg["db_path"], run_id)
        for finding in findings:
            assert finding["status"] in ("confirmed", "needs_review")
            assert finding["evidence_path"]
    finally:
        target.stop()


def test_a_vulnerable_form_login_is_confirmed_with_form_evidence(tmp_path):
    target = FakeTarget(form_login=True)
    try:
        cfg = make_config(target.origin, tmp_path)
        run_id, results = run_checks(target, cfg, only=["sql_injection_login"])
        assert results["sql_injection_login"]["result"] == "failed"

        evidence = (tmp_path / "evidence" / str(run_id) / "sql_injection_login.json").read_text(encoding="utf-8")
        assert '"request_format": "form"' in evidence
        # a form mode finding has to show which fields were posted, without the values
        assert "username=[sent]" in evidence
        assert "password=[sent]" in evidence
        assert "evil.example" not in evidence
    finally:
        target.stop()


def test_a_form_login_uses_the_observed_field_names(tmp_path):
    target = FakeTarget(form_login=True, form_fields=("email_address", "user_password"))
    try:
        cfg = make_config(target.origin, tmp_path)
        run_id, results = run_checks(target, cfg, only=["weak_credentials"])

        # the fields were recognised, so the check ran rather than being skipped
        assert results["weak_credentials"]["result"] == "failed"
        evidence = (tmp_path / "evidence" / str(run_id) / "weak_credentials.json").read_text(encoding="utf-8")
        assert '"request_format": "form"' in evidence
    finally:
        target.stop()


def test_the_gate_is_the_only_thing_that_decides_applicability(tmp_path):
    # the same target, once through the gate and once with the gate bypassed by a direct call
    target = FakeTarget(form_login=True, form_fields=("user_id", "secret"))
    try:
        cfg = make_config(target.origin, tmp_path)
        run_id, results = run_checks(target, cfg, only=LOGIN_CHECKS)
        profile = __import__("json").loads(db.get_run(cfg["db_path"], run_id)["profile_json"])

        for check_id in LOGIN_CHECKS:
            reason = unmet_requirement(
                __import__("backend.catalogue", fromlist=["CATALOGUE_BY_ID"]).CATALOGUE_BY_ID[check_id], profile
            )
            assert reason is not None
            assert results[check_id]["result"] == "not_applicable"
            assert results[check_id]["detail"] == reason
    finally:
        target.stop()
