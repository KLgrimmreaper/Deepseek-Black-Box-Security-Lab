from backend import db
from backend.config import load_config
from backend.runner import run_pipeline
from backend.tests.fake_target import FakeTarget


def test_stats_and_findings_are_aggregated_across_runs(tmp_path):
    target = FakeTarget(hardened=False)
    try:
        cfg = load_config(
            {
                "allowed_targets": [target.origin],
                "mock_agent": True,
                "request_delay_ms": 0,
                "db_path": tmp_path / "lab.db",
                "evidence_dir": tmp_path / "evidence",
                "reports_dir": tmp_path / "reports",
                "credentials": ["admin@example.com:fakepass1"],
            }
        )
        run_pipeline(target.origin, "", cfg, only_checks=["security_headers", "cors_policy"])
        run_pipeline(target.origin, "", cfg, only_checks=["security_headers"])

        stats = db.get_stats(cfg["db_path"])
        assert stats["totals"]["runs"] == 2
        assert stats["totals"]["finished"] == 2
        assert stats["totals"]["checks_run"] == 3
        assert stats["totals"]["requests"] > 0

        # security headers and cors both fail on this target, so run 1 has two findings and run 2 has one
        assert stats["totals"]["findings"] == 3
        assert {"label": "low", "value": 2} in stats["by_severity"]
        assert {"label": "medium", "value": 1} in stats["by_severity"]
        assert {"label": "failed", "value": 3} in stats["by_result"]
        assert stats["top_failing_checks"] == [
            {"label": "security_headers", "value": 2},
            {"label": "cors_policy", "value": 1},
        ]
        assert [point["value"] for point in stats["trend"]] == [2, 1]

        findings = db.list_findings(cfg["db_path"])
        assert len(findings) == 3
        assert findings[0]["target"] == target.origin
        assert findings[0]["evidence_path"].endswith("security_headers.json")
    finally:
        target.stop()


def test_stats_on_an_empty_database_are_zero_not_missing(tmp_path):
    cfg = load_config({"db_path": tmp_path / "lab.db"})
    db.init_db(cfg["db_path"])
    stats = db.get_stats(cfg["db_path"])

    assert stats["totals"]["runs"] == 0
    assert stats["totals"]["requests"] == 0
    assert stats["by_severity"] == []
    assert stats["trend"] == []
