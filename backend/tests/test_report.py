from backend import db, report
from backend.config import load_config

PLAN = {
    "source": "model",
    "checks": [{"id": "security_headers", "reason": "always worth a look"}],
    "skipped": [{"id": "made_up_check", "reason": "not in the catalogue"}],
}


def build_run(tmp_path, with_finding=True, summary_source="model"):
    cfg = load_config(
        {
            "db_path": tmp_path / "lab.db",
            "evidence_dir": tmp_path / "evidence",
            "reports_dir": tmp_path / "reports",
        }
    )
    db.init_db(cfg["db_path"])
    run_id = db.create_run(cfg["db_path"], "http://localhost:3000", "notes here", "deepseek-chat")
    db.set_run_plan(cfg["db_path"], run_id, PLAN)
    db.add_check_result(
        cfg["db_path"], run_id,
        check_id="security_headers", name="missing security headers", severity="low", result="failed",
        detail="missing headers: content-security-policy", reason="always worth a look",
        evidence_path="evidence/1/security_headers.json", requests_used=1,
    )
    db.add_check_result(
        cfg["db_path"], run_id,
        check_id="reflected_xss", name="reflected input in the search parameter", severity="high",
        result="not_applicable", detail="the search parameter was not reflected in the response body",
        reason="looks for reflected input", evidence_path="evidence/1/reflected_xss.json", requests_used=1,
    )
    if with_finding:
        db.add_finding(
            cfg["db_path"], run_id,
            check_id="security_headers", title="missing security headers", severity="low", status="confirmed",
            evidence_path="evidence/1/security_headers.json",
            description="missing headers: content-security-policy", impact="impact text",
            remediation="remediation text", model_generated=1,
        )
    db.finish_run(
        cfg["db_path"], run_id,
        status="finished",
        summary="2 checks were run.",
        summary_source=summary_source,
        request_count=2,
    )
    return cfg, run_id


def render(cfg, run_id):
    run = db.get_run(cfg["db_path"], run_id)
    return report.render_report(
        run,
        report.parse_plan(run),
        db.get_check_results(cfg["db_path"], run_id),
        db.get_findings(cfg["db_path"], run_id),
    )


def test_report_shows_the_plan_results_findings_and_gaps(tmp_path):
    cfg, run_id = build_run(tmp_path)
    text = render(cfg, run_id)

    assert f"# black-box test report, run {run_id}" in text
    assert "http://localhost:3000" in text
    assert "always worth a look" in text
    assert "made_up_check" in text
    assert "not_applicable" in text
    assert "no evidence" not in text.lower()
    assert "evidence/1/security_headers.json" in text
    assert "model written" in text
    assert "\u2014" not in text


def test_report_without_findings_says_so(tmp_path):
    cfg, run_id = build_run(tmp_path, with_finding=False)
    text = render(cfg, run_id)

    assert "no confirmed findings in this run." in text
    assert "model written" not in text


def test_report_labels_the_summary_as_model_written(tmp_path):
    cfg, run_id = build_run(tmp_path)
    text = render(cfg, run_id)

    assert "the summary paragraph above was written by the model" in text
    assert "2 checks were run." in text


def test_report_labels_a_runner_summary_as_runner_written(tmp_path):
    cfg, run_id = build_run(tmp_path, summary_source="runner")
    text = render(cfg, run_id)

    assert "written by the runner, not by the model" in text


def test_write_report_puts_the_file_in_the_reports_dir(tmp_path):
    cfg, run_id = build_run(tmp_path)
    run = db.get_run(cfg["db_path"], run_id)
    path, text = report.write_report(
        run,
        report.parse_plan(run),
        db.get_check_results(cfg["db_path"], run_id),
        db.get_findings(cfg["db_path"], run_id),
        cfg,
    )

    assert path == cfg["reports_dir"] / f"run_{run_id}.md"
    assert path.exists()
    assert path.read_text(encoding="utf-8") == text
