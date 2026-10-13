import argparse

from . import db
from .catalogue import CATALOGUE
from .config import load_config
from .runner import run_pipeline


def print_run(run_id, cfg):
    run = db.get_run(cfg["db_path"], run_id)
    print(f"run {run_id}: {run['status']} ({run['request_count']} requests, model: {run['model']})")
    if run["error"]:
        print(f"error: {run['error']}")
    for row in db.get_check_results(cfg["db_path"], run_id):
        print(f"  {row['result']:<14} {row['check_id']:<28} {row['detail']}")
    findings = db.get_findings(cfg["db_path"], run_id)
    print(f"{len(findings)} finding(s)")
    for finding in findings:
        print(f"  [{finding['severity']}] {finding['title']} ({finding['status']}) evidence: {finding['evidence_path']}")
    print(f"report: reports/run_{run_id}.md")


def main():
    parser = argparse.ArgumentParser(prog="lab", description="deepseek black-box security lab")
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="test a target once")
    run_parser.add_argument("--target", help="base url, has to match ALLOWED_TARGETS")
    run_parser.add_argument("--notes", default="", help="free text stored with the run")
    run_parser.add_argument("--only", default="", help="comma separated check ids, skips the model")
    run_parser.add_argument("--mock", action="store_true", help="use the fallback plan, no api calls")

    sub.add_parser("checks", help="print the check catalogue")
    sub.add_parser("runs", help="print the last runs")

    args = parser.parse_args()
    overrides = {"mock_agent": True} if getattr(args, "mock", False) else None
    cfg = load_config(overrides)

    if args.command == "checks":
        for entry in CATALOGUE:
            print(f"{entry['id']:<28} {entry['severity']:<7} {entry['category']:<18} {entry['name']}")
        return

    if args.command == "runs":
        for row in db.list_runs(cfg["db_path"]):
            print(f"{row['id']:>4} {row['status']:<10} {row['target']:<28} {row['started_at']} "
                  f"{row['finding_count']} finding(s)")
        return

    target = args.target or (cfg["allowed_targets"][0] if cfg["allowed_targets"] else "")
    if not target:
        print("no target given and ALLOWED_TARGETS is empty")
        return
    only = [item.strip() for item in args.only.split(",") if item.strip()]
    run_id = run_pipeline(target, args.notes, cfg, only_checks=only or None)
    print_run(run_id, cfg)


if __name__ == "__main__":
    main()
