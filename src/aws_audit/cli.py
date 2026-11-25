"""Command-line interface for the AWS Security & Cost Audit Reporter."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Sequence

from aws_audit import __version__
from aws_audit.collector import LiveAWSCollector, load_snapshot, save_snapshot
from aws_audit.config import DEFAULT_OUTPUT_DIR, load_config
from aws_audit.models import Severity
from aws_audit.reporters import (
    write_csv_report,
    write_html_report,
    write_json_report,
    write_markdown_report,
    write_sarif_report,
)
from aws_audit.scoring import evaluate_snapshot, meets_severity_threshold

ALL_FORMATS = ("md", "html", "csv", "json", "sarif")


class _JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            }
        )


def _configure_logging(*, json_logs: bool, verbose: bool, quiet: bool) -> None:
    level = logging.WARNING if quiet else (logging.DEBUG if verbose else logging.INFO)
    handler = logging.StreamHandler(sys.stderr)
    if json_logs:
        handler.setFormatter(_JsonLogFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)


def _parse_formats(raw: str) -> list[str]:
    tokens = [t.strip().lower() for t in raw.split(",") if t.strip()]
    if not tokens or "all" in tokens:
        return list(ALL_FORMATS)
    invalid = [t for t in tokens if t not in ALL_FORMATS]
    if invalid:
        raise ValueError(f"Unsupported report format(s): {', '.join(invalid)}. Valid: {', '.join(ALL_FORMATS)}, all")
    return list(dict.fromkeys(tokens))


def _parse_regions(region_arg: str | None, regions_arg: str | None, default_region: str) -> list[str]:
    if regions_arg:
        parsed = [r.strip() for r in regions_arg.split(",") if r.strip()]
        if parsed:
            return parsed
    if region_arg:
        return [region_arg.strip()]
    return [default_region]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-audit",
        description="Read-only AWS security posture, compliance, and FinOps cost optimization auditor.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--mode",
        choices=["demo", "aws", "snapshot"],
        default="demo",
        help="Execution mode: 'demo' (built-in sample), 'aws' (live boto3), or 'snapshot' (offline JSON file).",
    )
    parser.add_argument(
        "--input-snapshot",
        type=Path,
        help="Path to snapshot JSON file when using --mode snapshot (or custom demo input).",
    )
    parser.add_argument(
        "--save-snapshot",
        type=Path,
        help="Optional path to save the collected snapshot JSON for reproducible offline audits.",
    )
    parser.add_argument("--region", help="Single AWS region for live audit (default from config: us-east-1).")
    parser.add_argument("--regions", help="Comma-separated AWS regions to scan concurrently in live mode.")
    parser.add_argument(
        "--all-regions",
        action="store_true",
        help="Discover and scan all enabled AWS regions in live mode.",
    )
    parser.add_argument("--profile", help="AWS CLI named profile for live mode.")
    parser.add_argument("--role-arn", help="IAM Role ARN to assume via STS for cross-account auditing.")
    parser.add_argument("--external-id", help="Optional STS ExternalId used when assuming --role-arn.")
    parser.add_argument("--config", type=Path, help="Path to YAML or JSON audit policy configuration.")
    parser.add_argument("--waivers", type=Path, help="Path to YAML or JSON risk-acceptance waivers file.")
    parser.add_argument(
        "--only",
        choices=["all", "security", "cost"],
        default="all",
        help="Restrict evaluation to security checks, FinOps cost checks, or both (default: all).",
    )
    parser.add_argument(
        "--min-severity",
        choices=[s.value for s in Severity if s != Severity.INFO],
        default=Severity.LOW.value,
        help="Only include findings at or above this severity (default: LOW).",
    )
    parser.add_argument(
        "--fail-on",
        choices=["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="NONE",
        help="Exit with code 2 when any open finding meets or exceeds this severity (for CI/CD gates).",
    )
    parser.add_argument(
        "--formats",
        default="all",
        help="Comma-separated output formats (md,html,csv,json,sarif,all). Default: all.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory for generated reports (default: {DEFAULT_OUTPUT_DIR}).",
    )
    parser.add_argument("--json-logs", action="store_true", help="Emit structured JSON log lines to stderr.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug logging.")
    parser.add_argument("--quiet", action="store_true", help="Suppress console summary output.")
    return parser


def run_cli(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_logging(json_logs=args.json_logs, verbose=args.verbose, quiet=args.quiet)

    try:
        formats = _parse_formats(args.formats)
        cfg = load_config(config_path=args.config, waivers_path=args.waivers)
    except Exception as exc:
        logging.error("Configuration error: %s", exc)
        return 1

    try:
        if args.mode == "demo":
            snapshot = load_snapshot(args.input_snapshot, mode="demo")
        elif args.mode == "snapshot":
            if not args.input_snapshot:
                raise ValueError("--input-snapshot is required when --mode snapshot is selected.")
            snapshot = load_snapshot(args.input_snapshot, mode="snapshot")
        else:
            regions = _parse_regions(args.region, args.regions, cfg.default_region)
            collector = LiveAWSCollector(
                regions=regions,
                all_regions=args.all_regions,
                profile=args.profile,
                role_arn=args.role_arn,
                external_id=args.external_id,
                max_workers=cfg.max_workers,
            )
            snapshot = collector.collect()
    except Exception as exc:
        logging.error("Snapshot collection failed: %s", exc)
        return 1

    if args.save_snapshot:
        save_snapshot(snapshot, args.save_snapshot)

    result = evaluate_snapshot(
        snapshot,
        cfg,
        include_security=args.only in {"all", "security"},
        include_cost=args.only in {"all", "cost"},
        min_severity=args.min_severity,
    )

    out_dir: Path = args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}

    if "md" in formats:
        p = out_dir / "aws_audit_report.md"
        write_markdown_report(p, result)
        written["Markdown"] = p
    if "html" in formats:
        p = out_dir / "aws_audit_report.html"
        write_html_report(p, result)
        written["HTML"] = p
    if "csv" in formats:
        p = out_dir / "findings.csv"
        write_csv_report(p, result)
        written["CSV"] = p
    if "json" in formats:
        p = out_dir / "aws_audit_report.json"
        write_json_report(p, result)
        written["JSON"] = p
    if "sarif" in formats:
        p = out_dir / "findings.sarif"
        write_sarif_report(p, result)
        written["SARIF"] = p

    if not args.quiet:
        s = result.summary
        print(
            f"[AWS Audit] Account={s.account_id} Regions={','.join(s.regions)} "
            f"Score={s.security_score}/100 ({s.security_grade})"
        )
        print(
            f"            Open={s.total_findings} "
            f"(CRIT={s.severity_counts['CRITICAL']}, HIGH={s.severity_counts['HIGH']}, "
            f"MED={s.severity_counts['MEDIUM']}, LOW={s.severity_counts['LOW']}) "
            f"| Suppressed={s.suppressed_count} | Warnings={s.warnings_count}"
        )
        print(
            f"            Estimated Savings=${s.total_monthly_savings_usd:,.2f}/mo "
            f"(${s.total_annual_savings_usd:,.2f}/yr)"
        )
        for label, path in written.items():
            print(f"            {label:<8} -> {path}")

    if args.fail_on != "NONE":
        failing = [f for f in result.findings if meets_severity_threshold(f.severity, args.fail_on)]
        if failing:
            logging.warning(
                "Policy gate failed: %d open finding(s) meet or exceed %s severity.",
                len(failing),
                args.fail_on,
            )
            return 2

    return 0


def main() -> None:
    raise SystemExit(run_cli())


if __name__ == "__main__":
    main()
