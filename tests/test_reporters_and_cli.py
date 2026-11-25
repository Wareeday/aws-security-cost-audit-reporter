"""End-to-end tests for scoring, security of HTML/CSV reporters, SARIF, JSON, and CLI."""

from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from aws_audit.cli import run_cli
from aws_audit.collector import load_snapshot
from aws_audit.config import AuditConfig
from aws_audit.reporters import (
    write_csv_report,
    write_html_report,
    write_json_report,
    write_markdown_report,
    write_sarif_report,
)
from aws_audit.scoring import evaluate_snapshot


class TestReportersAndCli(unittest.TestCase):
    def test_demo_end_to_end_scoring_and_reports(self) -> None:
        snapshot = load_snapshot(mode="demo")
        result = evaluate_snapshot(snapshot, AuditConfig())

        self.assertEqual(result.summary.total_findings, 28)
        self.assertAlmostEqual(result.summary.total_monthly_savings_usd, 117.93, places=2)
        self.assertAlmostEqual(result.summary.total_annual_savings_usd, 1415.16, places=2)
        self.assertEqual(result.summary.severity_counts["CRITICAL"], 2)
        self.assertEqual(result.summary.security_score, 19)
        self.assertEqual(result.summary.security_grade, "F")

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            md = write_markdown_report(tmp / "report.md", result)
            html_out = write_html_report(tmp / "report.html", result)
            write_csv_report(tmp / "findings.csv", result)
            json_out = write_json_report(tmp / "report.json", result)
            sarif_out = write_sarif_report(tmp / "findings.sarif", result)

            self.assertIn("$117.93/mo", md)
            self.assertIn("Security Posture Score", md)
            self.assertIn("AWS Security Posture &amp; FinOps Audit Report", html_out)

            parsed_json = json.loads(json_out)
            self.assertEqual(parsed_json["schema_version"], "2.0")
            self.assertEqual(len(parsed_json["findings"]), 28)

            sarif = json.loads(sarif_out)
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(len(sarif["runs"][0]["results"]), 28)
            self.assertGreater(len(sarif["runs"][0]["tool"]["driver"]["rules"]), 10)

            with (tmp / "findings.csv").open(encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
                self.assertEqual(len(rows), 28)

    def test_html_xss_and_csv_formula_escaping(self) -> None:
        malicious_snapshot = {
            "account_id": "123456789012",
            "regions": ["us-east-1"],
            "s3_buckets": [
                {
                    "name": '=cmd|"/C calc"!A0<script>alert(1)</script>',
                    "public_access_blocked": False,
                }
            ],
        }
        result = evaluate_snapshot(malicious_snapshot, AuditConfig())

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            html_out = write_html_report(tmp / "xss.html", result)
            write_csv_report(tmp / "formula.csv", result)

            self.assertNotIn("<script>alert(1)</script>", html_out)
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html_out)

            with (tmp / "formula.csv").open(encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
                self.assertTrue(rows[0]["resource_id"].startswith("'="))

    def test_cli_demo_fail_on_and_snapshot_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            out_dir = tmp / "out"
            saved_snap = tmp / "captured.json"

            # Fail-on CRITICAL should exit with status 2 on demo snapshot
            rc_fail = run_cli(
                [
                    "--mode",
                    "demo",
                    "--formats",
                    "md,sarif",
                    "--output-dir",
                    str(out_dir),
                    "--save-snapshot",
                    str(saved_snap),
                    "--fail-on",
                    "CRITICAL",
                    "--quiet",
                ]
            )
            self.assertEqual(rc_fail, 2)
            self.assertTrue((out_dir / "aws_audit_report.md").exists())
            self.assertTrue((out_dir / "findings.sarif").exists())
            self.assertTrue(saved_snap.exists())

            # Clean snapshot should pass --fail-on LOW with exit code 0
            clean_snap = tmp / "clean.json"
            clean_snap.write_text(json.dumps({"account_id": "123456789012"}), encoding="utf-8")
            rc_pass = run_cli(
                [
                    "--mode",
                    "snapshot",
                    "--input-snapshot",
                    str(clean_snap),
                    "--formats",
                    "json",
                    "--output-dir",
                    str(out_dir),
                    "--fail-on",
                    "LOW",
                    "--quiet",
                ]
            )
            self.assertEqual(rc_pass, 0)

    def test_cli_filters_and_waivers(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            out_dir = tmp / "filtered"
            waivers = tmp / "waivers.json"
            waivers.write_text(
                json.dumps(
                    {
                        "suppressions": [
                            {
                                "rule_id": "FIN-NET-002",
                                "resource_pattern": "^nat-0unused11223344$",
                                "reason": "Scheduled failover NAT",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            rc = run_cli(
                [
                    "--mode",
                    "demo",
                    "--only",
                    "cost",
                    "--min-severity",
                    "MEDIUM",
                    "--waivers",
                    str(waivers),
                    "--formats",
                    "json",
                    "--output-dir",
                    str(out_dir),
                    "--quiet",
                ]
            )
            self.assertEqual(rc, 0)
            report = json.loads((out_dir / "aws_audit_report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["category_counts"]["Security"], 0)
            self.assertEqual(report["summary"]["suppressed_count"], 1)
            self.assertTrue(all(f["severity"] in {"CRITICAL", "HIGH", "MEDIUM"} for f in report["findings"]))


if __name__ == "__main__":
    unittest.main()
