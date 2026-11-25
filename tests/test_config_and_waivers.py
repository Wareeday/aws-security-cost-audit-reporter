"""Unit tests for policy config loading and suppression waiver expiration."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from aws_audit.config import AuditConfig, SuppressionRule, apply_suppressions, load_config
from aws_audit.models import Finding


class TestConfigAndWaivers(unittest.TestCase):
    def test_load_json_and_yaml_configs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            cfg_file = tmp / "policy.json"
            cfg_file.write_text(
                json.dumps(
                    {
                        "thresholds": {"max_access_key_age_days": 45, "default_region": "eu-central-1"},
                        "sensitive_ports": {"9000": ["SonarQube", "HIGH"]},
                        "disabled_rules": ["SEC-LOG-003"],
                    }
                ),
                encoding="utf-8",
            )
            waiver_file = tmp / "waivers.json"
            waiver_file.write_text(
                json.dumps(
                    {
                        "suppressions": [
                            {
                                "rule_id": "SEC-STG-001",
                                "resource_pattern": "^public-assets$",
                                "reason": "CloudFront origin",
                                "expires_at": "2099-01-01",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            cfg = load_config(config_path=cfg_file, waivers_path=waiver_file)
            self.assertEqual(cfg.max_access_key_age_days, 45)
            self.assertEqual(cfg.default_region, "eu-central-1")
            self.assertEqual(cfg.sensitive_ports[9000], ("SonarQube", "HIGH"))
            self.assertIn("SEC-LOG-003", cfg.disabled_rules)
            self.assertEqual(len(cfg.suppressions), 1)

    def test_waiver_matching_and_expiration(self) -> None:
        finding = Finding(
            rule_id="SEC-STG-001",
            category="Security",
            severity="HIGH",
            title="S3 Block Public Access Incomplete",
            resource_id="acme-cdn-bucket",
            resource_type="AWS::S3::Bucket",
            resource_name="S3 Bucket: acme-cdn-bucket",
            region="us-east-1",
            account_id="123456789012",
            issue="Disabled",
            remediation="Enable",
        )
        active_waiver = SuppressionRule(
            rule_id="SEC-STG-001",
            resource_pattern="^acme-cdn-bucket$",
            reason="Approved static site",
            expires_at="2027-01-01",
        )
        expired_waiver = SuppressionRule(
            rule_id="SEC-STG-001",
            resource_pattern="^acme-cdn-bucket$",
            reason="Expired exception",
            expires_at="2025-01-01",
        )

        ref_day = date(2026, 11, 25)
        active, suppressed = apply_suppressions([finding], [active_waiver], today=ref_day)
        self.assertEqual(len(active), 0)
        self.assertEqual(len(suppressed), 1)
        self.assertTrue(suppressed[0].suppressed)

        # Reset and test expired waiver
        finding.suppressed = False
        finding.suppression_reason = ""
        active2, suppressed2 = apply_suppressions([finding], [expired_waiver], today=ref_day)
        self.assertEqual(len(active2), 1)
        self.assertEqual(len(suppressed2), 0)

    def test_example_yaml_files_parse_cleanly(self) -> None:
        root = Path(__file__).resolve().parents[1]
        cfg = load_config(
            config_path=root / "examples" / "audit-policy.yaml",
            waivers_path=root / "examples" / "waivers.yaml",
        )
        self.assertIsInstance(cfg, AuditConfig)
        self.assertEqual(cfg.max_access_key_age_days, 90)
        self.assertGreaterEqual(len(cfg.suppressions), 2)


if __name__ == "__main__":
    unittest.main()
