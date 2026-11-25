"""Unit tests for network, IAM, storage, database, and logging security rules."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from aws_audit.checks import run_security_checks
from aws_audit.config import AuditConfig


class TestSecurityChecks(unittest.TestCase):
    def test_security_group_all_traffic_and_sensitive_ports(self) -> None:
        snapshot = {
            "account_id": "111122223333",
            "regions": ["us-east-1"],
            "security_groups": [
                {
                    "group_id": "sg-all",
                    "group_name": "wide-open",
                    "rules": [
                        {"from_port": 0, "to_port": 65535, "protocol": "tcp", "cidrs": ["0.0.0.0/0"]}
                    ],
                },
                {
                    "group_id": "sg-db",
                    "group_name": "db-public",
                    "rules": [
                        {"from_port": 3306, "to_port": 3306, "protocol": "6", "cidrs": ["::/0"]},
                        {"from_port": 443, "to_port": 443, "protocol": "tcp", "cidrs": ["0.0.0.0/0"]},
                    ],
                },
                {
                    "group_id": "sg-def",
                    "group_name": "default",
                    "is_default": True,
                    "rules": [{"from_port": -1, "to_port": -1, "protocol": "-1", "cidrs": ["10.0.0.0/8"]}],
                    "egress_rules": [],
                },
            ],
        }
        findings = run_security_checks(snapshot, AuditConfig())
        rule_ids = [f.rule_id for f in findings]
        # 0-65535 should emit one SEC-NET-001 finding, not duplicate port findings
        self.assertEqual(rule_ids.count("SEC-NET-001"), 1)
        self.assertEqual(rule_ids.count("SEC-NET-002"), 1)
        self.assertEqual(rule_ids.count("SEC-NET-003"), 1)
        db_finding = next(f for f in findings if f.rule_id == "SEC-NET-002")
        self.assertIn("3306/TCP (MySQL)", db_finding.issue)

    def test_iam_root_password_policy_console_vs_programmatic_mfa_and_keys(self) -> None:
        snapshot = {
            "account_id": "111122223333",
            "iam_summary": {
                "root_mfa_enabled": False,
                "root_access_keys_present": True,
                "password_policy": {"exists": False},
            },
            "iam_users": [
                {
                    "username": "console-no-mfa",
                    "has_console_access": True,
                    "has_mfa": False,
                    "attached_policies": ["AdministratorAccess"],
                    "inline_policies": ["emergency-inline"],
                    "access_keys": [
                        {"access_key_id": "AKIAOLD1", "status": "Active", "age_days": 200, "last_used_days": 5},
                        {"access_key_id": "AKIANEVER", "status": "Active", "age_days": 45, "last_used_days": None},
                    ],
                },
                {
                    "username": "ci-bot",
                    "has_console_access": False,
                    "has_mfa": False,
                    "attached_policies": ["ReadOnlyAccess"],
                    "inline_policies": [],
                    "access_keys": [
                        {"access_key_id": "AKIAFRESH", "status": "Active", "age_days": 15, "last_used_days": 1}
                    ],
                },
            ],
        }
        findings = run_security_checks(snapshot, AuditConfig())
        by_rule = {f.rule_id: f for f in findings}

        self.assertIn("SEC-IAM-001", by_rule)
        self.assertEqual(by_rule["SEC-IAM-001"].severity, "CRITICAL")
        self.assertIn("SEC-IAM-002", by_rule)
        self.assertIn("SEC-IAM-006", by_rule)
        self.assertIn("SEC-IAM-007", by_rule)

        # Only console-no-mfa should trigger SEC-IAM-003, not ci-bot
        mfa_findings = [f for f in findings if f.rule_id == "SEC-IAM-003"]
        self.assertEqual(len(mfa_findings), 1)
        self.assertIn("console-no-mfa", mfa_findings[0].resource_name)

        # Key age >= 180d escalates to HIGH
        key_age = [f for f in findings if f.rule_id == "SEC-IAM-004"]
        self.assertEqual(len(key_age), 1)
        self.assertEqual(key_age[0].severity, "HIGH")

        # Never-used active key >30d triggers SEC-IAM-005
        unused = [f for f in findings if f.rule_id == "SEC-IAM-005"]
        self.assertEqual(len(unused), 1)
        self.assertIn("never been used", unused[0].issue)

    def test_vpc_ec2_rds_s3_and_cloudtrail_checks(self) -> None:
        snapshot = {
            "account_id": "111122223333",
            "regions": ["eu-west-1"],
            "vpcs": [{"vpc_id": "vpc-1", "flow_logs_enabled": False}],
            "ec2_instances": [
                {"instance_id": "i-1", "state": "running", "public_ip": "1.2.3.4", "imdsv2_required": False},
                {"instance_id": "i-2", "state": "terminated", "public_ip": None, "imdsv2_required": False},
            ],
            "rds_instances": [
                {"db_instance_id": "db-1", "engine": "mysql", "publicly_accessible": True, "storage_encrypted": False}
            ],
            "s3_buckets": [
                {"name": "bucket-1", "public_access_blocked": False, "encryption_enabled": False, "versioning_enabled": False}
            ],
            "ebs_volumes": [
                {"volume_id": "vol-1", "volume_type": "gp3", "size_gb": 50, "state": "in-use", "encrypted": False}
            ],
            "cloudtrail_trails": [],
            "log_groups": [{"name": "/aws/test", "retention_days": None, "stored_bytes": 0}],
        }
        findings = run_security_checks(snapshot, AuditConfig())
        rule_ids = {f.rule_id for f in findings}
        expected = {
            "SEC-NET-004",
            "SEC-NET-005",
            "SEC-NET-006",
            "SEC-STG-001",
            "SEC-STG-002",
            "SEC-STG-003",
            "SEC-STG-004",
            "SEC-STG-005",
            "SEC-LOG-001",
            "SEC-LOG-003",
        }
        self.assertEqual(rule_ids, expected)


if __name__ == "__main__":
    unittest.main()
