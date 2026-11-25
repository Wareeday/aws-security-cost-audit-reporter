"""Unit tests for FinOps cost optimization checks and double-counting guards."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from aws_audit.checks import run_finops_checks
from aws_audit.config import AuditConfig


class TestCostChecks(unittest.TestCase):
    def test_finops_rules_and_zero_double_counting(self) -> None:
        snapshot = {
            "account_id": "111122223333",
            "regions": ["us-east-1"],
            "ebs_volumes": [
                {"volume_id": "vol-avail", "volume_type": "gp3", "size_gb": 100, "state": "available"},
                {"volume_id": "vol-active-gp2", "volume_type": "gp2", "size_gb": 200, "state": "in-use"},
                {"volume_id": "vol-stopped-gp2", "volume_type": "gp2", "size_gb": 100, "state": "in-use"},
            ],
            "ec2_instances": [
                {
                    "instance_id": "i-stopped",
                    "name": "zombie",
                    "state": "stopped",
                    "stopped_days": 45,
                    "attached_volumes": [
                        {"volume_id": "vol-stopped-gp2", "volume_type": "gp2", "size_gb": 100}
                    ],
                }
            ],
            "ebs_snapshots": [
                {"snapshot_id": "snap-old", "volume_size_gb": 100, "age_days": 120, "ami_referenced": False},
                {"snapshot_id": "snap-ami", "volume_size_gb": 100, "age_days": 200, "ami_referenced": True},
            ],
            "elastic_ips": [
                {"allocation_id": "eip-1", "public_ip": "198.51.100.1", "associated": False},
                {"allocation_id": "eip-2", "public_ip": "198.51.100.2", "associated": True},
            ],
            "nat_gateways": [
                {"nat_gateway_id": "nat-idle", "state": "available", "idle": True, "bytes_7d": 0},
                {"nat_gateway_id": "nat-busy", "state": "available", "idle": False, "bytes_7d": 50000},
            ],
            "load_balancers": [
                {"arn": "arn:alb-idle", "name": "idle-alb", "type": "application", "target_count": 0},
                {"arn": "arn:alb-busy", "name": "busy-alb", "type": "application", "target_count": 2},
            ],
            "log_groups": [
                {"name": "/aws/big-logs", "retention_days": None, "stored_bytes": 100 * (1024 ** 3)},
                {"name": "/aws/tiny-logs", "retention_days": None, "stored_bytes": 1024},
            ],
        }

        findings = run_finops_checks(snapshot, AuditConfig())
        by_resource = {f.resource_id: f for f in findings}

        self.assertEqual(by_resource["vol-avail"].monthly_savings_usd, 8.0)
        self.assertEqual(by_resource["vol-active-gp2"].rule_id, "FIN-EBS-002")
        self.assertEqual(by_resource["vol-active-gp2"].monthly_savings_usd, 4.0)
        # vol-stopped-gp2 must NOT also emit FIN-EBS-002 because i-stopped claims full $10/mo deletion savings
        self.assertNotIn("vol-stopped-gp2", by_resource)
        self.assertEqual(by_resource["i-stopped"].monthly_savings_usd, 10.0)
        self.assertEqual(by_resource["snap-old"].monthly_savings_usd, 5.0)
        self.assertNotIn("snap-ami", by_resource)
        self.assertEqual(by_resource["eip-1"].monthly_savings_usd, 3.65)
        self.assertEqual(by_resource["nat-idle"].monthly_savings_usd, 32.85)
        self.assertEqual(by_resource["arn:alb-idle"].monthly_savings_usd, 16.43)
        self.assertEqual(by_resource["/aws/big-logs"].monthly_savings_usd, 3.0)
        self.assertNotIn("/aws/tiny-logs", by_resource)


if __name__ == "__main__":
    unittest.main()
