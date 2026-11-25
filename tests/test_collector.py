"""Unit tests for snapshot normalization and LiveAWSCollector with a fake boto3 session."""

from __future__ import annotations

import sys
import tempfile
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from aws_audit.collector import LiveAWSCollector, load_snapshot, normalize_snapshot, save_snapshot


class _FakeClientError(Exception):
    def __init__(self, code: str, message: str = "error") -> None:
        super().__init__(message)
        self.response = {"Error": {"Code": code, "Message": message}}


class _FakePaginator:
    def __init__(self, pages: list[dict]) -> None:
        self._pages = pages

    def paginate(self, **_kwargs):
        return iter(self._pages)


class _FakeClient:
    def __init__(self, responses: dict, paginator_pages: dict | None = None) -> None:
        self._responses = responses
        self._paginator_pages = paginator_pages or {}

    def can_paginate(self, op_name: str) -> bool:
        return op_name in self._paginator_pages

    def get_paginator(self, op_name: str) -> _FakePaginator:
        return _FakePaginator(self._paginator_pages[op_name])

    def __getattr__(self, name: str):
        def _method(**kwargs):
            val = self._responses[name]
            result = val(**kwargs) if callable(val) else val
            if isinstance(result, Exception):
                raise result
            return result

        return _method


class _FakeSession:
    def __init__(self, clients: dict) -> None:
        self._clients = clients

    def client(self, service: str, region_name: str | None = None, config=None):
        key = (service, region_name)
        if key in self._clients:
            return self._clients[key]
        return self._clients[service]


class TestCollector(unittest.TestCase):
    def test_v1_snapshot_normalization_and_roundtrip(self) -> None:
        v1 = {
            "account_id": "123456789012",
            "region": "us-west-2",
            "security_groups": [],
            "iam_users": [],
            "s3_buckets": [],
            "ebs_volumes": [],
            "elastic_ips": [],
        }
        norm = normalize_snapshot(v1, collector_mode="snapshot")
        self.assertEqual(norm["regions"], ["us-west-2"])
        self.assertEqual(norm["collector_mode"], "snapshot")

        with tempfile.TemporaryDirectory() as tmpdir:
            snap_path = Path(tmpdir) / "snap.json"
            save_snapshot(norm, snap_path)
            reloaded = load_snapshot(snap_path, mode="snapshot")
            self.assertEqual(reloaded["account_id"], "123456789012")
            self.assertEqual(reloaded["regions"], ["us-west-2"])

    def test_live_collector_pagination_and_graceful_access_denied(self) -> None:
        now = datetime.now(timezone.utc)
        old_key_dt = now - timedelta(days=120)
        stopped_ts = (now - timedelta(days=40)).strftime("%Y-%m-%d %H:%M:%S")

        sts_client = _FakeClient({"get_caller_identity": {"Account": "999888777666"}})
        iam_client = _FakeClient(
            responses={
                "list_account_aliases": {"AccountAliases": ["prod-core"]},
                "get_account_summary": {
                    "SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}
                },
                "get_account_password_policy": _FakeClientError("NoSuchEntity"),
                "get_login_profile": lambda UserName: (
                    _FakeClientError("NoSuchEntity") if UserName == "svc-bot" else {"LoginProfile": {}}
                ),
                "get_access_key_last_used": {"AccessKeyLastUsed": {"LastUsedDate": now - timedelta(days=2)}},
            },
            paginator_pages={
                "list_users": [{"Users": [{"UserName": "alice"}]}, {"Users": [{"UserName": "svc-bot"}]}],
                "list_mfa_devices": [{"MFADevices": []}],
                "list_attached_user_policies": [{"AttachedPolicies": [{"PolicyName": "AdministratorAccess"}]}],
                "list_user_policies": [{"PolicyNames": []}],
                "list_access_keys": [
                    {
                        "AccessKeyMetadata": [
                            {"AccessKeyId": "AKIA1", "Status": "Active", "CreateDate": old_key_dt}
                        ]
                    }
                ],
            },
        )
        s3_client = _FakeClient(
            {
                "list_buckets": {"Buckets": [{"Name": "public-missing-pab"}]},
                "get_bucket_location": {"LocationConstraint": None},
                "get_public_access_block": _FakeClientError("NoSuchPublicAccessBlockConfiguration"),
                "get_bucket_encryption": _FakeClientError("ServerSideEncryptionConfigurationNotFoundError"),
                "get_bucket_versioning": {"Status": "Suspended"},
            }
        )
        ec2_client = _FakeClient(
            responses={
                "describe_images": {"Images": []},
                "describe_addresses": {"Addresses": [{"AllocationId": "eip-1", "PublicIp": "198.51.100.5"}]},
            },
            paginator_pages={
                "describe_security_groups": [
                    {"SecurityGroups": [{"GroupId": "sg-1", "GroupName": "web", "IpPermissions": []}]}
                ],
                "describe_volumes": [
                    {
                        "Volumes": [
                            {
                                "VolumeId": "vol-1",
                                "VolumeType": "gp3",
                                "Size": 100,
                                "State": "in-use",
                                "Encrypted": True,
                                "CreateTime": old_key_dt,
                            }
                        ]
                    }
                ],
                "describe_instances": [
                    {
                        "Reservations": [
                            {
                                "Instances": [
                                    {
                                        "InstanceId": "i-1",
                                        "Tags": [{"Key": "Name", "Value": "worker"}],
                                        "InstanceType": "t3.small",
                                        "State": {"Name": "stopped"},
                                        "StateTransitionReason": f"User initiated ({stopped_ts} GMT)",
                                        "MetadataOptions": {"HttpTokens": "optional"},
                                        "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-1"}}],
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "describe_snapshots": [{"Snapshots": []}],
                "describe_vpcs": [{"Vpcs": [{"VpcId": "vpc-1", "IsDefault": False}]}],
                "describe_flow_logs": [{"FlowLogs": []}],
                "describe_nat_gateways": [{"NatGateways": []}],
            },
        )
        rds_client = _FakeClient(
            {"describe_db_instances": _FakeClientError("AccessDenied", "Not authorized for RDS")}
        )
        elbv2_client = _FakeClient({}, paginator_pages={"describe_load_balancers": [{"LoadBalancers": []}]})
        cloudtrail_client = _FakeClient({"describe_trails": {"trailList": []}})
        logs_client = _FakeClient({}, paginator_pages={"describe_log_groups": [{"logGroups": []}]})
        cw_client = _FakeClient({})

        fake_session = _FakeSession(
            {
                "sts": sts_client,
                "iam": iam_client,
                "s3": s3_client,
                "ec2": ec2_client,
                "rds": rds_client,
                "elbv2": elbv2_client,
                "cloudtrail": cloudtrail_client,
                "logs": logs_client,
                "cloudwatch": cw_client,
            }
        )

        # Provide minimal stub boto3 + botocore modules so tests run without boto3 installed
        fake_boto3 = types.ModuleType("boto3")
        fake_botocore = types.ModuleType("botocore")
        fake_botocore_cfg = types.ModuleType("botocore.config")

        class _DummyConfig:
            def __init__(self, **_kwargs) -> None:
                pass

        fake_botocore_cfg.Config = _DummyConfig
        fake_botocore.config = fake_botocore_cfg

        with patch.dict(
            sys.modules,
            {"boto3": fake_boto3, "botocore": fake_botocore, "botocore.config": fake_botocore_cfg},
        ):
            collector = LiveAWSCollector(regions=["us-east-1"], session=fake_session)
            snap = collector.collect()

        self.assertEqual(snap["account_id"], "999888777666")
        self.assertEqual(snap["account_alias"], "prod-core")
        self.assertEqual(snap["iam_summary"]["password_policy"], {"exists": False})
        self.assertEqual(len(snap["iam_users"]), 2)
        svc = next(u for u in snap["iam_users"] if u["username"] == "svc-bot")
        self.assertFalse(svc["has_console_access"])
        self.assertFalse(snap["s3_buckets"][0]["public_access_blocked"])
        self.assertGreaterEqual(snap["ec2_instances"][0]["stopped_days"], 39)
        # RDS AccessDenied should produce a warning instead of crashing the audit
        self.assertEqual(len(snap["collection_warnings"]), 1)
        self.assertEqual(snap["collection_warnings"][0]["error_code"], "AccessDenied")


if __name__ == "__main__":
    unittest.main()
