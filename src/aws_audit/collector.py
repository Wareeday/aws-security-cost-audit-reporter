"""AWS Data Collectors: offline normalized snapshot loading and live multi-region boto3 collection."""

from __future__ import annotations

import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from aws_audit.config import DEFAULT_DEMO_SNAPSHOT
from aws_audit.models import CollectionWarning

logger = logging.getLogger(__name__)

_STATE_TRANSITION_TS_RE = re.compile(r"\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) GMT\)")


def _extract_error_code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return str(response.get("Error", {}).get("Code", type(exc).__name__))
    return type(exc).__name__


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def normalize_snapshot(raw: dict[str, Any], collector_mode: str | None = None) -> dict[str, Any]:
    """Normalize v1 or v2 snapshot dictionaries into a consistent schema."""
    if not isinstance(raw, dict):
        raise ValueError("Snapshot root must be a JSON object.")

    normalized = dict(raw)
    if "regions" not in normalized:
        region = str(normalized.get("region", "us-east-1"))
        normalized["regions"] = [region]
    elif isinstance(normalized["regions"], str):
        normalized["regions"] = [normalized["regions"]]

    normalized.setdefault("schema_version", "2.0")
    normalized.setdefault("account_id", "unknown")
    normalized.setdefault("account_alias", "")
    normalized.setdefault("collected_at", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    normalized["collector_mode"] = collector_mode or normalized.get("collector_mode", "snapshot")
    normalized.setdefault("security_groups", [])
    normalized.setdefault("iam_users", [])
    normalized.setdefault("s3_buckets", [])
    normalized.setdefault("ebs_volumes", [])
    normalized.setdefault("elastic_ips", [])
    normalized.setdefault("collection_warnings", [])
    return normalized


def load_snapshot(filepath: Path | None = None, *, mode: str = "demo") -> dict[str, Any]:
    """Load and normalize an offline AWS account snapshot JSON file."""
    target = filepath or DEFAULT_DEMO_SNAPSHOT
    if not target.exists():
        raise FileNotFoundError(f"Snapshot file not found: {target}")
    data = json.loads(target.read_text(encoding="utf-8"))
    return normalize_snapshot(data, collector_mode=mode)


def save_snapshot(snapshot: dict[str, Any], filepath: Path) -> Path:
    """Persist a collected snapshot to disk as formatted JSON."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    filepath.write_text(json.dumps(snapshot, indent=2, default=str) + "\n", encoding="utf-8")
    return filepath


class LiveAWSCollector:
    """Resilient, multi-region, read-only AWS collector built on boto3 paginators."""

    def __init__(
        self,
        *,
        regions: list[str] | None = None,
        all_regions: bool = False,
        profile: str | None = None,
        role_arn: str | None = None,
        external_id: str | None = None,
        max_workers: int = 8,
        session: Any | None = None,
    ) -> None:
        self.requested_regions = regions or ["us-east-1"]
        self.all_regions = all_regions
        self.profile = profile
        self.role_arn = role_arn
        self.external_id = external_id
        self.max_workers = max(1, max_workers)
        self._injected_session = session
        self._warnings: list[CollectionWarning] = []

    def _warn(self, service: str, region: str, exc: Exception) -> None:
        code = _extract_error_code(exc)
        msg = str(exc)
        logger.warning("AWS collection warning [%s/%s] %s: %s", service, region, code, msg)
        self._warnings.append(
            CollectionWarning(service=service, region=region, error_code=code, message=msg)
        )

    def _build_session(self) -> tuple[Any, Any]:
        try:
            import boto3
            from botocore.config import Config
        except ImportError as exc:
            raise RuntimeError(
                "boto3 is not installed. Run `pip install boto3` or `pip install .[aws]` for live AWS mode."
            ) from exc

        boto_cfg = Config(
            retries={"max_attempts": 5, "mode": "adaptive"},
            connect_timeout=10,
            read_timeout=30,
        )

        if self._injected_session is not None:
            return self._injected_session, boto_cfg

        base_session = boto3.Session(profile_name=self.profile)
        if not self.role_arn:
            return base_session, boto_cfg

        sts = base_session.client("sts", config=boto_cfg)
        assume_kwargs: dict[str, Any] = {
            "RoleArn": self.role_arn,
            "RoleSessionName": "aws-security-cost-audit-reporter",
        }
        if self.external_id:
            assume_kwargs["ExternalId"] = self.external_id
        creds = sts.assume_role(**assume_kwargs)["Credentials"]
        assumed_session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
        return assumed_session, boto_cfg

    @staticmethod
    def _paginate(client: Any, op_name: str, result_key: str, **kwargs: Any) -> list[Any]:
        if hasattr(client, "can_paginate") and client.can_paginate(op_name):
            paginator = client.get_paginator(op_name)
            items: list[Any] = []
            for page in paginator.paginate(**kwargs):
                items.extend(page.get(result_key, []))
            return items
        method = getattr(client, op_name)
        return list(method(**kwargs).get(result_key, []))

    def _resolve_regions(self, session: Any, boto_cfg: Any) -> list[str]:
        if not self.all_regions:
            deduped: list[str] = []
            for reg in self.requested_regions:
                clean = reg.strip()
                if clean and clean not in deduped:
                    deduped.append(clean)
            return deduped or ["us-east-1"]

        ec2 = session.client("ec2", region_name=self.requested_regions[0], config=boto_cfg)
        try:
            resp = ec2.describe_regions(AllRegions=False)
            regions = sorted(r["RegionName"] for r in resp.get("Regions", []) if r.get("RegionName"))
            return regions or ["us-east-1"]
        except Exception as exc:
            self._warn("ec2:describe_regions", self.requested_regions[0], exc)
            return list(self.requested_regions)

    def _collect_iam_summary(self, iam: Any) -> dict[str, Any]:
        summary_data: dict[str, Any] = {}
        try:
            smap = iam.get_account_summary().get("SummaryMap", {})
            summary_data["root_mfa_enabled"] = bool(smap.get("AccountMFAEnabled", 0))
            summary_data["root_access_keys_present"] = bool(smap.get("AccountAccessKeysPresent", 0))
        except Exception as exc:
            self._warn("iam:get_account_summary", "global", exc)

        try:
            policy = iam.get_account_password_policy().get("PasswordPolicy", {})
            summary_data["password_policy"] = {
                "exists": True,
                "minimum_password_length": policy.get("MinimumPasswordLength", 0),
                "require_symbols": policy.get("RequireSymbols", False),
                "require_numbers": policy.get("RequireNumbers", False),
                "require_uppercase": policy.get("RequireUppercaseCharacters", False),
                "require_lowercase": policy.get("RequireLowercaseCharacters", False),
                "max_password_age": policy.get("MaxPasswordAge"),
                "password_reuse_prevention": policy.get("PasswordReusePrevention", 0),
            }
        except Exception as exc:
            if _extract_error_code(exc) == "NoSuchEntity":
                summary_data["password_policy"] = {"exists": False}
            else:
                self._warn("iam:get_account_password_policy", "global", exc)

        return summary_data

    def _collect_iam_users(self, iam: Any, now: datetime) -> list[dict[str, Any]]:
        users_out: list[dict[str, Any]] = []
        try:
            users = self._paginate(iam, "list_users", "Users")
        except Exception as exc:
            self._warn("iam:list_users", "global", exc)
            return users_out

        for user in users:
            uname = user["UserName"]
            has_console = True
            try:
                iam.get_login_profile(UserName=uname)
            except Exception as exc:
                if _extract_error_code(exc) == "NoSuchEntity":
                    has_console = False
                else:
                    self._warn("iam:get_login_profile", "global", exc)

            has_mfa = False
            try:
                mfa_devices = self._paginate(iam, "list_mfa_devices", "MFADevices", UserName=uname)
                has_mfa = len(mfa_devices) > 0
            except Exception as exc:
                self._warn("iam:list_mfa_devices", "global", exc)

            attached_policies: list[str] = []
            try:
                attached = self._paginate(
                    iam, "list_attached_user_policies", "AttachedPolicies", UserName=uname
                )
                attached_policies = [p.get("PolicyName", "") for p in attached if p.get("PolicyName")]
            except Exception as exc:
                self._warn("iam:list_attached_user_policies", "global", exc)

            inline_policies: list[str] = []
            try:
                inline_policies = self._paginate(
                    iam, "list_user_policies", "PolicyNames", UserName=uname
                )
            except Exception as exc:
                self._warn("iam:list_user_policies", "global", exc)

            keys_out: list[dict[str, Any]] = []
            try:
                keys = self._paginate(iam, "list_access_keys", "AccessKeyMetadata", UserName=uname)
                for key_meta in keys:
                    key_id = key_meta["AccessKeyId"]
                    age_days = max(0, (now - _ensure_utc(key_meta["CreateDate"])).days)
                    last_used_days: int | None = None
                    try:
                        lu_resp = iam.get_access_key_last_used(AccessKeyId=key_id)
                        last_used_date = lu_resp.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                        if last_used_date is not None:
                            last_used_days = max(0, (now - _ensure_utc(last_used_date)).days)
                    except Exception as exc:
                        self._warn("iam:get_access_key_last_used", "global", exc)
                    keys_out.append(
                        {
                            "access_key_id": key_id,
                            "status": key_meta.get("Status", "Inactive"),
                            "age_days": age_days,
                            "last_used_days": last_used_days,
                        }
                    )
            except Exception as exc:
                self._warn("iam:list_access_keys", "global", exc)

            users_out.append(
                {
                    "username": uname,
                    "has_console_access": has_console,
                    "has_mfa": has_mfa,
                    "attached_policies": attached_policies,
                    "inline_policies": inline_policies,
                    "access_keys": keys_out,
                }
            )

        return users_out

    def _inspect_s3_bucket(self, s3: Any, bname: str) -> dict[str, Any]:
        entry: dict[str, Any] = {"name": bname, "region": "us-east-1"}

        try:
            loc = s3.get_bucket_location(Bucket=bname).get("LocationConstraint")
            if loc == "EU":
                entry["region"] = "eu-west-1"
            elif loc:
                entry["region"] = str(loc)
        except Exception as exc:
            self._warn("s3:get_bucket_location", "global", exc)

        try:
            pab = s3.get_public_access_block(Bucket=bname).get("PublicAccessBlockConfiguration", {})
            entry["public_access_blocked"] = all(
                [
                    pab.get("BlockPublicAcls", False),
                    pab.get("IgnorePublicAcls", False),
                    pab.get("BlockPublicPolicy", False),
                    pab.get("RestrictPublicBuckets", False),
                ]
            )
        except Exception as exc:
            code = _extract_error_code(exc)
            if code == "NoSuchPublicAccessBlockConfiguration":
                entry["public_access_blocked"] = False
            else:
                self._warn("s3:get_public_access_block", entry["region"], exc)

        try:
            enc = s3.get_bucket_encryption(Bucket=bname)
            rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            entry["encryption_enabled"] = len(rules) > 0
        except Exception as exc:
            code = _extract_error_code(exc)
            if code in {"ServerSideEncryptionConfigurationNotFoundError", "NoSuchEncryptionConfiguration"}:
                entry["encryption_enabled"] = False
            else:
                self._warn("s3:get_bucket_encryption", entry["region"], exc)

        try:
            ver = s3.get_bucket_versioning(Bucket=bname)
            entry["versioning_enabled"] = ver.get("Status") == "Enabled"
        except Exception as exc:
            self._warn("s3:get_bucket_versioning", entry["region"], exc)

        return entry

    def _collect_s3_buckets(self, s3: Any) -> list[dict[str, Any]]:
        try:
            raw_buckets = s3.list_buckets().get("Buckets", [])
        except Exception as exc:
            self._warn("s3:list_buckets", "global", exc)
            return []

        if not raw_buckets:
            return []

        results: list[dict[str, Any]] = []
        workers = min(self.max_workers, len(raw_buckets))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(self._inspect_s3_bucket, s3, b["Name"]): b["Name"]
                for b in raw_buckets
                if b.get("Name")
            }
            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception as exc:
                    self._warn("s3:inspect_bucket", "global", exc)
        return sorted(results, key=lambda item: item["name"])

    def _collect_region(self, session: Any, boto_cfg: Any, region: str, now: datetime) -> dict[str, Any]:
        ec2 = session.client("ec2", region_name=region, config=boto_cfg)
        rds = session.client("rds", region_name=region, config=boto_cfg)
        elbv2 = session.client("elbv2", region_name=region, config=boto_cfg)
        cloudtrail = session.client("cloudtrail", region_name=region, config=boto_cfg)
        logs = session.client("logs", region_name=region, config=boto_cfg)
        cw = session.client("cloudwatch", region_name=region, config=boto_cfg)

        region_data: dict[str, Any] = {
            "security_groups": [],
            "ebs_volumes": [],
            "ebs_snapshots": [],
            "elastic_ips": [],
            "ec2_instances": [],
            "vpcs": [],
            "nat_gateways": [],
            "load_balancers": [],
            "rds_instances": [],
            "cloudtrail_trails": [],
            "log_groups": [],
        }

        # 1. Security Groups
        try:
            for sg in self._paginate(ec2, "describe_security_groups", "SecurityGroups"):
                def _parse_perms(perms: list[dict[str, Any]]) -> list[dict[str, Any]]:
                    parsed = []
                    for perm in perms:
                        cidrs = [r["CidrIp"] for r in perm.get("IpRanges", []) if r.get("CidrIp")]
                        cidrs += [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6")]
                        parsed.append(
                            {
                                "from_port": perm.get("FromPort"),
                                "to_port": perm.get("ToPort"),
                                "protocol": perm.get("IpProtocol", "-1"),
                                "cidrs": cidrs,
                            }
                        )
                    return parsed

                region_data["security_groups"].append(
                    {
                        "group_id": sg["GroupId"],
                        "group_name": sg.get("GroupName", ""),
                        "region": region,
                        "vpc_id": sg.get("VpcId", ""),
                        "is_default": sg.get("GroupName") == "default",
                        "rules": _parse_perms(sg.get("IpPermissions", [])),
                        "egress_rules": _parse_perms(sg.get("IpPermissionsEgress", [])),
                    }
                )
        except Exception as exc:
            self._warn("ec2:describe_security_groups", region, exc)

        # 2. EBS Volumes (ALL volumes so we catch unencrypted in-use & gp2->gp3 savings)
        vol_map: dict[str, dict[str, Any]] = {}
        try:
            for vol in self._paginate(ec2, "describe_volumes", "Volumes"):
                vid = vol["VolumeId"]
                create_time = vol.get("CreateTime")
                age_days = max(0, (now - _ensure_utc(create_time)).days) if create_time else 0
                entry = {
                    "volume_id": vid,
                    "region": region,
                    "volume_type": vol.get("VolumeType", "gp3"),
                    "size_gb": vol.get("Size", 0),
                    "state": vol.get("State", "available"),
                    "encrypted": bool(vol.get("Encrypted", False)),
                    "age_days": age_days,
                }
                vol_map[vid] = entry
                region_data["ebs_volumes"].append(entry)
        except Exception as exc:
            self._warn("ec2:describe_volumes", region, exc)

        # 3. EC2 Instances
        try:
            reservations = self._paginate(ec2, "describe_instances", "Reservations")
            for res in reservations:
                for inst in res.get("Instances", []):
                    tags = {t["Key"]: t["Value"] for t in inst.get("Tags", []) if "Key" in t}
                    state_name = inst.get("State", {}).get("Name", "unknown")
                    stopped_days = 0
                    if state_name == "stopped":
                        match = _STATE_TRANSITION_TS_RE.search(inst.get("StateTransitionReason", ""))
                        if match:
                            stopped_dt = datetime.strptime(
                                match.group(1), "%Y-%m-%d %H:%M:%S"
                            ).replace(tzinfo=timezone.utc)
                            stopped_days = max(0, (now - stopped_dt).days)
                    attached_vols = []
                    for mapping in inst.get("BlockDeviceMappings", []):
                        ebs_ref = mapping.get("Ebs", {})
                        vid = ebs_ref.get("VolumeId")
                        if vid and vid in vol_map:
                            attached_vols.append(
                                {
                                    "volume_id": vid,
                                    "volume_type": vol_map[vid]["volume_type"],
                                    "size_gb": vol_map[vid]["size_gb"],
                                }
                            )
                    http_tokens = inst.get("MetadataOptions", {}).get("HttpTokens", "optional")
                    region_data["ec2_instances"].append(
                        {
                            "instance_id": inst["InstanceId"],
                            "name": tags.get("Name", ""),
                            "region": region,
                            "instance_type": inst.get("InstanceType", ""),
                            "state": state_name,
                            "public_ip": inst.get("PublicIpAddress"),
                            "imdsv2_required": http_tokens == "required",
                            "stopped_days": stopped_days,
                            "attached_volumes": attached_vols,
                        }
                    )
        except Exception as exc:
            self._warn("ec2:describe_instances", region, exc)

        # 4. EBS Snapshots + AMI reference check
        try:
            ami_snap_ids: set[str] = set()
            try:
                for img in ec2.describe_images(Owners=["self"]).get("Images", []):
                    for bdm in img.get("BlockDeviceMappings", []):
                        sid = bdm.get("Ebs", {}).get("SnapshotId")
                        if sid:
                            ami_snap_ids.add(sid)
            except Exception as exc:
                self._warn("ec2:describe_images", region, exc)

            for snap in self._paginate(ec2, "describe_snapshots", "Snapshots", OwnerIds=["self"]):
                start_time = snap.get("StartTime")
                age_days = max(0, (now - _ensure_utc(start_time)).days) if start_time else 0
                region_data["ebs_snapshots"].append(
                    {
                        "snapshot_id": snap["SnapshotId"],
                        "region": region,
                        "volume_size_gb": snap.get("VolumeSize", 0),
                        "age_days": age_days,
                        "encrypted": bool(snap.get("Encrypted", False)),
                        "ami_referenced": snap["SnapshotId"] in ami_snap_ids,
                    }
                )
        except Exception as exc:
            self._warn("ec2:describe_snapshots", region, exc)

        # 5. Elastic IPs
        try:
            for addr in ec2.describe_addresses().get("Addresses", []):
                region_data["elastic_ips"].append(
                    {
                        "allocation_id": addr.get("AllocationId", ""),
                        "public_ip": addr.get("PublicIp", ""),
                        "region": region,
                        "associated": bool(addr.get("AssociationId")),
                    }
                )
        except Exception as exc:
            self._warn("ec2:describe_addresses", region, exc)

        # 6. VPCs & Flow Logs
        try:
            vpcs = self._paginate(ec2, "describe_vpcs", "Vpcs")
            flow_logs = self._paginate(ec2, "describe_flow_logs", "FlowLogs")
            active_flow_vpcs = {
                fl.get("ResourceId")
                for fl in flow_logs
                if fl.get("FlowLogStatus") == "ACTIVE"
            }
            for vpc in vpcs:
                vpc_id = vpc["VpcId"]
                region_data["vpcs"].append(
                    {
                        "vpc_id": vpc_id,
                        "region": region,
                        "cidr_block": vpc.get("CidrBlock", ""),
                        "is_default": bool(vpc.get("IsDefault", False)),
                        "flow_logs_enabled": vpc_id in active_flow_vpcs,
                    }
                )
        except Exception as exc:
            self._warn("ec2:describe_vpcs_flow_logs", region, exc)

        # 7. NAT Gateways + 7d CloudWatch transfer check
        try:
            nats = self._paginate(ec2, "describe_nat_gateways", "NatGateways")
            start_dt = now - timedelta(days=7)
            for nat in nats:
                nat_id = nat["NatGatewayId"]
                nat_entry: dict[str, Any] = {
                    "nat_gateway_id": nat_id,
                    "region": region,
                    "state": nat.get("State", "available"),
                }
                if nat_entry["state"] == "available":
                    try:
                        total_bytes = 0
                        for metric in ("BytesOutToDestination", "BytesInFromSource"):
                            stats = cw.get_metric_statistics(
                                Namespace="AWS/NATGateway",
                                MetricName=metric,
                                Dimensions=[{"Name": "NatGatewayId", "Value": nat_id}],
                                StartTime=start_dt,
                                EndTime=now,
                                Period=86400,
                                Statistics=["Sum"],
                            )
                            total_bytes += sum(int(dp.get("Sum", 0)) for dp in stats.get("Datapoints", []))
                        nat_entry["bytes_7d"] = total_bytes
                        nat_entry["idle"] = total_bytes == 0
                    except Exception as exc:
                        self._warn("cloudwatch:nat_metrics", region, exc)
                region_data["nat_gateways"].append(nat_entry)
        except Exception as exc:
            self._warn("ec2:describe_nat_gateways", region, exc)

        # 8. Load Balancers (ELBv2)
        try:
            lbs = self._paginate(elbv2, "describe_load_balancers", "LoadBalancers")
            for lb in lbs:
                lb_arn = lb["LoadBalancerArn"]
                target_count = 0
                try:
                    tgs = self._paginate(
                        elbv2, "describe_target_groups", "TargetGroups", LoadBalancerArn=lb_arn
                    )
                    for tg in tgs:
                        health = elbv2.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])
                        target_count += len(health.get("TargetHealthDescriptions", []))
                except Exception as exc:
                    self._warn("elbv2:describe_target_health", region, exc)
                    target_count = 1  # Avoid false positive when target lookup fails
                region_data["load_balancers"].append(
                    {
                        "arn": lb_arn,
                        "name": lb.get("LoadBalancerName", ""),
                        "type": lb.get("Type", "application"),
                        "region": region,
                        "target_count": target_count,
                    }
                )
        except Exception as exc:
            self._warn("elbv2:describe_load_balancers", region, exc)

        # 9. RDS Instances
        try:
            for db in self._paginate(rds, "describe_db_instances", "DBInstances"):
                region_data["rds_instances"].append(
                    {
                        "db_instance_id": db["DBInstanceIdentifier"],
                        "engine": db.get("Engine", ""),
                        "region": region,
                        "publicly_accessible": bool(db.get("PubliclyAccessible", False)),
                        "storage_encrypted": bool(db.get("StorageEncrypted", False)),
                    }
                )
        except Exception as exc:
            self._warn("rds:describe_db_instances", region, exc)

        # 10. CloudTrail Trails (home region trails only to avoid cross-region duplicates)
        try:
            for trail in cloudtrail.describe_trails(includeShadowTrails=False).get("trailList", []):
                trail_arn = trail.get("TrailARN", trail.get("Name", ""))
                is_logging = False
                try:
                    status = cloudtrail.get_trail_status(Name=trail_arn)
                    is_logging = bool(status.get("IsLogging", False))
                except Exception as exc:
                    self._warn("cloudtrail:get_trail_status", region, exc)
                region_data["cloudtrail_trails"].append(
                    {
                        "name": trail.get("Name", ""),
                        "region": trail.get("HomeRegion", region),
                        "is_multi_region": bool(trail.get("IsMultiRegionTrail", False)),
                        "is_logging": is_logging,
                        "log_file_validation_enabled": bool(
                            trail.get("LogFileValidationEnabled", False)
                        ),
                    }
                )
        except Exception as exc:
            self._warn("cloudtrail:describe_trails", region, exc)

        # 11. CloudWatch Log Groups
        try:
            for lg in self._paginate(logs, "describe_log_groups", "logGroups"):
                region_data["log_groups"].append(
                    {
                        "name": lg.get("logGroupName", ""),
                        "region": region,
                        "retention_days": lg.get("retentionInDays"),
                        "stored_bytes": lg.get("storedBytes", 0),
                    }
                )
        except Exception as exc:
            self._warn("logs:describe_log_groups", region, exc)

        return region_data

    def collect(self) -> dict[str, Any]:
        """Execute full global + multi-region read-only AWS collection."""
        self._warnings = []
        now = datetime.now(timezone.utc)
        session, boto_cfg = self._build_session()
        regions = self._resolve_regions(session, boto_cfg)

        sts = session.client("sts", config=boto_cfg)
        iam = session.client("iam", config=boto_cfg)
        s3 = session.client("s3", config=boto_cfg)

        account_id = "unknown"
        try:
            account_id = str(sts.get_caller_identity().get("Account", "unknown"))
        except Exception as exc:
            self._warn("sts:get_caller_identity", "global", exc)

        account_alias = ""
        try:
            aliases = iam.list_account_aliases().get("AccountAliases", [])
            if aliases:
                account_alias = str(aliases[0])
        except Exception as exc:
            self._warn("iam:list_account_aliases", "global", exc)

        iam_summary = self._collect_iam_summary(iam)
        iam_users = self._collect_iam_users(iam, now)
        s3_buckets = self._collect_s3_buckets(s3)

        aggregated: dict[str, list[Any]] = {
            "security_groups": [],
            "ebs_volumes": [],
            "ebs_snapshots": [],
            "elastic_ips": [],
            "ec2_instances": [],
            "vpcs": [],
            "nat_gateways": [],
            "load_balancers": [],
            "rds_instances": [],
            "cloudtrail_trails": [],
            "log_groups": [],
        }

        workers = min(self.max_workers, len(regions))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(self._collect_region, session, boto_cfg, reg, now): reg for reg in regions
            }
            for fut in as_completed(futures):
                reg = futures[fut]
                try:
                    reg_data = fut.result()
                    for key, items in reg_data.items():
                        aggregated[key].extend(items)
                except Exception as exc:
                    self._warn("collector:region", reg, exc)

        return normalize_snapshot(
            {
                "schema_version": "2.0",
                "account_id": account_id,
                "account_alias": account_alias,
                "regions": regions,
                "collected_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "collector_mode": "aws",
                "iam_summary": iam_summary,
                "iam_users": iam_users,
                "s3_buckets": s3_buckets,
                **aggregated,
                "collection_warnings": [w.to_dict() for w in self._warnings],
            },
            collector_mode="aws",
        )
