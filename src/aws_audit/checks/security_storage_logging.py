"""Storage, Database Encryption, and Audit Logging Security Checks."""

from __future__ import annotations

from typing import Any

from aws_audit.checks.base import build_finding, default_region_for
from aws_audit.config import AuditConfig
from aws_audit.models import Finding


def _check_s3_buckets(snapshot: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    account_id = str(snapshot.get("account_id", "unknown"))

    for bucket in snapshot.get("s3_buckets", []):
        bname = str(bucket.get("name", "unknown"))
        region = default_region_for(snapshot, bucket)
        resource_label = f"S3 Bucket: {bname}"

        if not bucket.get("public_access_blocked", True):
            findings.append(
                build_finding(
                    "SEC-STG-001",
                    resource_id=bname,
                    resource_type="AWS::S3::Bucket",
                    resource_name=resource_label,
                    region=region,
                    account_id=account_id,
                    issue="S3 Block Public Access is disabled or incomplete",
                    remediation="Enable all four Block Public Access settings unless the bucket intentionally hosts public content.",
                    remediation_cli=(
                        f"aws s3api put-public-access-block --bucket {bname} "
                        "--public-access-block-configuration "
                        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
                    ),
                )
            )

        if "encryption_enabled" in bucket and not bucket.get("encryption_enabled", True):
            findings.append(
                build_finding(
                    "SEC-STG-002",
                    resource_id=bname,
                    resource_type="AWS::S3::Bucket",
                    resource_name=resource_label,
                    region=region,
                    account_id=account_id,
                    issue="Explicit S3 bucket server-side encryption rule is missing",
                    remediation="Configure default SSE-KMS or SSE-S3 encryption on the bucket.",
                    remediation_cli=(
                        f"aws s3api put-bucket-encryption --bucket {bname} "
                        "--server-side-encryption-configuration "
                        "'{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'"
                    ),
                )
            )

        if "versioning_enabled" in bucket and not bucket.get("versioning_enabled", True):
            findings.append(
                build_finding(
                    "SEC-STG-003",
                    resource_id=bname,
                    resource_type="AWS::S3::Bucket",
                    resource_name=resource_label,
                    region=region,
                    account_id=account_id,
                    issue="S3 bucket versioning is disabled or suspended",
                    remediation="Enable S3 Versioning (and lifecycle expiration for noncurrent versions) to protect against accidental deletion.",
                    remediation_cli=(
                        f"aws s3api put-bucket-versioning --bucket {bname} "
                        "--versioning-configuration Status=Enabled"
                    ),
                )
            )

    return findings


def _check_encryption_at_rest(snapshot: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    account_id = str(snapshot.get("account_id", "unknown"))

    for vol in snapshot.get("ebs_volumes", []):
        if "encrypted" not in vol or vol.get("encrypted", True):
            continue
        vid = str(vol.get("volume_id", "unknown"))
        region = default_region_for(snapshot, vol)
        size_gb = vol.get("size_gb", 0)
        vtype = vol.get("volume_type", "gp3")
        findings.append(
            build_finding(
                "SEC-STG-004",
                resource_id=vid,
                resource_type="AWS::EC2::Volume",
                resource_name=f"EBS Volume: {vid}",
                region=region,
                account_id=account_id,
                issue=f"Unencrypted {size_gb} GB {vtype} EBS volume (state: {vol.get('state', 'unknown')})",
                remediation="Enable account-level EBS default encryption and migrate data to an encrypted snapshot copy.",
                remediation_cli=f"aws ec2 enable-ebs-encryption-by-default --region {region}",
                evidence={"size_gb": size_gb, "volume_type": vtype},
            )
        )

    for db in snapshot.get("rds_instances", []):
        if "storage_encrypted" not in db or db.get("storage_encrypted", True):
            continue
        db_id = str(db.get("db_instance_id", "unknown"))
        engine = str(db.get("engine", "database"))
        region = default_region_for(snapshot, db)
        findings.append(
            build_finding(
                "SEC-STG-005",
                resource_id=db_id,
                resource_type="AWS::RDS::DBInstance",
                resource_name=f"{db_id} ({engine})",
                region=region,
                account_id=account_id,
                issue=f"RDS {engine} database storage encryption is disabled",
                remediation="Create an encrypted snapshot copy of the database and restore to a new encrypted RDS instance.",
                remediation_cli=(
                    f"aws rds describe-db-instances --region {region} "
                    f"--db-instance-identifier {db_id} --query 'DBInstances[0].StorageEncrypted'"
                ),
            )
        )

    return findings


def _check_cloudtrail_and_logs(snapshot: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    account_id = str(snapshot.get("account_id", "unknown"))
    primary_region = default_region_for(snapshot)

    if "cloudtrail_trails" in snapshot:
        trails = snapshot.get("cloudtrail_trails", [])
        active_multi_region = [
            t for t in trails if t.get("is_multi_region", False) and t.get("is_logging", False)
        ]
        if not active_multi_region:
            findings.append(
                build_finding(
                    "SEC-LOG-001",
                    resource_id=f"arn:aws:cloudtrail:{primary_region}:{account_id}:trail/missing",
                    resource_type="AWS::CloudTrail::Trail",
                    resource_name="Account CloudTrail Coverage",
                    region="global",
                    account_id=account_id,
                    issue="No active multi-region CloudTrail trail is logging management events",
                    remediation="Create and enable a multi-region CloudTrail trail delivering logs to an encrypted, versioned S3 bucket.",
                    remediation_cli=(
                        f"aws cloudtrail create-trail --region {primary_region} --name org-audit-trail "
                        "--is-multi-region-trail --enable-log-file-validation --s3-bucket-name <audit-logs-bucket>"
                    ),
                    evidence={"trails_found": len(trails)},
                )
            )

        for trail in trails:
            if not trail.get("log_file_validation_enabled", True):
                tname = str(trail.get("name", "unknown"))
                tregion = default_region_for(snapshot, trail)
                findings.append(
                    build_finding(
                        "SEC-LOG-002",
                        resource_id=tname,
                        resource_type="AWS::CloudTrail::Trail",
                        resource_name=f"CloudTrail: {tname}",
                        region=tregion,
                        account_id=account_id,
                        issue="CloudTrail log file integrity validation is disabled",
                        remediation="Enable log file validation so SHA-256 digest files verify logs have not been tampered with.",
                        remediation_cli=(
                            f"aws cloudtrail update-trail --region {tregion} --name {tname} "
                            "--enable-log-file-validation"
                        ),
                    )
                )

    for lg in snapshot.get("log_groups", []):
        if lg.get("retention_days") is not None:
            continue
        lg_name = str(lg.get("name", "unknown"))
        region = default_region_for(snapshot, lg)
        stored_gb = round(float(lg.get("stored_bytes", 0)) / (1024 ** 3), 2)
        findings.append(
            build_finding(
                "SEC-LOG-003",
                resource_id=lg_name,
                resource_type="AWS::Logs::LogGroup",
                resource_name=f"Log Group: {lg_name}",
                region=region,
                account_id=account_id,
                issue=f"CloudWatch Log Group retention set to Never Expire ({stored_gb} GB stored)",
                remediation="Set an explicit retention period (e.g., 30, 90, or 365 days aligned with compliance needs).",
                remediation_cli=(
                    f"aws logs put-retention-policy --region {region} "
                    f"--log-group-name '{lg_name}' --retention-in-days 90"
                ),
                evidence={"stored_gb": stored_gb},
            )
        )

    return findings


def run_storage_logging_checks(snapshot: dict[str, Any], _cfg: AuditConfig) -> list[Finding]:
    """Evaluate S3, EBS/RDS encryption at rest, CloudTrail, and CloudWatch Log Group controls."""
    findings: list[Finding] = []
    findings.extend(_check_s3_buckets(snapshot))
    findings.extend(_check_encryption_at_rest(snapshot))
    findings.extend(_check_cloudtrail_and_logs(snapshot))
    return findings
