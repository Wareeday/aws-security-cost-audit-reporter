"""Shared rule metadata catalog and helper utilities for audit checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aws_audit.models import Category, Finding


@dataclass(frozen=True, slots=True)
class RuleSpec:
    """Static rule definition used for finding metadata and SARIF rule descriptors."""

    rule_id: str
    title: str
    category: str
    default_severity: str
    description: str
    compliance: tuple[str, ...] = ()


RULE_CATALOG: dict[str, RuleSpec] = {
    "SEC-NET-001": RuleSpec(
        rule_id="SEC-NET-001",
        title="Unrestricted All-Traffic Security Group Ingress",
        category=Category.SECURITY.value,
        default_severity="CRITICAL",
        description="Security Group permits unrestricted inbound traffic across all protocols or all ports (0-65535) from 0.0.0.0/0 or ::/0.",
        compliance=("CIS-AWS-3.0:5.2", "CIS-AWS-3.0:5.3", "AWS-FSBP:EC2.19"),
    ),
    "SEC-NET-002": RuleSpec(
        rule_id="SEC-NET-002",
        title="Sensitive Port Exposed to the Internet",
        category=Category.SECURITY.value,
        default_severity="HIGH",
        description="Security Group exposes administrative or database ports (e.g., SSH, RDP, PostgreSQL, MySQL, Redis) to 0.0.0.0/0 or ::/0.",
        compliance=("CIS-AWS-3.0:5.2", "CIS-AWS-3.0:5.3", "AWS-FSBP:EC2.19"),
    ),
    "SEC-NET-003": RuleSpec(
        rule_id="SEC-NET-003",
        title="Default VPC Security Group Permits Traffic",
        category=Category.SECURITY.value,
        default_severity="MEDIUM",
        description="The default security group of a VPC should restrict all inbound and outbound traffic to prevent accidental exposure.",
        compliance=("CIS-AWS-3.0:5.4", "AWS-FSBP:EC2.2"),
    ),
    "SEC-NET-004": RuleSpec(
        rule_id="SEC-NET-004",
        title="VPC Flow Logs Disabled",
        category=Category.SECURITY.value,
        default_severity="HIGH",
        description="Active VPC lacks VPC Flow Logs, reducing network forensics, intrusion detection, and traffic auditing visibility.",
        compliance=("CIS-AWS-3.0:3.9", "AWS-FSBP:EC2.6"),
    ),
    "SEC-NET-005": RuleSpec(
        rule_id="SEC-NET-005",
        title="EC2 Instance Allows IMDSv1",
        category=Category.SECURITY.value,
        default_severity="HIGH",
        description="EC2 instance does not enforce IMDSv2 (HttpTokens=required), increasing SSRF credential-exfiltration risk.",
        compliance=("AWS-FSBP:EC2.8",),
    ),
    "SEC-NET-006": RuleSpec(
        rule_id="SEC-NET-006",
        title="Publicly Accessible RDS Instance",
        category=Category.SECURITY.value,
        default_severity="CRITICAL",
        description="Amazon RDS database instance is marked PubliclyAccessible=true, increasing direct internet attack surface.",
        compliance=("CIS-AWS-3.0:2.3.3", "AWS-FSBP:RDS.2"),
    ),
    "SEC-IAM-001": RuleSpec(
        rule_id="SEC-IAM-001",
        title="Root Account MFA Disabled",
        category=Category.SECURITY.value,
        default_severity="CRITICAL",
        description="AWS account root user does not have Multi-Factor Authentication (MFA) enabled.",
        compliance=("CIS-AWS-3.0:1.5", "AWS-FSBP:IAM.9"),
    ),
    "SEC-IAM-002": RuleSpec(
        rule_id="SEC-IAM-002",
        title="Root Account Access Keys Present",
        category=Category.SECURITY.value,
        default_severity="CRITICAL",
        description="AWS account root user has active API access keys configured.",
        compliance=("CIS-AWS-3.0:1.4", "AWS-FSBP:IAM.4"),
    ),
    "SEC-IAM-003": RuleSpec(
        rule_id="SEC-IAM-003",
        title="Console IAM User Missing MFA",
        category=Category.SECURITY.value,
        default_severity="HIGH",
        description="IAM user with AWS Management Console password access does not have an MFA device enrolled.",
        compliance=("CIS-AWS-3.0:1.10", "AWS-FSBP:IAM.5"),
    ),
    "SEC-IAM-004": RuleSpec(
        rule_id="SEC-IAM-004",
        title="Stale Active IAM Access Key",
        category=Category.SECURITY.value,
        default_severity="MEDIUM",
        description="Active IAM user access key exceeds the maximum allowed rotation age threshold.",
        compliance=("CIS-AWS-3.0:1.14", "AWS-FSBP:IAM.3"),
    ),
    "SEC-IAM-005": RuleSpec(
        rule_id="SEC-IAM-005",
        title="Dormant or Unused IAM Access Key",
        category=Category.SECURITY.value,
        default_severity="MEDIUM",
        description="Active IAM user access key has not been used within the inactivity threshold or was never used.",
        compliance=("CIS-AWS-3.0:1.12", "AWS-FSBP:IAM.22"),
    ),
    "SEC-IAM-006": RuleSpec(
        rule_id="SEC-IAM-006",
        title="Weak or Missing IAM Password Policy",
        category=Category.SECURITY.value,
        default_severity="MEDIUM",
        description="IAM account password policy is missing or fails complexity, minimum length, rotation, or reuse standards.",
        compliance=("CIS-AWS-3.0:1.8", "CIS-AWS-3.0:1.9", "AWS-FSBP:IAM.7"),
    ),
    "SEC-IAM-007": RuleSpec(
        rule_id="SEC-IAM-007",
        title="Over-Privileged IAM User Policy Assignment",
        category=Category.SECURITY.value,
        default_severity="HIGH",
        description="IAM user has direct inline policies or broad administrative managed policies attached instead of role/group least privilege.",
        compliance=("CIS-AWS-3.0:1.15", "CIS-AWS-3.0:1.16", "AWS-FSBP:IAM.1"),
    ),
    "SEC-STG-001": RuleSpec(
        rule_id="SEC-STG-001",
        title="S3 Block Public Access Incomplete",
        category=Category.SECURITY.value,
        default_severity="HIGH",
        description="S3 bucket does not enforce all four Block Public Access controls.",
        compliance=("CIS-AWS-3.0:2.1.4", "AWS-FSBP:S3.8"),
    ),
    "SEC-STG-002": RuleSpec(
        rule_id="SEC-STG-002",
        title="S3 Default Encryption Missing or Unverified",
        category=Category.SECURITY.value,
        default_severity="MEDIUM",
        description="S3 bucket lacks explicit default server-side encryption configuration.",
        compliance=("CIS-AWS-3.0:2.1.1", "AWS-FSBP:S3.4"),
    ),
    "SEC-STG-003": RuleSpec(
        rule_id="SEC-STG-003",
        title="S3 Bucket Versioning Disabled",
        category=Category.SECURITY.value,
        default_severity="LOW",
        description="S3 bucket versioning is disabled, increasing risk of accidental or ransomware-induced data loss.",
        compliance=("AWS-FSBP:S3.14",),
    ),
    "SEC-STG-004": RuleSpec(
        rule_id="SEC-STG-004",
        title="Unencrypted EBS Volume",
        category=Category.SECURITY.value,
        default_severity="HIGH",
        description="EBS volume does not have encryption at rest enabled.",
        compliance=("CIS-AWS-3.0:2.2.1", "AWS-FSBP:EC2.7"),
    ),
    "SEC-STG-005": RuleSpec(
        rule_id="SEC-STG-005",
        title="Unencrypted RDS Database Storage",
        category=Category.SECURITY.value,
        default_severity="HIGH",
        description="Amazon RDS database instance does not have storage encryption enabled.",
        compliance=("CIS-AWS-3.0:2.3.1", "AWS-FSBP:RDS.3"),
    ),
    "SEC-LOG-001": RuleSpec(
        rule_id="SEC-LOG-001",
        title="Multi-Region CloudTrail Logging Not Active",
        category=Category.SECURITY.value,
        default_severity="CRITICAL",
        description="No active multi-region AWS CloudTrail trail is logging control-plane API events.",
        compliance=("CIS-AWS-3.0:3.1", "AWS-FSBP:CloudTrail.1"),
    ),
    "SEC-LOG-002": RuleSpec(
        rule_id="SEC-LOG-002",
        title="CloudTrail Log File Validation Disabled",
        category=Category.SECURITY.value,
        default_severity="MEDIUM",
        description="Active CloudTrail trail does not enable SHA-256 log file integrity validation.",
        compliance=("CIS-AWS-3.0:3.2", "AWS-FSBP:CloudTrail.4"),
    ),
    "SEC-LOG-003": RuleSpec(
        rule_id="SEC-LOG-003",
        title="CloudWatch Log Group Infinite Retention",
        category=Category.SECURITY.value,
        default_severity="LOW",
        description="CloudWatch Log Group has no expiration retention policy set, increasing long-term log storage bloat.",
        compliance=("AWS-WellArchitected:SUS04-BP02",),
    ),
    "FIN-EBS-001": RuleSpec(
        rule_id="FIN-EBS-001",
        title="Unattached EBS Volume Waste",
        category=Category.COST.value,
        default_severity="MEDIUM",
        description="EBS volume is in 'available' (unattached) state and continues incurring recurring storage charges.",
        compliance=("AWS-FinOps:EBS-Idle",),
    ),
    "FIN-EBS-002": RuleSpec(
        rule_id="FIN-EBS-002",
        title="Legacy gp2 EBS Volume Upgrade Opportunity",
        category=Category.COST.value,
        default_severity="LOW",
        description="In-use gp2 EBS volume can be migrated online to gp3 for ~20% lower storage cost and decoupled baseline IOPS.",
        compliance=("AWS-FinOps:EBS-RightSizing",),
    ),
    "FIN-EBS-003": RuleSpec(
        rule_id="FIN-EBS-003",
        title="Aged Unreferenced EBS Snapshot",
        category=Category.COST.value,
        default_severity="LOW",
        description="EBS snapshot exceeds retention threshold and is not referenced by an active AMI.",
        compliance=("AWS-FinOps:Snapshot-Lifecycle",),
    ),
    "FIN-NET-001": RuleSpec(
        rule_id="FIN-NET-001",
        title="Unassociated Public IPv4 Elastic IP",
        category=Category.COST.value,
        default_severity="LOW",
        description="Unassociated Elastic IPv4 address incurs hourly public IPv4 charges without active workload association.",
        compliance=("AWS-FinOps:IPv4-Idle",),
    ),
    "FIN-NET-002": RuleSpec(
        rule_id="FIN-NET-002",
        title="Idle NAT Gateway",
        category=Category.COST.value,
        default_severity="MEDIUM",
        description="Provisioned NAT Gateway shows zero data transfer during the lookback window while accruing fixed hourly charges.",
        compliance=("AWS-FinOps:Network-Idle",),
    ),
    "FIN-NET-003": RuleSpec(
        rule_id="FIN-NET-003",
        title="Load Balancer With Zero Targets",
        category=Category.COST.value,
        default_severity="MEDIUM",
        description="Elastic Load Balancer has zero registered targets and accrues baseline hourly capacity charges.",
        compliance=("AWS-FinOps:ELB-Idle",),
    ),
    "FIN-EC2-001": RuleSpec(
        rule_id="FIN-EC2-001",
        title="Long-Stopped EC2 Instance Holding Storage",
        category=Category.COST.value,
        default_severity="MEDIUM",
        description="EC2 instance has remained stopped past threshold while attached EBS volumes continue incurring charges.",
        compliance=("AWS-FinOps:Compute-Zombie",),
    ),
    "FIN-LOG-001": RuleSpec(
        rule_id="FIN-LOG-001",
        title="Unbounded CloudWatch Log Group Storage Cost",
        category=Category.COST.value,
        default_severity="LOW",
        description="CloudWatch Log Group with infinite retention stores significant historical logs at recurring GB-month cost.",
        compliance=("AWS-FinOps:Logs-Retention",),
    ),
}


def build_finding(
    rule_id: str,
    *,
    resource_id: str,
    resource_type: str,
    resource_name: str,
    region: str,
    account_id: str,
    issue: str,
    remediation: str,
    remediation_cli: str = "",
    severity: str | None = None,
    monthly_savings_usd: float = 0.0,
    evidence: dict[str, Any] | None = None,
) -> Finding:
    """Create a Finding pre-populated with catalog title, category, and compliance controls."""
    spec = RULE_CATALOG[rule_id]
    return Finding(
        rule_id=rule_id,
        category=spec.category,
        severity=severity or spec.default_severity,
        title=spec.title,
        resource_id=resource_id,
        resource_type=resource_type,
        resource_name=resource_name,
        region=region,
        account_id=account_id,
        issue=issue,
        remediation=remediation,
        remediation_cli=remediation_cli,
        monthly_savings_usd=round(float(monthly_savings_usd), 2),
        compliance=list(spec.compliance),
        evidence=evidence or {},
    )


def default_region_for(snapshot: dict[str, Any], item: dict[str, Any] | None = None) -> str:
    """Resolve resource region from item metadata or snapshot primary region."""
    if item and item.get("region"):
        return str(item["region"])
    regions = snapshot.get("regions")
    if isinstance(regions, list) and regions:
        return str(regions[0])
    return str(snapshot.get("region", "us-east-1"))
