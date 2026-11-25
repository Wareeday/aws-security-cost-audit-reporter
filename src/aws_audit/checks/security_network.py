"""Network & Compute Security Checks: Security Groups, VPC Flow Logs, EC2 IMDSv2, Public RDS."""

from __future__ import annotations

from typing import Any

from aws_audit.checks.base import build_finding, default_region_for
from aws_audit.config import AuditConfig
from aws_audit.models import Finding

WORLD_CIDRS = frozenset({"0.0.0.0/0", "::/0"})


def _is_world_open(cidr: str) -> bool:
    return cidr.strip() in WORLD_CIDRS


def _normalize_protocol(proto: Any) -> str:
    value = str(proto if proto is not None else "-1").strip().lower()
    if value in {"-1", "all"}:
        return "all"
    if value == "6":
        return "tcp"
    if value == "17":
        return "udp"
    return value


def _check_security_groups(snapshot: dict[str, Any], cfg: AuditConfig) -> list[Finding]:
    findings: list[Finding] = []
    account_id = str(snapshot.get("account_id", "unknown"))

    for sg in snapshot.get("security_groups", []):
        sg_id = str(sg.get("group_id", "unknown"))
        sg_name = str(sg.get("group_name", ""))
        region = default_region_for(snapshot, sg)
        resource_label = f"{sg_id} ({sg_name})" if sg_name else sg_id
        ingress_rules = sg.get("rules", [])
        egress_rules = sg.get("egress_rules", [])

        # SEC-NET-003: Default Security Group should have zero rules
        if sg.get("is_default", sg_name == "default") and (ingress_rules or egress_rules):
            findings.append(
                build_finding(
                    "SEC-NET-003",
                    resource_id=sg_id,
                    resource_type="AWS::EC2::SecurityGroup",
                    resource_name=resource_label,
                    region=region,
                    account_id=account_id,
                    issue=(
                        f"Default VPC security group has active rules "
                        f"({len(ingress_rules)} ingress, {len(egress_rules)} egress)"
                    ),
                    remediation=(
                        "Remove all ingress and egress rules from the default security group "
                        "and assign explicit workload-specific security groups."
                    ),
                    remediation_cli=(
                        f"aws ec2 describe-security-groups --region {region} --group-ids {sg_id}"
                    ),
                    evidence={
                        "ingress_count": len(ingress_rules),
                        "egress_count": len(egress_rules),
                    },
                )
            )

        for rule in ingress_rules:
            open_cidrs = sorted({c for c in rule.get("cidrs", []) if _is_world_open(str(c))})
            if not open_cidrs:
                continue

            proto = _normalize_protocol(rule.get("protocol"))
            from_p = rule.get("from_port")
            to_p = rule.get("to_port")
            cidr_display = ", ".join(open_cidrs)

            all_ports_range = (
                from_p is not None
                and to_p is not None
                and int(from_p) == 0
                and int(to_p) == 65535
            )
            if proto == "all" or all_ports_range:
                scope_desc = "All traffic (-1)" if proto == "all" else f"All {proto.upper()} ports (0-65535)"
                findings.append(
                    build_finding(
                        "SEC-NET-001",
                        resource_id=sg_id,
                        resource_type="AWS::EC2::SecurityGroup",
                        resource_name=resource_label,
                        region=region,
                        account_id=account_id,
                        issue=f"{scope_desc} allowed from {cidr_display}",
                        remediation="Restrict inbound rules to explicit ports and trusted VPC or VPN CIDR ranges.",
                        remediation_cli=(
                            f"aws ec2 revoke-security-group-ingress --region {region} "
                            f"--group-id {sg_id} --protocol {rule.get('protocol', '-1')} --cidr {open_cidrs[0]}"
                        ),
                        evidence={"protocol": proto, "cidrs": open_cidrs},
                    )
                )
                continue

            if from_p is None or to_p is None or proto not in {"tcp", "udp"}:
                continue

            from_port = int(from_p)
            to_port = int(to_p)
            for port, (service, severity) in cfg.sensitive_ports.items():
                if from_port <= port <= to_port:
                    findings.append(
                        build_finding(
                            "SEC-NET-002",
                            severity=severity,
                            resource_id=sg_id,
                            resource_type="AWS::EC2::SecurityGroup",
                            resource_name=resource_label,
                            region=region,
                            account_id=account_id,
                            issue=(
                                f"Port {port}/{proto.upper()} ({service}) open to {cidr_display}"
                            ),
                            remediation=(
                                f"Restrict port {port} ({service}) to trusted corporate/VPN CIDRs "
                                "or replace direct ingress with AWS Systems Manager Session Manager."
                            ),
                            remediation_cli=(
                                f"aws ec2 revoke-security-group-ingress --region {region} "
                                f"--group-id {sg_id} --protocol {proto} --port {port} --cidr {open_cidrs[0]}"
                            ),
                            evidence={
                                "port": port,
                                "protocol": proto,
                                "service": service,
                                "cidrs": open_cidrs,
                            },
                        )
                    )

    return findings


def _check_vpc_flow_logs(snapshot: dict[str, Any]) -> list[Finding]:
    if "vpcs" not in snapshot:
        return []
    findings: list[Finding] = []
    account_id = str(snapshot.get("account_id", "unknown"))

    for vpc in snapshot.get("vpcs", []):
        if vpc.get("flow_logs_enabled", False):
            continue
        vpc_id = str(vpc.get("vpc_id", "unknown"))
        region = default_region_for(snapshot, vpc)
        cidr = vpc.get("cidr_block", "")
        label = f"{vpc_id} ({cidr})" if cidr else vpc_id
        findings.append(
            build_finding(
                "SEC-NET-004",
                resource_id=vpc_id,
                resource_type="AWS::EC2::VPC",
                resource_name=label,
                region=region,
                account_id=account_id,
                issue="VPC Flow Logs are disabled",
                remediation="Enable VPC Flow Logs delivering REJECT or ALL traffic metadata to CloudWatch Logs or encrypted S3.",
                remediation_cli=(
                    f"aws ec2 create-flow-logs --region {region} --resource-type VPC "
                    f"--resource-ids {vpc_id} --traffic-type ALL --log-destination-type cloud-watch-logs"
                ),
                evidence={"is_default": bool(vpc.get("is_default", False))},
            )
        )
    return findings


def _check_ec2_imdsv2(snapshot: dict[str, Any]) -> list[Finding]:
    if "ec2_instances" not in snapshot:
        return []
    findings: list[Finding] = []
    account_id = str(snapshot.get("account_id", "unknown"))

    for inst in snapshot.get("ec2_instances", []):
        state = str(inst.get("state", "running")).lower()
        if state == "terminated":
            continue
        if inst.get("imdsv2_required", True):
            continue
        iid = str(inst.get("instance_id", "unknown"))
        name = str(inst.get("name", ""))
        region = default_region_for(snapshot, inst)
        label = f"{iid} ({name})" if name else iid
        has_public = bool(inst.get("public_ip"))
        findings.append(
            build_finding(
                "SEC-NET-005",
                severity="HIGH" if has_public else "MEDIUM",
                resource_id=iid,
                resource_type="AWS::EC2::Instance",
                resource_name=label,
                region=region,
                account_id=account_id,
                issue=(
                    f"IMDSv2 not enforced (HttpTokens=optional"
                    f"{', public IP attached' if has_public else ''})"
                ),
                remediation="Require IMDSv2 session tokens on the instance metadata options.",
                remediation_cli=(
                    f"aws ec2 modify-instance-metadata-options --region {region} "
                    f"--instance-id {iid} --http-tokens required --http-endpoint enabled"
                ),
                evidence={"public_ip": inst.get("public_ip"), "state": state},
            )
        )
    return findings


def _check_public_rds(snapshot: dict[str, Any]) -> list[Finding]:
    if "rds_instances" not in snapshot:
        return []
    findings: list[Finding] = []
    account_id = str(snapshot.get("account_id", "unknown"))

    for db in snapshot.get("rds_instances", []):
        if not db.get("publicly_accessible", False):
            continue
        db_id = str(db.get("db_instance_id", "unknown"))
        engine = str(db.get("engine", "database"))
        region = default_region_for(snapshot, db)
        findings.append(
            build_finding(
                "SEC-NET-006",
                resource_id=db_id,
                resource_type="AWS::RDS::DBInstance",
                resource_name=f"{db_id} ({engine})",
                region=region,
                account_id=account_id,
                issue=f"RDS {engine} instance has PubliclyAccessible enabled",
                remediation="Disable PubliclyAccessible and place the database in private subnets behind internal security groups.",
                remediation_cli=(
                    f"aws rds modify-db-instance --region {region} "
                    f"--db-instance-identifier {db_id} --no-publicly-accessible --apply-immediately"
                ),
                evidence={"engine": engine},
            )
        )
    return findings


def run_network_checks(snapshot: dict[str, Any], cfg: AuditConfig) -> list[Finding]:
    """Evaluate network, perimeter, VPC, EC2 metadata, and database exposure rules."""
    findings: list[Finding] = []
    findings.extend(_check_security_groups(snapshot, cfg))
    findings.extend(_check_vpc_flow_logs(snapshot))
    findings.extend(_check_ec2_imdsv2(snapshot))
    findings.extend(_check_public_rds(snapshot))
    return findings
