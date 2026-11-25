"""FinOps Cost Optimization Checks: EBS Waste, gp2->gp3, Snapshots, EIPs, NAT GW, ELB, EC2, Logs."""

from __future__ import annotations

from typing import Any

from aws_audit.checks.base import build_finding, default_region_for
from aws_audit.config import AuditConfig
from aws_audit.models import Finding


def _ebs_rate(vtype: str, cfg: AuditConfig) -> float:
    return float(cfg.ebs_monthly_rate_per_gb.get(vtype.lower(), cfg.default_ebs_rate_per_gb))


def run_cost_checks(snapshot: dict[str, Any], cfg: AuditConfig | None = None) -> list[Finding]:
    """Detect idle AWS resources and rightsizing opportunities with monthly USD savings estimates."""
    active_cfg = cfg or AuditConfig()
    findings: list[Finding] = []
    account_id = str(snapshot.get("account_id", "unknown"))

    # Pre-identify EBS volumes attached to long-stopped EC2 instances so we don't double-count
    # deletion savings (FIN-EC2-001) and gp2->gp3 migration savings (FIN-EBS-002) on the same volume.
    stopped_instance_vol_ids: set[str] = set()
    for inst in snapshot.get("ec2_instances", []):
        if (
            str(inst.get("state", "")).lower() == "stopped"
            and int(inst.get("stopped_days", 0)) > active_cfg.long_stopped_instance_days
        ):
            for av in inst.get("attached_volumes", []):
                if av.get("volume_id"):
                    stopped_instance_vol_ids.add(str(av["volume_id"]))

    # 1. EBS Volumes: Unattached waste (available) vs in-use gp2 -> gp3 migration
    for vol in snapshot.get("ebs_volumes", []):
        vid = str(vol.get("volume_id", "unknown"))
        region = default_region_for(snapshot, vol)
        state = str(vol.get("state", "")).lower()
        vtype = str(vol.get("volume_type", "gp3")).lower()
        size_gb = float(vol.get("size_gb", 0))
        rate = _ebs_rate(vtype, active_cfg)

        if state == "available":
            monthly_cost = round(size_gb * rate, 2)
            findings.append(
                build_finding(
                    "FIN-EBS-001",
                    severity="HIGH" if monthly_cost >= 50 else ("MEDIUM" if monthly_cost >= 10 else "LOW"),
                    resource_id=vid,
                    resource_type="AWS::EC2::Volume",
                    resource_name=f"EBS Volume: {vid}",
                    region=region,
                    account_id=account_id,
                    issue=f"Unattached {int(size_gb)} GB {vtype} volume (status: available)",
                    remediation="Create a final snapshot if retention is required, then delete the unattached EBS volume.",
                    remediation_cli=f"aws ec2 delete-volume --region {region} --volume-id {vid}",
                    monthly_savings_usd=monthly_cost,
                    evidence={"size_gb": size_gb, "volume_type": vtype},
                )
            )
        elif state == "in-use" and vtype == "gp2" and vid not in stopped_instance_vol_ids:
            gp3_rate = _ebs_rate("gp3", active_cfg)
            savings = round(max(0.0, size_gb * (rate - gp3_rate)), 2)
            if savings > 0:
                findings.append(
                    build_finding(
                        "FIN-EBS-002",
                        severity="MEDIUM" if savings >= 20 else "LOW",
                        resource_id=vid,
                        resource_type="AWS::EC2::Volume",
                        resource_name=f"EBS Volume: {vid}",
                        region=region,
                        account_id=account_id,
                        issue=f"Attached {int(size_gb)} GB legacy gp2 volume eligible for zero-downtime gp3 migration",
                        remediation="Modify volume type from gp2 to gp3 online to save ~20% on storage while gaining baseline 3,000 IOPS.",
                        remediation_cli=(
                            f"aws ec2 modify-volume --region {region} --volume-id {vid} --volume-type gp3"
                        ),
                        monthly_savings_usd=savings,
                        evidence={"size_gb": size_gb, "current_type": "gp2", "target_type": "gp3"},
                    )
                )

    # 2. Aged Unreferenced EBS Snapshots
    for snap in snapshot.get("ebs_snapshots", []):
        age_days = int(snap.get("age_days", 0))
        if age_days <= active_cfg.max_snapshot_age_days or snap.get("ami_referenced", False):
            continue
        snap_id = str(snap.get("snapshot_id", "unknown"))
        region = default_region_for(snapshot, snap)
        billable_gb = float(snap.get("stored_gb", snap.get("volume_size_gb", 0)))
        monthly_cost = round(billable_gb * active_cfg.ebs_snapshot_rate_per_gb, 2)
        findings.append(
            build_finding(
                "FIN-EBS-003",
                severity="MEDIUM" if monthly_cost >= 15 else "LOW",
                resource_id=snap_id,
                resource_type="AWS::EC2::Snapshot",
                resource_name=f"EBS Snapshot: {snap_id}",
                region=region,
                account_id=account_id,
                issue=(
                    f"Unreferenced EBS snapshot is {age_days} days old "
                    f"({int(billable_gb)} GB nominal size)"
                ),
                remediation="Verify retention/compliance need via AWS Backup or DLM lifecycle policies, then delete obsolete snapshots.",
                remediation_cli=f"aws ec2 delete-snapshot --region {region} --snapshot-id {snap_id}",
                monthly_savings_usd=monthly_cost,
                evidence={"age_days": age_days, "size_gb": billable_gb},
            )
        )

    # 3. Unassociated Elastic IPs
    for eip in snapshot.get("elastic_ips", []):
        if eip.get("associated", False):
            continue
        alloc_id = str(eip.get("allocation_id", ""))
        public_ip = str(eip.get("public_ip", ""))
        region = default_region_for(snapshot, eip)
        findings.append(
            build_finding(
                "FIN-NET-001",
                resource_id=alloc_id or public_ip,
                resource_type="AWS::EC2::EIP",
                resource_name=f"Elastic IP: {public_ip} ({alloc_id})",
                region=region,
                account_id=account_id,
                issue="Unassociated public IPv4 Elastic IP incurring hourly idle charge",
                remediation="Release unused Elastic IPv4 addresses not reserved for active DNS allowlisting.",
                remediation_cli=f"aws ec2 release-address --region {region} --allocation-id {alloc_id}",
                monthly_savings_usd=active_cfg.idle_elastic_ip_monthly_usd,
            )
        )

    # 4. Idle NAT Gateways
    for nat in snapshot.get("nat_gateways", []):
        if str(nat.get("state", "available")).lower() != "available":
            continue
        is_idle = bool(nat.get("idle", False)) or (
            "bytes_7d" in nat and int(nat.get("bytes_7d") or 0) == 0
        )
        if not is_idle:
            continue
        nat_id = str(nat.get("nat_gateway_id", "unknown"))
        region = default_region_for(snapshot, nat)
        findings.append(
            build_finding(
                "FIN-NET-002",
                resource_id=nat_id,
                resource_type="AWS::EC2::NatGateway",
                resource_name=f"NAT Gateway: {nat_id}",
                region=region,
                account_id=account_id,
                issue="Available NAT Gateway recorded zero traffic over 7-day lookback window",
                remediation="Verify VPC route tables do not depend on this NAT Gateway, then delete unused NAT Gateway.",
                remediation_cli=f"aws ec2 delete-nat-gateway --region {region} --nat-gateway-id {nat_id}",
                monthly_savings_usd=active_cfg.idle_nat_gateway_monthly_usd,
            )
        )

    # 5. Load Balancers with Zero Targets
    for lb in snapshot.get("load_balancers", []):
        if int(lb.get("target_count", 1)) > 0:
            continue
        lb_name = str(lb.get("name", "unknown"))
        lb_arn = str(lb.get("arn", lb_name))
        lb_type = str(lb.get("type", "application")).lower()
        region = default_region_for(snapshot, lb)
        rate = (
            active_cfg.idle_clb_monthly_usd
            if lb_type == "classic"
            else active_cfg.idle_alb_monthly_usd
        )
        findings.append(
            build_finding(
                "FIN-NET-003",
                resource_id=lb_arn,
                resource_type="AWS::ElasticLoadBalancingV2::LoadBalancer",
                resource_name=f"{lb_type.upper()} LB: {lb_name}",
                region=region,
                account_id=account_id,
                issue=f"{lb_type.upper()} load balancer has 0 registered targets",
                remediation="Confirm no DNS CNAME/Route53 records actively rely on the endpoint, then delete idle load balancer.",
                remediation_cli=f"aws elbv2 delete-load-balancer --region {region} --load-balancer-arn {lb_arn}",
                monthly_savings_usd=rate,
            )
        )

    # 6. Long-Stopped EC2 Instances Holding EBS Storage
    for inst in snapshot.get("ec2_instances", []):
        if str(inst.get("state", "")).lower() != "stopped":
            continue
        stopped_days = int(inst.get("stopped_days", 0))
        if stopped_days <= active_cfg.long_stopped_instance_days:
            continue
        iid = str(inst.get("instance_id", "unknown"))
        name = str(inst.get("name", ""))
        region = default_region_for(snapshot, inst)
        attached_vols = inst.get("attached_volumes", [])
        attached_cost = sum(
            float(v.get("size_gb", 0)) * _ebs_rate(str(v.get("volume_type", "gp3")), active_cfg)
            for v in attached_vols
        )
        attached_cost = round(attached_cost, 2)
        if attached_cost <= 0:
            continue
        label = f"{iid} ({name})" if name else iid
        findings.append(
            build_finding(
                "FIN-EC2-001",
                severity="MEDIUM" if attached_cost >= 15 else "LOW",
                resource_id=iid,
                resource_type="AWS::EC2::Instance",
                resource_name=label,
                region=region,
                account_id=account_id,
                issue=(
                    f"EC2 instance stopped for {stopped_days} days holding "
                    f"{len(attached_vols)} EBS volume(s)"
                ),
                remediation="Create an AMI/snapshot if archival is needed, then terminate the zombie instance and attached volumes.",
                remediation_cli=f"aws ec2 terminate-instances --region {region} --instance-ids {iid}",
                monthly_savings_usd=attached_cost,
                evidence={"stopped_days": stopped_days, "attached_volumes": len(attached_vols)},
            )
        )

    # 7. CloudWatch Log Groups with Infinite Retention and Material Storage Cost
    for lg in snapshot.get("log_groups", []):
        if lg.get("retention_days") is not None:
            continue
        stored_bytes = float(lg.get("stored_bytes", 0))
        stored_gb = stored_bytes / (1024 ** 3)
        monthly_cost = round(stored_gb * active_cfg.cloudwatch_logs_rate_per_gb, 2)
        if monthly_cost < 0.50:
            continue
        lg_name = str(lg.get("name", "unknown"))
        region = default_region_for(snapshot, lg)
        findings.append(
            build_finding(
                "FIN-LOG-001",
                resource_id=lg_name,
                resource_type="AWS::Logs::LogGroup",
                resource_name=f"Log Group: {lg_name}",
                region=region,
                account_id=account_id,
                issue=f"Unbounded log retention storing {stored_gb:.1f} GB (${monthly_cost:,.2f}/mo)",
                remediation="Apply a 30-90 day CloudWatch Logs retention policy or archive cold logs to S3 Glacier.",
                remediation_cli=(
                    f"aws logs put-retention-policy --region {region} "
                    f"--log-group-name '{lg_name}' --retention-in-days 90"
                ),
                monthly_savings_usd=monthly_cost,
                evidence={"stored_gb": round(stored_gb, 2)},
            )
        )

    return findings
