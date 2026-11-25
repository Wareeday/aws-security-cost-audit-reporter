"""Posture scoring, compliance aggregation, sorting, and audit evaluation pipeline."""

from __future__ import annotations

from collections import Counter
from datetime import date
from typing import Any

from aws_audit.checks import run_all_checks
from aws_audit.config import AuditConfig, apply_suppressions
from aws_audit.models import (
    SEVERITY_ORDER,
    AuditResult,
    AuditSummary,
    Category,
    CollectionWarning,
    Finding,
    Severity,
)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Order findings by severity (CRITICAL first), highest monthly savings, then rule ID."""
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 9),
            -float(f.monthly_savings_usd),
            f.rule_id,
            f.resource_id,
        ),
    )


def compute_security_score(security_findings: list[Finding]) -> tuple[int, str]:
    """Compute a monotonic 0-100 Security Posture Score and letter grade (A-F).

    Uses severity-weighted multiplicative risk decay across open Security findings:
      CRITICAL factor = 0.80, HIGH = 0.89, MEDIUM = 0.96, LOW = 0.99.
    Every remediated finding measurably improves the score without saturating early at 0.
    """
    active_sec = [
        f for f in security_findings if f.category == Category.SECURITY.value and not f.suppressed
    ]
    crit = sum(1 for f in active_sec if f.severity == Severity.CRITICAL.value)
    high = sum(1 for f in active_sec if f.severity == Severity.HIGH.value)
    med = sum(1 for f in active_sec if f.severity == Severity.MEDIUM.value)
    low = sum(1 for f in active_sec if f.severity == Severity.LOW.value)

    raw_score = 100.0 * (0.80 ** crit) * (0.89 ** high) * (0.96 ** med) * (0.99 ** low)
    score = max(0, min(100, round(raw_score)))
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 55:
        grade = "D"
    else:
        grade = "F"
    return score, grade


def meets_severity_threshold(severity: str, threshold: str) -> bool:
    """Return True if `severity` is at least as severe as `threshold`."""
    return SEVERITY_ORDER.get(severity.upper(), 9) <= SEVERITY_ORDER.get(threshold.upper(), 9)


def evaluate_snapshot(
    snapshot: dict[str, Any],
    cfg: AuditConfig | None = None,
    *,
    include_security: bool = True,
    include_cost: bool = True,
    min_severity: str = Severity.LOW.value,
    today: date | None = None,
) -> AuditResult:
    """Evaluate an AWS snapshot against enabled checks, waivers, and posture scoring."""
    active_cfg = cfg or AuditConfig()
    raw_findings = run_all_checks(
        snapshot,
        active_cfg,
        include_security=include_security,
        include_cost=include_cost,
    )
    active_findings, suppressed_findings = apply_suppressions(
        raw_findings, active_cfg.suppressions, today=today
    )

    min_sev = min_severity.upper()
    filtered_active = sort_findings(
        [f for f in active_findings if meets_severity_threshold(f.severity, min_sev)]
    )
    ordered_suppressed = sort_findings(suppressed_findings)

    score, grade = compute_security_score(filtered_active)
    sev_counts = {
        sev: sum(1 for f in filtered_active if f.severity == sev)
        for sev in (
            Severity.CRITICAL.value,
            Severity.HIGH.value,
            Severity.MEDIUM.value,
            Severity.LOW.value,
        )
    }
    cat_counts = {
        Category.SECURITY.value: sum(
            1 for f in filtered_active if f.category == Category.SECURITY.value
        ),
        Category.COST.value: sum(1 for f in filtered_active if f.category == Category.COST.value),
    }

    total_monthly = round(sum(float(f.monthly_savings_usd) for f in filtered_active), 2)
    total_annual = round(total_monthly * 12.0, 2)

    compliance_counter: Counter[str] = Counter()
    for finding in filtered_active:
        for ctrl in finding.compliance:
            framework = ctrl.split(":", 1)[0]
            compliance_counter[framework] += 1

    resource_keys = (
        "security_groups",
        "iam_users",
        "s3_buckets",
        "ebs_volumes",
        "ebs_snapshots",
        "elastic_ips",
        "ec2_instances",
        "vpcs",
        "nat_gateways",
        "load_balancers",
        "rds_instances",
        "cloudtrail_trails",
        "log_groups",
    )
    resources_scanned = {
        key: len(snapshot.get(key, []))
        for key in resource_keys
        if key in snapshot
    }

    warnings = [
        CollectionWarning(
            service=str(w.get("service", "")),
            region=str(w.get("region", "")),
            error_code=str(w.get("error_code", "")),
            message=str(w.get("message", "")),
        )
        for w in snapshot.get("collection_warnings", [])
        if isinstance(w, dict)
    ]

    summary = AuditSummary(
        account_id=str(snapshot.get("account_id", "unknown")),
        account_alias=str(snapshot.get("account_alias", "")),
        regions=[str(r) for r in snapshot.get("regions", ["us-east-1"])],
        collected_at=str(snapshot.get("collected_at", "")),
        collector_mode=str(snapshot.get("collector_mode", "snapshot")),
        security_score=score,
        security_grade=grade,
        total_findings=len(filtered_active),
        suppressed_count=len(ordered_suppressed),
        severity_counts=sev_counts,
        category_counts=cat_counts,
        total_monthly_savings_usd=total_monthly,
        total_annual_savings_usd=total_annual,
        compliance_summary=dict(sorted(compliance_counter.items())),
        resources_scanned=resources_scanned,
        warnings_count=len(warnings),
    )

    return AuditResult(
        schema_version="2.0",
        summary=summary,
        findings=filtered_active,
        suppressed_findings=ordered_suppressed,
        warnings=warnings,
    )
