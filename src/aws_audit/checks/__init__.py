"""Rule registry and unified runner for security and FinOps audit checks."""

from __future__ import annotations

from typing import Any

from aws_audit.checks.cost_checks import run_cost_checks
from aws_audit.checks.security_iam import run_iam_checks
from aws_audit.checks.security_network import run_network_checks
from aws_audit.checks.security_storage_logging import run_storage_logging_checks
from aws_audit.config import AuditConfig
from aws_audit.models import Finding


def run_security_checks(snapshot: dict[str, Any], cfg: AuditConfig | None = None) -> list[Finding]:
    """Run all network, IAM, storage, database, and logging security checks."""
    active_cfg = cfg or AuditConfig()
    findings: list[Finding] = []
    findings.extend(run_network_checks(snapshot, active_cfg))
    findings.extend(run_iam_checks(snapshot, active_cfg))
    findings.extend(run_storage_logging_checks(snapshot, active_cfg))
    if active_cfg.disabled_rules:
        findings = [f for f in findings if f.rule_id not in active_cfg.disabled_rules]
    return findings


def run_finops_checks(snapshot: dict[str, Any], cfg: AuditConfig | None = None) -> list[Finding]:
    """Run all FinOps cost optimization checks."""
    active_cfg = cfg or AuditConfig()
    findings = run_cost_checks(snapshot, active_cfg)
    if active_cfg.disabled_rules:
        findings = [f for f in findings if f.rule_id not in active_cfg.disabled_rules]
    return findings


def run_all_checks(
    snapshot: dict[str, Any],
    cfg: AuditConfig | None = None,
    include_security: bool = True,
    include_cost: bool = True,
) -> list[Finding]:
    """Run enabled security and/or FinOps check suites against a normalized snapshot."""
    active_cfg = cfg or AuditConfig()
    findings: list[Finding] = []
    if include_security:
        findings.extend(run_security_checks(snapshot, active_cfg))
    if include_cost:
        findings.extend(run_finops_checks(snapshot, active_cfg))
    return findings


__all__ = [
    "run_all_checks",
    "run_cost_checks",
    "run_finops_checks",
    "run_iam_checks",
    "run_network_checks",
    "run_security_checks",
    "run_storage_logging_checks",
]
