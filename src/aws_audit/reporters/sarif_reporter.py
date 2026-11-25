"""SARIF v2.1.0 report generator for GitHub Code Scanning and security platforms."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aws_audit import __version__
from aws_audit.checks.base import RULE_CATALOG
from aws_audit.models import AuditResult

_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

_SARIF_SECURITY_SCORE = {
    "CRITICAL": "9.5",
    "HIGH": "8.0",
    "MEDIUM": "5.5",
    "LOW": "3.0",
    "INFO": "1.0",
}


def build_sarif_payload(result: AuditResult) -> dict[str, Any]:
    """Convert AuditResult findings into a SARIF v2.1.0 compliant dictionary."""
    rules_in_use = sorted({f.rule_id for f in result.findings})
    rule_descriptors: list[dict[str, Any]] = []

    for rule_id in rules_in_use:
        spec = RULE_CATALOG.get(rule_id)
        if spec is None:
            continue
        rule_descriptors.append(
            {
                "id": spec.rule_id,
                "name": spec.title,
                "shortDescription": {"text": spec.title},
                "fullDescription": {"text": spec.description},
                "defaultConfiguration": {
                    "level": _SARIF_LEVEL.get(spec.default_severity, "warning")
                },
                "properties": {
                    "tags": [spec.category.lower(), *spec.compliance],
                    "security-severity": _SARIF_SECURITY_SCORE.get(spec.default_severity, "5.0"),
                },
            }
        )

    sarif_results: list[dict[str, Any]] = []
    for f in result.findings:
        msg = f"[{f.severity}] {f.resource_name} ({f.region}): {f.issue} Remediation: {f.remediation}"
        if f.monthly_savings_usd > 0:
            msg += f" Est. savings: ${f.monthly_savings_usd:,.2f}/mo."
        sarif_results.append(
            {
                "ruleId": f.rule_id,
                "level": _SARIF_LEVEL.get(f.severity, "warning"),
                "message": {"text": msg},
                "locations": [
                    {
                        "logicalLocations": [
                            {
                                "name": f.resource_id,
                                "fullyQualifiedName": f"aws://{f.account_id}/{f.region}/{f.resource_type}/{f.resource_id}",
                                "kind": f.resource_type,
                            }
                        ]
                    }
                ],
                "properties": {
                    "category": f.category,
                    "severity": f.severity,
                    "region": f.region,
                    "account_id": f.account_id,
                    "monthly_savings_usd": f.monthly_savings_usd,
                    "compliance": f.compliance,
                },
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "aws-security-cost-audit-reporter",
                        "version": __version__,
                        "informationUri": "https://github.com/aws-security-cost-audit-reporter",
                        "rules": rule_descriptors,
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def write_sarif_report(filepath: Path, result: AuditResult) -> str:
    """Write SARIF v2.1.0 output to `filepath`."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(build_sarif_payload(result), indent=2) + "\n"
    filepath.write_text(payload, encoding="utf-8")
    return payload
