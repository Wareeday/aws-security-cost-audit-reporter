"""Formula-injection-safe CSV audit tracker generator."""

from __future__ import annotations

import csv
from pathlib import Path

from aws_audit.models import AuditResult

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _safe_csv_cell(value: object) -> str:
    text = str(value)
    if text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


def write_csv_report(filepath: Path, result: AuditResult, *, include_suppressed: bool = True) -> None:
    """Write audit findings to an Excel-safe CSV tracker."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "rule_id",
        "status",
        "category",
        "severity",
        "region",
        "resource_type",
        "resource_id",
        "resource_name",
        "title",
        "issue",
        "monthly_savings_usd",
        "annual_savings_usd",
        "compliance",
        "remediation",
        "remediation_cli",
        "suppression_reason",
    ]

    items = list(result.findings)
    if include_suppressed:
        items.extend(result.suppressed_findings)

    with filepath.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for f in items:
            writer.writerow(
                {
                    "rule_id": _safe_csv_cell(f.rule_id),
                    "status": _safe_csv_cell(f.status),
                    "category": _safe_csv_cell(f.category),
                    "severity": _safe_csv_cell(f.severity),
                    "region": _safe_csv_cell(f.region),
                    "resource_type": _safe_csv_cell(f.resource_type),
                    "resource_id": _safe_csv_cell(f.resource_id),
                    "resource_name": _safe_csv_cell(f.resource_name),
                    "title": _safe_csv_cell(f.title),
                    "issue": _safe_csv_cell(f.issue),
                    "monthly_savings_usd": f"{f.monthly_savings_usd:.2f}",
                    "annual_savings_usd": f"{f.annual_savings_usd:.2f}",
                    "compliance": _safe_csv_cell("; ".join(f.compliance)),
                    "remediation": _safe_csv_cell(f.remediation),
                    "remediation_cli": _safe_csv_cell(f.remediation_cli),
                    "suppression_reason": _safe_csv_cell(f.suppression_reason),
                }
            )
