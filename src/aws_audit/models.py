"""Typed domain models for AWS Security & FinOps audit snapshots, findings, and reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Normalized finding severity levels ordered from highest to lowest impact."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_ORDER: dict[str, int] = {
    Severity.CRITICAL.value: 0,
    Severity.HIGH.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 3,
    Severity.INFO.value: 4,
}


class Category(str, Enum):
    """Audit finding categories."""

    SECURITY = "Security"
    COST = "Cost"


@dataclass(slots=True)
class Finding:
    """Single security misconfiguration or FinOps cost optimization finding."""

    rule_id: str
    category: str
    severity: str
    title: str
    resource_id: str
    resource_type: str
    resource_name: str
    region: str
    account_id: str
    issue: str
    remediation: str
    remediation_cli: str = ""
    monthly_savings_usd: float = 0.0
    compliance: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    suppressed: bool = False
    suppression_reason: str = ""

    @property
    def annual_savings_usd(self) -> float:
        """Return annualized estimated savings in USD."""
        return round(float(self.monthly_savings_usd) * 12.0, 2)

    @property
    def status(self) -> str:
        """Return human-readable lifecycle status of the finding."""
        return "SUPPRESSED" if self.suppressed else "OPEN"

    def to_dict(self) -> dict[str, Any]:
        """Serialize finding to a JSON-friendly dictionary."""
        data = asdict(self)
        data["annual_savings_usd"] = self.annual_savings_usd
        data["status"] = self.status
        return data


@dataclass(slots=True)
class CollectionWarning:
    """Non-fatal collection warning (e.g., AccessDenied on an optional AWS service)."""

    service: str
    region: str
    error_code: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AuditSummary:
    """Aggregated executive KPIs for an audit run."""

    account_id: str
    account_alias: str
    regions: list[str]
    collected_at: str
    collector_mode: str
    security_score: int
    security_grade: str
    total_findings: int
    suppressed_count: int
    severity_counts: dict[str, int]
    category_counts: dict[str, int]
    total_monthly_savings_usd: float
    total_annual_savings_usd: float
    compliance_summary: dict[str, int]
    resources_scanned: dict[str, int]
    warnings_count: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AuditResult:
    """Complete audit report bundle produced by the evaluation engine."""

    schema_version: str
    summary: AuditSummary
    findings: list[Finding]
    suppressed_findings: list[Finding] = field(default_factory=list)
    warnings: list[CollectionWarning] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "summary": self.summary.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "suppressed_findings": [f.to_dict() for f in self.suppressed_findings],
            "warnings": [w.to_dict() for w in self.warnings],
        }
