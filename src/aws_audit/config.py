"""Configuration, pricing tables, compliance thresholds, and suppression waiver engine."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from aws_audit.models import Finding

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_DATA_DIR = PROJECT_ROOT / "sample_data"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "output"
DEFAULT_DEMO_SNAPSHOT = SAMPLE_DATA_DIR / "mock_aws_snapshot.json"

DEFAULT_SENSITIVE_PORTS: dict[int, tuple[str, str]] = {
    22: ("SSH", "CRITICAL"),
    3389: ("RDP", "CRITICAL"),
    2375: ("Docker Daemon (Unencrypted)", "CRITICAL"),
    3306: ("MySQL", "HIGH"),
    5432: ("PostgreSQL", "HIGH"),
    1433: ("MSSQL", "HIGH"),
    6379: ("Redis", "HIGH"),
    27017: ("MongoDB", "HIGH"),
    9200: ("Elasticsearch", "HIGH"),
    11211: ("Memcached", "HIGH"),
    5900: ("VNC", "HIGH"),
}

DEFAULT_EBS_MONTHLY_RATE_PER_GB: dict[str, float] = {
    "gp3": 0.08,
    "gp2": 0.10,
    "io1": 0.125,
    "io2": 0.125,
    "st1": 0.045,
    "sc1": 0.015,
    "standard": 0.05,
}

ADMIN_POLICY_NAMES: frozenset[str] = frozenset(
    {
        "AdministratorAccess",
        "PowerUserAccess",
        "IAMFullAccess",
    }
)


@dataclass(slots=True)
class SuppressionRule:
    """Suppression / risk-acceptance waiver targeting a rule and resource pattern."""

    rule_id: str
    resource_pattern: str
    reason: str
    expires_at: str | None = None
    region: str | None = None

    def is_expired(self, today: date | None = None) -> bool:
        """Return True if the waiver has an expiry date strictly before today."""
        if not self.expires_at:
            return False
        ref_date = today or date.today()
        expiry = date.fromisoformat(self.expires_at)
        return expiry < ref_date

    def matches(self, finding: Finding, today: date | None = None) -> bool:
        """Return True if this active waiver matches the given finding."""
        if self.is_expired(today=today):
            return False
        if self.rule_id != "*" and self.rule_id != finding.rule_id:
            return False
        if self.region and self.region != "*" and self.region != finding.region:
            return False
        pattern = re.compile(self.resource_pattern)
        return bool(pattern.search(finding.resource_id) or pattern.search(finding.resource_name))


@dataclass(slots=True)
class AuditConfig:
    """Centralized configuration for security thresholds, FinOps rates, and waivers."""

    default_region: str = "us-east-1"
    max_access_key_age_days: int = 90
    critical_access_key_age_days: int = 180
    unused_access_key_days: int = 90
    min_password_length: int = 14
    max_password_age_days: int = 90
    max_snapshot_age_days: int = 90
    long_stopped_instance_days: int = 30
    sensitive_ports: dict[int, tuple[str, str]] = field(
        default_factory=lambda: dict(DEFAULT_SENSITIVE_PORTS)
    )
    ebs_monthly_rate_per_gb: dict[str, float] = field(
        default_factory=lambda: dict(DEFAULT_EBS_MONTHLY_RATE_PER_GB)
    )
    default_ebs_rate_per_gb: float = 0.08
    ebs_snapshot_rate_per_gb: float = 0.05
    idle_elastic_ip_monthly_usd: float = 3.65
    idle_nat_gateway_monthly_usd: float = 32.85
    idle_alb_monthly_usd: float = 16.43
    idle_clb_monthly_usd: float = 18.25
    cloudwatch_logs_rate_per_gb: float = 0.03
    max_workers: int = 8
    disabled_rules: set[str] = field(default_factory=set)
    suppressions: list[SuppressionRule] = field(default_factory=list)


def _load_structured_file(filepath: Path) -> dict[str, Any]:
    """Load a JSON or YAML file into a dictionary."""
    if not filepath.exists():
        raise FileNotFoundError(f"Configuration file not found: {filepath}")

    raw = filepath.read_text(encoding="utf-8")
    suffix = filepath.suffix.lower()

    if suffix == ".json":
        data = json.loads(raw)
    elif suffix in {".yaml", ".yml"}:
        try:
            import yaml
        except ImportError as exc:
            raise RuntimeError(
                "PyYAML is required to load .yaml/.yml config files. "
                "Install it with `pip install PyYAML` or use JSON format."
            ) from exc
        data = yaml.safe_load(raw) or {}
    else:
        # Fallback: try JSON first, then YAML if available
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            import yaml

            data = yaml.safe_load(raw) or {}

    if not isinstance(data, dict):
        raise ValueError(f"Expected a top-level mapping/object in {filepath}")
    return data


def load_suppressions_file(filepath: Path) -> list[SuppressionRule]:
    """Parse waiver/suppression entries from a JSON or YAML file."""
    data = _load_structured_file(filepath)
    raw_items = data.get("suppressions", data.get("waivers", []))
    rules: list[SuppressionRule] = []
    for item in raw_items:
        rules.append(
            SuppressionRule(
                rule_id=str(item["rule_id"]),
                resource_pattern=str(item["resource_pattern"]),
                reason=str(item.get("reason", "Risk accepted via waiver policy")),
                expires_at=item.get("expires_at"),
                region=item.get("region"),
            )
        )
    return rules


def load_config(
    config_path: Path | None = None,
    waivers_path: Path | None = None,
) -> AuditConfig:
    """Build AuditConfig from defaults merged with optional policy and waiver files."""
    cfg = AuditConfig()

    if config_path is not None:
        data = _load_structured_file(config_path)
        thresholds = data.get("thresholds", data)
        scalar_fields = (
            "default_region",
            "max_access_key_age_days",
            "critical_access_key_age_days",
            "unused_access_key_days",
            "min_password_length",
            "max_password_age_days",
            "max_snapshot_age_days",
            "long_stopped_instance_days",
            "default_ebs_rate_per_gb",
            "ebs_snapshot_rate_per_gb",
            "idle_elastic_ip_monthly_usd",
            "idle_nat_gateway_monthly_usd",
            "idle_alb_monthly_usd",
            "idle_clb_monthly_usd",
            "cloudwatch_logs_rate_per_gb",
            "max_workers",
        )
        for field_name in scalar_fields:
            if field_name in thresholds:
                setattr(cfg, field_name, thresholds[field_name])

        if "sensitive_ports" in data:
            parsed_ports: dict[int, tuple[str, str]] = {}
            for port_key, spec in data["sensitive_ports"].items():
                if isinstance(spec, (list, tuple)) and len(spec) >= 2:
                    parsed_ports[int(port_key)] = (str(spec[0]), str(spec[1]).upper())
                elif isinstance(spec, dict):
                    parsed_ports[int(port_key)] = (
                        str(spec.get("service", f"Port {port_key}")),
                        str(spec.get("severity", "HIGH")).upper(),
                    )
            cfg.sensitive_ports.update(parsed_ports)

        if "ebs_monthly_rate_per_gb" in data:
            for vol_type, rate in data["ebs_monthly_rate_per_gb"].items():
                cfg.ebs_monthly_rate_per_gb[str(vol_type).lower()] = float(rate)

        if "disabled_rules" in data:
            cfg.disabled_rules = {str(r) for r in data["disabled_rules"]}

        if "suppressions" in data or "waivers" in data:
            raw_items = data.get("suppressions", data.get("waivers", []))
            for item in raw_items:
                cfg.suppressions.append(
                    SuppressionRule(
                        rule_id=str(item["rule_id"]),
                        resource_pattern=str(item["resource_pattern"]),
                        reason=str(item.get("reason", "Risk accepted via policy config")),
                        expires_at=item.get("expires_at"),
                        region=item.get("region"),
                    )
                )

    if waivers_path is not None:
        cfg.suppressions.extend(load_suppressions_file(waivers_path))

    return cfg


def apply_suppressions(
    findings: list[Finding],
    suppressions: list[SuppressionRule],
    today: date | None = None,
) -> tuple[list[Finding], list[Finding]]:
    """Partition findings into active and suppressed lists according to active waivers."""
    if not suppressions:
        return list(findings), []

    active: list[Finding] = []
    suppressed: list[Finding] = []

    for finding in findings:
        matched_rule = next((rule for rule in suppressions if rule.matches(finding, today=today)), None)
        if matched_rule is not None:
            finding.suppressed = True
            finding.suppression_reason = matched_rule.reason
            if matched_rule.expires_at:
                finding.suppression_reason += f" (expires {matched_rule.expires_at})"
            suppressed.append(finding)
        else:
            active.append(finding)

    return active, suppressed
