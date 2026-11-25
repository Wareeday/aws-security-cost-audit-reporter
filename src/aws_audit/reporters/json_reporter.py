"""Structured JSON audit report writer for SIEM, SOAR, and CI/CD pipelines."""

from __future__ import annotations

import json
from pathlib import Path

from aws_audit.models import AuditResult


def write_json_report(filepath: Path, result: AuditResult) -> str:
    """Serialize AuditResult to formatted JSON."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(result.to_dict(), indent=2) + "\n"
    filepath.write_text(payload, encoding="utf-8")
    return payload
