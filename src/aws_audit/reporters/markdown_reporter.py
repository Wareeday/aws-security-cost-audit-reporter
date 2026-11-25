"""Executive Markdown audit report generator."""

from __future__ import annotations

from pathlib import Path

from aws_audit.models import AuditResult


def _md_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def write_markdown_report(filepath: Path, result: AuditResult) -> str:
    """Render an executive Markdown report and write it to `filepath`."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    s = result.summary
    account_display = f"{s.account_id} ({s.account_alias})" if s.account_alias else s.account_id
    regions_display = ", ".join(s.regions)

    lines: list[str] = [
        "# AWS Security Posture & FinOps Audit Report",
        "",
        "## Executive Summary",
        "",
        f"- **AWS Account:** `{account_display}`",
        f"- **Regions Scanned:** `{regions_display}`",
        f"- **Collection Mode:** `{s.collector_mode}`",
        f"- **Audit Timestamp:** `{s.collected_at}`",
        f"- **Security Posture Score:** **{s.security_score}/100 (Grade {s.security_grade})**",
        (
            f"- **Open Findings:** **{s.total_findings}** "
            f"(CRITICAL: {s.severity_counts['CRITICAL']} | "
            f"HIGH: {s.severity_counts['HIGH']} | "
            f"MEDIUM: {s.severity_counts['MEDIUM']} | "
            f"LOW: {s.severity_counts['LOW']})"
        ),
        f"- **Suppressed (Waived) Findings:** {s.suppressed_count}",
        (
            f"- **Estimated Cost Optimization Potential:** "
            f"**${s.total_monthly_savings_usd:,.2f}/mo** "
            f"(${s.total_annual_savings_usd:,.2f}/yr)"
        ),
        "",
    ]

    if s.compliance_summary:
        lines.extend(
            [
                "## Compliance & Framework Impact",
                "",
                "| Framework / Tag | Open Findings |",
                "| :--- | ---: |",
            ]
        )
        for framework, count in s.compliance_summary.items():
            lines.append(f"| `{_md_cell(framework)}` | {count} |")
        lines.append("")

    if result.findings:
        lines.extend(
            [
                "## Prioritized Findings & Remediation Plan",
                "",
                "| Rule ID | Severity | Category | Region | Resource | Issue | Est. Monthly Savings | Recommended Action |",
                "| :--- | :---: | :--- | :--- | :--- | :--- | ---: | :--- |",
            ]
        )
        for f in result.findings:
            savings_str = f"${f.monthly_savings_usd:,.2f}" if f.monthly_savings_usd > 0 else "—"
            lines.append(
                f"| `{_md_cell(f.rule_id)}` | **{_md_cell(f.severity)}** | {_md_cell(f.category)} | "
                f"`{_md_cell(f.region)}` | `{_md_cell(f.resource_name)}` | {_md_cell(f.issue)} | "
                f"{savings_str} | {_md_cell(f.remediation)} |"
            )
        lines.append("")

        cli_items = [f for f in result.findings if f.remediation_cli]
        if cli_items:
            lines.extend(["## Remediation AWS CLI Quick Reference", ""])
            for f in cli_items:
                lines.append(f"- **`{f.rule_id}`** (`{f.resource_id}`): `{f.remediation_cli}`")
            lines.append("")
    else:
        lines.extend(
            [
                "## Prioritized Findings & Remediation Plan",
                "",
                "No open findings matched the active policy thresholds.",
                "",
            ]
        )

    if result.suppressed_findings:
        lines.extend(
            [
                "## Suppressed Findings (Active Waivers)",
                "",
                "| Rule ID | Severity | Resource | Waiver Reason |",
                "| :--- | :---: | :--- | :--- |",
            ]
        )
        for f in result.suppressed_findings:
            lines.append(
                f"| `{_md_cell(f.rule_id)}` | {_md_cell(f.severity)} | "
                f"`{_md_cell(f.resource_name)}` | {_md_cell(f.suppression_reason)} |"
            )
        lines.append("")

    if result.warnings:
        lines.extend(
            [
                "## Collector Coverage Warnings",
                "",
                "| Service | Region | Error Code | Details |",
                "| :--- | :--- | :--- | :--- |",
            ]
        )
        for w in result.warnings:
            lines.append(
                f"| `{_md_cell(w.service)}` | `{_md_cell(w.region)}` | "
                f"`{_md_cell(w.error_code)}` | {_md_cell(w.message)} |"
            )
        lines.append("")

    content = "\n".join(lines)
    filepath.write_text(content, encoding="utf-8")
    return content
