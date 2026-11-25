"""Interactive, print-ready, XSS-safe self-contained HTML audit dashboard."""

from __future__ import annotations

import html
from pathlib import Path

from aws_audit.models import AuditResult

_SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#d97706",
    "LOW": "#2563eb",
    "INFO": "#4b5563",
}

_GRADE_COLORS = {
    "A": "#15803d",
    "B": "#0284c7",
    "C": "#d97706",
    "D": "#ea580c",
    "F": "#dc2626",
}


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def write_html_report(filepath: Path, result: AuditResult) -> str:
    """Render a self-contained interactive HTML report with strict output escaping."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    s = result.summary
    account_label = f"{s.account_id} ({s.account_alias})" if s.account_alias else s.account_id
    regions_str = ", ".join(s.regions)
    grade_color = _GRADE_COLORS.get(s.security_grade, "#374151")

    region_options = sorted({f.region for f in result.findings})
    region_select_html = "".join(
        f'<option value="{_esc(r)}">{_esc(r)}</option>' for r in region_options
    )

    rows_html: list[str] = []
    for f in result.findings:
        sev_color = _SEVERITY_COLORS.get(f.severity, "#4b5563")
        savings_str = f"${f.monthly_savings_usd:,.2f}" if f.monthly_savings_usd > 0 else "—"
        comp_badges = " ".join(
            f'<span class="tag">{_esc(c)}</span>' for c in f.compliance
        )
        cli_block = (
            f'<div class="cli-box"><code>{_esc(f.remediation_cli)}</code></div>'
            if f.remediation_cli
            else ""
        )
        rows_html.append(
            f'<tr class="finding-row" '
            f'data-severity="{_esc(f.severity)}" '
            f'data-category="{_esc(f.category)}" '
            f'data-region="{_esc(f.region)}">'
            f'<td><span class="badge" style="background:{sev_color}">{_esc(f.severity)}</span>'
            f'<div class="rule-id">{_esc(f.rule_id)}</div></td>'
            f'<td>{_esc(f.category)}</td>'
            f'<td><code>{_esc(f.region)}</code></td>'
            f'<td><div class="res-name"><code>{_esc(f.resource_name)}</code></div>'
            f'<div class="res-type">{_esc(f.resource_type)}</div></td>'
            f'<td><div class="finding-title">{_esc(f.title)}</div>'
            f'<div class="finding-issue">{_esc(f.issue)}</div>{comp_badges}</td>'
            f'<td class="num">{_esc(savings_str)}</td>'
            f'<td><div>{_esc(f.remediation)}</div>{cli_block}</td>'
            f"</tr>"
        )

    suppressed_section = ""
    if result.suppressed_findings:
        sup_rows = "".join(
            f"<tr><td><code>{_esc(f.rule_id)}</code></td>"
            f"<td>{_esc(f.severity)}</td>"
            f"<td><code>{_esc(f.resource_name)}</code></td>"
            f"<td>{_esc(f.suppression_reason)}</td></tr>"
            for f in result.suppressed_findings
        )
        suppressed_section = f"""
        <details class="panel">
          <summary>Suppressed Findings ({len(result.suppressed_findings)})</summary>
          <table>
            <thead><tr><th>Rule ID</th><th>Severity</th><th>Resource</th><th>Waiver Reason</th></tr></thead>
            <tbody>{sup_rows}</tbody>
          </table>
        </details>
        """

    warnings_section = ""
    if result.warnings:
        warn_rows = "".join(
            f"<tr><td><code>{_esc(w.service)}</code></td>"
            f"<td><code>{_esc(w.region)}</code></td>"
            f"<td><code>{_esc(w.error_code)}</code></td>"
            f"<td>{_esc(w.message)}</td></tr>"
            for w in result.warnings
        )
        warnings_section = f"""
        <details class="panel warning-panel">
          <summary>Collector Coverage Warnings ({len(result.warnings)})</summary>
          <table>
            <thead><tr><th>Service</th><th>Region</th><th>Code</th><th>Message</th></tr></thead>
            <tbody>{warn_rows}</tbody>
          </table>
        </details>
        """

    empty_notice = (
        ""
        if result.findings
        else '<div class="empty-state">No open findings matched the active policy thresholds.</div>'
    )

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>AWS Security Posture &amp; FinOps Audit Report</title>
<style>
  :root {{
    --bg: #f8fafc;
    --surface: #ffffff;
    --border: #e2e8f0;
    --text: #0f172a;
    --muted: #475569;
    --accent: #0f172a;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    margin: 0;
    padding: 28px 20px 56px;
    line-height: 1.45;
  }}
  .container {{ max-width: 1280px; margin: 0 auto; }}
  .header {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 22px 24px;
    margin-bottom: 18px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 16px;
    flex-wrap: wrap;
  }}
  h1 {{ margin: 0 0 8px; font-size: 1.55rem; }}
  .meta {{ color: var(--muted); font-size: 0.9rem; display: flex; flex-wrap: wrap; gap: 14px; }}
  .score-box {{
    text-align: center;
    border: 2px solid {grade_color};
    border-radius: 12px;
    padding: 10px 18px;
    min-width: 150px;
    background: #fff;
  }}
  .score-label {{ font-size: 0.72rem; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); font-weight: 600; }}
  .score-val {{ font-size: 1.65rem; font-weight: 800; color: {grade_color}; }}
  .kpis {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(195px, 1fr));
    gap: 12px;
    margin-bottom: 18px;
  }}
  .kpi {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 14px 16px;
  }}
  .kpi-label {{ font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; font-weight: 600; }}
  .kpi-value {{ font-size: 1.45rem; font-weight: 700; margin-top: 4px; }}
  .kpi-sub {{ font-size: 0.8rem; color: var(--muted); margin-top: 3px; }}
  .toolbar {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 12px 16px;
    margin-bottom: 14px;
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    align-items: center;
  }}
  .toolbar input, .toolbar select {{
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    padding: 7px 10px;
    font-size: 0.88rem;
    background: #fff;
  }}
  .toolbar input {{ flex: 1 1 260px; }}
  .count-pill {{ margin-left: auto; font-size: 0.84rem; color: var(--muted); font-weight: 600; }}
  .table-wrap {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow-x: auto;
  }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
  th, td {{ border-bottom: 1px solid var(--border); padding: 11px 10px; text-align: left; vertical-align: top; }}
  th {{ background: #f1f5f9; font-size: 0.78rem; text-transform: uppercase; letter-spacing: .04em; color: #334155; }}
  .num {{ text-align: right; white-space: nowrap; font-weight: 600; }}
  .badge {{ color: #fff; padding: 3px 8px; border-radius: 5px; font-weight: 700; font-size: 0.74rem; display: inline-block; }}
  .rule-id {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.75rem; color: var(--muted); margin-top: 4px; }}
  .res-type {{ font-size: 0.74rem; color: var(--muted); margin-top: 3px; }}
  .finding-title {{ font-weight: 600; margin-bottom: 3px; }}
  .finding-issue {{ color: #334155; margin-bottom: 5px; }}
  .tag {{
    display: inline-block;
    background: #eff6ff;
    color: #1d4ed8;
    border: 1px solid #bfdbfe;
    border-radius: 4px;
    font-size: 0.7rem;
    padding: 1px 6px;
    margin: 2px 4px 0 0;
  }}
  code {{ background: #f1f5f9; padding: 2px 5px; border-radius: 4px; font-size: 0.84em; word-break: break-word; }}
  .cli-box {{ margin-top: 6px; }}
  .cli-box code {{ display: block; padding: 6px 8px; background: #0f172a; color: #e2e8f0; font-size: 0.76rem; border-radius: 6px; }}
  .panel {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 12px 16px;
    margin-top: 16px;
  }}
  .panel summary {{ cursor: pointer; font-weight: 600; }}
  .warning-panel {{ border-color: #fde68a; background: #fffbeb; }}
  .empty-state {{ padding: 28px; text-align: center; color: #15803d; font-weight: 600; }}
  @media print {{
    body {{ background: #fff; padding: 0; }}
    .toolbar {{ display: none; }}
    .header, .kpi, .table-wrap, .panel {{ break-inside: avoid; }}
  }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1>AWS Security Posture &amp; FinOps Audit Report</h1>
      <div class="meta">
        <span><strong>Account:</strong> <code>{_esc(account_label)}</code></span>
        <span><strong>Regions:</strong> <code>{_esc(regions_str)}</code></span>
        <span><strong>Mode:</strong> <code>{_esc(s.collector_mode)}</code></span>
        <span><strong>Collected:</strong> <code>{_esc(s.collected_at)}</code></span>
      </div>
    </div>
    <div class="score-box">
      <div class="score-label">Security Score</div>
      <div class="score-val">{s.security_score}/100 ({_esc(s.security_grade)})</div>
    </div>
  </div>

  <div class="kpis">
    <div class="kpi">
      <div class="kpi-label">Critical / High</div>
      <div class="kpi-value">{s.severity_counts['CRITICAL']} / {s.severity_counts['HIGH']}</div>
      <div class="kpi-sub">Medium: {s.severity_counts['MEDIUM']} &middot; Low: {s.severity_counts['LOW']}</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">Open Findings</div>
      <div class="kpi-value">{s.total_findings}</div>
      <div class="kpi-sub">Security: {s.category_counts['Security']} &middot; Cost: {s.category_counts['Cost']}</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">Est. Monthly Savings</div>
      <div class="kpi-value">${s.total_monthly_savings_usd:,.2f}/mo</div>
      <div class="kpi-sub">${s.total_annual_savings_usd:,.2f}/yr annualized</div>
    </div>
    <div class="kpi">
      <div class="kpi-label">Governance</div>
      <div class="kpi-value">{s.suppressed_count} Waived</div>
      <div class="kpi-sub">Collection warnings: {s.warnings_count}</div>
    </div>
  </div>

  <div class="toolbar">
    <input id="searchBox" type="search" placeholder="Filter by rule, resource, issue, or compliance tag..." />
    <select id="severityFilter">
      <option value="">All Severities</option>
      <option value="CRITICAL">CRITICAL</option>
      <option value="HIGH">HIGH</option>
      <option value="MEDIUM">MEDIUM</option>
      <option value="LOW">LOW</option>
    </select>
    <select id="categoryFilter">
      <option value="">All Categories</option>
      <option value="Security">Security</option>
      <option value="Cost">Cost</option>
    </select>
    <select id="regionFilter">
      <option value="">All Regions</option>
      {region_select_html}
    </select>
    <span class="count-pill" id="visibleCount">Showing {len(result.findings)} of {len(result.findings)}</span>
  </div>

  <div class="table-wrap">
    {empty_notice}
    <table id="findingsTable">
      <thead>
        <tr>
          <th>Severity / Rule</th>
          <th>Category</th>
          <th>Region</th>
          <th>Resource</th>
          <th>Finding &amp; Compliance</th>
          <th class="num">Savings/Mo</th>
          <th>Remediation</th>
        </tr>
      </thead>
      <tbody>{''.join(rows_html)}</tbody>
    </table>
  </div>

  {suppressed_section}
  {warnings_section}
</div>

<script>
(function() {{
  const search = document.getElementById("searchBox");
  const sev = document.getElementById("severityFilter");
  const cat = document.getElementById("categoryFilter");
  const reg = document.getElementById("regionFilter");
  const countPill = document.getElementById("visibleCount");
  const rows = Array.from(document.querySelectorAll("tr.finding-row"));

  function applyFilters() {{
    const q = (search.value || "").toLowerCase();
    const sVal = sev.value;
    const cVal = cat.value;
    const rVal = reg.value;
    let visible = 0;

    for (const row of rows) {{
      const matchSev = !sVal || row.dataset.severity === sVal;
      const matchCat = !cVal || row.dataset.category === cVal;
      const matchReg = !rVal || row.dataset.region === rVal;
      const matchText = !q || row.textContent.toLowerCase().includes(q);
      const show = matchSev && matchCat && matchReg && matchText;
      row.style.display = show ? "" : "none";
      if (show) visible += 1;
    }}
    countPill.textContent = "Showing " + visible + " of " + rows.length;
  }}

  [search, sev, cat, reg].forEach(el => el.addEventListener("input", applyFilters));
}})();
</script>
</body>
</html>
"""
    filepath.write_text(doc, encoding="utf-8")
    return doc
