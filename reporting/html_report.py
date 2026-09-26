from __future__ import annotations

import html
from datetime import datetime
from typing import Iterable


def _escape(value) -> str:
    if value is None:
        return ""
    return html.escape(str(value))


def _format_dt(value) -> str:
    if value is None:
        return "—"
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S UTC")
    return _escape(value)


def _severity_class(severity: str) -> str:
    return str(severity or "info").lower()


def _jsonish(value) -> str:
    if value is None:
        return "—"

    if isinstance(value, dict):
        return "<br>".join(
            f"<strong>{_escape(key)}</strong>: {_escape(val)}"
            for key, val in value.items()
        )

    if isinstance(value, list):
        return "<br>".join(_escape(item) for item in value)

    return _escape(value)


def render_scan_report(
    *,
    scan,
    findings: Iterable,
    execution_errors: Iterable,
    lifecycle: dict | None = None,
) -> str:
    findings = list(findings)
    execution_errors = list(execution_errors)
    lifecycle = lifecycle or {}

    counts = {
        "critical": sum(
            str(item.severity).lower() == "critical"
            for item in findings
        ),
        "high": sum(
            str(item.severity).lower() == "high"
            for item in findings
        ),
        "medium": sum(
            str(item.severity).lower() == "medium"
            for item in findings
        ),
        "low": sum(
            str(item.severity).lower() == "low"
            for item in findings
        ),
        "info": sum(
            str(item.severity).lower() == "info"
            for item in findings
        ),
    }

    finding_rows = []

    for finding in findings:
        compliance = finding.compliance or []

        if isinstance(compliance, list):
            compliance_html = "<br>".join(
                _escape(item) for item in compliance
            ) or "—"
        else:
            compliance_html = _escape(compliance)

        finding_rows.append(
            f"""
            <tr>
                <td><strong>{_escape(finding.rule_id)}</strong></td>
                <td>{_escape(finding.title)}</td>
                <td>
                    <span class="severity {_severity_class(finding.severity)}">
                        {_escape(finding.severity)}
                    </span>
                </td>
                <td>{_escape(finding.risk_level)}</td>
                <td>{_escape(finding.resource_type)}</td>
                <td class="mono">{_escape(finding.resource_id)}</td>
                <td>{_escape(finding.description)}</td>
                <td>{_jsonish(finding.evidence)}</td>
                <td>{_escape(finding.remediation)}</td>
                <td>{compliance_html}</td>
            </tr>
            """
        )

    if not finding_rows:
        finding_rows.append(
            """
            <tr>
                <td colspan="10" class="empty">
                    No security findings were produced by this scan.
                </td>
            </tr>
            """
        )

    error_rows = []

    for error in execution_errors:
        error_rows.append(
            f"""
            <tr>
                <td>{_escape(error.service)}</td>
                <td>{_escape(error.error_type)}</td>
                <td>{_escape(error.error_code) or "—"}</td>
                <td>{_escape(error.message)}</td>
                <td>{_format_dt(error.created_at)}</td>
            </tr>
            """
        )

    if not error_rows:
        error_rows.append(
            """
            <tr>
                <td colspan="5" class="empty">
                    No execution errors were recorded.
                </td>
            </tr>
            """
        )

    lifecycle_html = ""

    if lifecycle:
        lifecycle_html = f"""
        <section>
            <h2>Finding Lifecycle</h2>
            <div class="lifecycle-grid">
                <div><strong>{lifecycle.get("new", 0)}</strong><span>New</span></div>
                <div><strong>{lifecycle.get("open", 0)}</strong><span>Open</span></div>
                <div><strong>{lifecycle.get("reopened", 0)}</strong><span>Reopened</span></div>
                <div><strong>{lifecycle.get("resolved", 0)}</strong><span>Resolved</span></div>
            </div>
            <p class="muted">
                Previous scan:
                {_escape(lifecycle.get("previous_scan_id") or "None")}
            </p>
        </section>
        """

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CloudSentinel Security Report — Scan {_escape(scan.id)}</title>
<style>
:root {{
    --bg: #f5f7fb;
    --panel: #ffffff;
    --text: #172033;
    --muted: #667085;
    --border: #e4e7ec;
    --critical: #b42318;
    --high: #d92d20;
    --medium: #dc6803;
    --low: #1570ef;
    --info: #475467;
}}
* {{ box-sizing: border-box; }}
body {{
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: Inter, Arial, sans-serif;
    line-height: 1.5;
}}
.container {{
    max-width: 1500px;
    margin: 0 auto;
    padding: 36px;
}}
header {{
    background: #101828;
    color: white;
    padding: 32px;
    border-radius: 16px;
    margin-bottom: 24px;
}}
h1, h2 {{ margin-top: 0; }}
h1 {{ font-size: 30px; margin-bottom: 8px; }}
h2 {{ font-size: 20px; margin-bottom: 16px; }}
section {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 24px;
    margin-bottom: 24px;
}}
.meta {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 14px;
    margin-top: 20px;
}}
.meta div {{
    background: rgba(255,255,255,.08);
    padding: 12px;
    border-radius: 10px;
}}
.meta strong {{
    display: block;
    font-size: 12px;
    color: #98a2b3;
    text-transform: uppercase;
}}
.meta span {{
    display: block;
    margin-top: 4px;
}}
.summary {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 14px;
}}
.card {{
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 18px;
}}
.card strong {{
    display: block;
    font-size: 28px;
}}
.card span {{
    color: var(--muted);
}}
.critical strong {{ color: var(--critical); }}
.high strong {{ color: var(--high); }}
.medium strong {{ color: var(--medium); }}
.low strong {{ color: var(--low); }}
.info strong {{ color: var(--info); }}
table {{
    width: 100%;
    border-collapse: collapse;
    min-width: 1100px;
}}
.table-wrap {{
    overflow-x: auto;
}}
th, td {{
    padding: 11px 12px;
    border-bottom: 1px solid var(--border);
    text-align: left;
    vertical-align: top;
    font-size: 13px;
}}
th {{
    background: #f9fafb;
    white-space: nowrap;
}}
.severity {{
    display: inline-block;
    padding: 3px 8px;
    border-radius: 999px;
    font-weight: 700;
    text-transform: uppercase;
    font-size: 11px;
}}
.severity.critical {{ color: var(--critical); background: #fee4e2; }}
.severity.high {{ color: var(--high); background: #fee4e2; }}
.severity.medium {{ color: var(--medium); background: #fef0c7; }}
.severity.low {{ color: var(--low); background: #dbeafe; }}
.severity.info {{ color: var(--info); background: #eaecf0; }}
.mono {{ font-family: ui-monospace, SFMono-Regular, monospace; }}
.muted {{ color: var(--muted); }}
.lifecycle-grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
}}
.lifecycle-grid div {{
    padding: 16px;
    border: 1px solid var(--border);
    border-radius: 10px;
}}
.lifecycle-grid strong {{
    display: block;
    font-size: 24px;
}}
.lifecycle-grid span {{
    color: var(--muted);
}}
.empty {{
    text-align: center;
    color: var(--muted);
    padding: 28px;
}}
@media print {{
    body {{ background: white; }}
    .container {{ max-width: none; padding: 10px; }}
    section, header {{ break-inside: avoid; }}
}}
</style>
</head>
<body>
<div class="container">

<header>
    <h1>CloudSentinel Security Assessment</h1>
    <p>Multi-Cloud Security Posture &amp; Compliance Auditor</p>

    <div class="meta">
        <div>
            <strong>Scan ID</strong>
            <span>{_escape(scan.id)}</span>
        </div>
        <div>
            <strong>Provider</strong>
            <span>{_escape(scan.provider)}</span>
        </div>
        <div>
            <strong>Status</strong>
            <span>{_escape(scan.status)}</span>
        </div>
        <div>
            <strong>Started</strong>
            <span>{_format_dt(scan.started_at)}</span>
        </div>
        <div>
            <strong>Completed</strong>
            <span>{_format_dt(scan.completed_at)}</span>
        </div>
    </div>
</header>

<section>
    <h2>Executive Summary</h2>

    <div class="summary">
        <div class="card">
            <strong>{len(findings)}</strong>
            <span>Total Findings</span>
        </div>
        <div class="card critical">
            <strong>{counts["critical"]}</strong>
            <span>Critical</span>
        </div>
        <div class="card high">
            <strong>{counts["high"]}</strong>
            <span>High</span>
        </div>
        <div class="card medium">
            <strong>{counts["medium"]}</strong>
            <span>Medium</span>
        </div>
        <div class="card low">
            <strong>{counts["low"]}</strong>
            <span>Low</span>
        </div>
        <div class="card info">
            <strong>{counts["info"]}</strong>
            <span>Info</span>
        </div>
    </div>
</section>

{lifecycle_html}

<section>
    <h2>Security Findings</h2>

    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Rule</th>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Risk</th>
                    <th>Resource Type</th>
                    <th>Resource ID</th>
                    <th>Description</th>
                    <th>Evidence</th>
                    <th>Remediation</th>
                    <th>Compliance</th>
                </tr>
            </thead>
            <tbody>
                {"".join(finding_rows)}
            </tbody>
        </table>
    </div>
</section>

<section>
    <h2>Execution Errors</h2>

    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Service</th>
                    <th>Error Type</th>
                    <th>Error Code</th>
                    <th>Message</th>
                    <th>Created</th>
                </tr>
            </thead>
            <tbody>
                {"".join(error_rows)}
            </tbody>
        </table>
    </div>
</section>

<footer class="muted">
    Generated by CloudSentinel.
</footer>

</div>
</body>
</html>
"""
