from __future__ import annotations

import io
import json
from collections.abc import Iterable
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    KeepTogether,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


PAGE_WIDTH, PAGE_HEIGHT = landscape(A4)


def _format_dt(value) -> str:
    if value is None:
        return "—"

    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S UTC")

    return str(value)


def _text(value) -> str:
    if value is None:
        return "—"

    return escape(str(value))


def _multiline(value) -> str:
    return _text(value).replace("\n", "<br/>")


def _jsonish(value) -> str:
    if value is None:
        return "—"

    try:
        rendered = json.dumps(
            value,
            indent=2,
            sort_keys=True,
            default=str,
        )
    except (TypeError, ValueError):
        rendered = str(value)

    return _multiline(rendered)


def _severity_counts(findings: list) -> dict[str, int]:
    levels = ("critical", "high", "medium", "low", "info")

    return {
        level: sum(
            str(getattr(item, "severity", "")).lower() == level
            for item in findings
        )
        for level in levels
    }


def _styles():
    base = getSampleStyleSheet()

    return {
        "title": ParagraphStyle(
            "CloudSentinelTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#101828"),
            spaceAfter=5 * mm,
        ),
        "subtitle": ParagraphStyle(
            "CloudSentinelSubtitle",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#667085"),
            spaceAfter=7 * mm,
        ),
        "section": ParagraphStyle(
            "CloudSentinelSection",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#101828"),
            spaceBefore=5 * mm,
            spaceAfter=3 * mm,
        ),
        "body": ParagraphStyle(
            "CloudSentinelBody",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#344054"),
        ),
        "small": ParagraphStyle(
            "CloudSentinelSmall",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=7.2,
            leading=9,
            textColor=colors.HexColor("#475467"),
        ),
        "small_bold": ParagraphStyle(
            "CloudSentinelSmallBold",
            parent=base["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=7.2,
            leading=9,
            textColor=colors.HexColor("#101828"),
        ),
        "finding_title": ParagraphStyle(
            "CloudSentinelFindingTitle",
            parent=base["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=10.5,
            leading=13,
            textColor=colors.HexColor("#101828"),
            spaceBefore=2 * mm,
            spaceAfter=2 * mm,
        ),
        "mono": ParagraphStyle(
            "CloudSentinelMono",
            parent=base["Code"],
            fontName="Courier",
            fontSize=6.5,
            leading=8,
            textColor=colors.HexColor("#344054"),
            wordWrap="CJK",
        ),
        "footer": ParagraphStyle(
            "CloudSentinelFooter",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=7,
            leading=9,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#98A2B3"),
        ),
    }


def _paragraph(value, style):
    return Paragraph(_text(value), style)


def _table(data, widths, *, header=True):
    table = Table(
        data,
        colWidths=widths,
        repeatRows=1 if header else 0,
        hAlign="LEFT",
    )

    commands = [
        (
            "GRID",
            (0, 0),
            (-1, -1),
            0.35,
            colors.HexColor("#E4E7EC"),
        ),
        (
            "VALIGN",
            (0, 0),
            (-1, -1),
            "TOP",
        ),
        (
            "LEFTPADDING",
            (0, 0),
            (-1, -1),
            5,
        ),
        (
            "RIGHTPADDING",
            (0, 0),
            (-1, -1),
            5,
        ),
        (
            "TOPPADDING",
            (0, 0),
            (-1, -1),
            5,
        ),
        (
            "BOTTOMPADDING",
            (0, 0),
            (-1, -1),
            5,
        ),
    ]

    if header:
        commands.extend(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#F2F4F7"),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#344054"),
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
            ]
        )

    table.setStyle(TableStyle(commands))
    return table


def _severity_badge(severity: str, styles):
    normalized = str(severity or "info").lower()

    backgrounds = {
        "critical": "#FEE4E2",
        "high": "#FEE4E2",
        "medium": "#FEF0C7",
        "low": "#DBEAFE",
        "info": "#EAECF0",
    }

    foregrounds = {
        "critical": "#B42318",
        "high": "#B42318",
        "medium": "#B54708",
        "low": "#175CD3",
        "info": "#344054",
    }

    background = backgrounds.get(normalized, "#EAECF0")
    foreground = foregrounds.get(normalized, "#344054")

    return Paragraph(
        (
            f'<font color="{foreground}">'
            f"<b>{escape(normalized.upper())}</b>"
            "</font>"
        ),
        ParagraphStyle(
            f"severity_{normalized}",
            parent=styles["small"],
            fontName="Helvetica-Bold",
            backColor=colors.HexColor(background),
            borderColor=colors.HexColor(background),
            borderWidth=0.5,
            borderPadding=3,
            alignment=TA_CENTER,
        ),
    )


def _header_footer(canvas, doc):
    canvas.saveState()

    canvas.setStrokeColor(colors.HexColor("#E4E7EC"))
    canvas.setLineWidth(0.5)
    canvas.line(
        18 * mm,
        12 * mm,
        PAGE_WIDTH - 18 * mm,
        12 * mm,
    )

    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#98A2B3"))
    canvas.drawString(
        18 * mm,
        7 * mm,
        "CloudSentinel Security Assessment",
    )
    canvas.drawRightString(
        PAGE_WIDTH - 18 * mm,
        7 * mm,
        f"Page {doc.page}",
    )

    canvas.restoreState()


class _ReportDocTemplate(BaseDocTemplate):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        frame = Frame(
            18 * mm,
            17 * mm,
            PAGE_WIDTH - 36 * mm,
            PAGE_HEIGHT - 31 * mm,
            id="report",
            leftPadding=0,
            rightPadding=0,
            topPadding=0,
            bottomPadding=0,
        )

        self.addPageTemplates(
            [
                PageTemplate(
                    id="report",
                    frames=[frame],
                    onPage=_header_footer,
                )
            ]
        )


def render_scan_pdf(
    *,
    scan,
    findings: Iterable,
    execution_errors: Iterable,
    lifecycle: dict | None = None,
) -> bytes:
    """
    Render a complete scan report as a self-contained PDF.

    The renderer intentionally uses only ReportLab primitives so the API
    container does not require Chromium, wkhtmltopdf, or other external
    browser binaries.
    """
    findings = list(findings)
    execution_errors = list(execution_errors)
    lifecycle = lifecycle or {}

    styles = _styles()
    counts = _severity_counts(findings)

    buffer = io.BytesIO()

    document = _ReportDocTemplate(
        buffer,
        pagesize=landscape(A4),
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=17 * mm,
        bottomMargin=17 * mm,
        title=f"CloudSentinel Security Report — Scan {scan.id}",
        author="CloudSentinel",
        subject="Cloud security posture and compliance assessment",
    )

    story = []

    story.append(
        Paragraph(
            "CloudSentinel Security Assessment",
            styles["title"],
        )
    )
    story.append(
        Paragraph(
            "Multi-Cloud Security Posture &amp; Compliance Auditor",
            styles["subtitle"],
        )
    )

    metadata = [
        [
            _paragraph("<b>Scan ID</b>", styles["small"]),
            _paragraph("<b>Provider</b>", styles["small"]),
            _paragraph("<b>Status</b>", styles["small"]),
            _paragraph("<b>Started</b>", styles["small"]),
            _paragraph("<b>Completed</b>", styles["small"]),
        ],
        [
            _paragraph(scan.id, styles["small"]),
            _paragraph(scan.provider, styles["small"]),
            _paragraph(scan.status, styles["small"]),
            _paragraph(_format_dt(scan.started_at), styles["small"]),
            _paragraph(_format_dt(scan.completed_at), styles["small"]),
        ],
    ]

    story.append(
        _table(
            metadata,
            [35 * mm, 35 * mm, 35 * mm, 55 * mm, 55 * mm],
        )
    )
    story.append(Spacer(1, 5 * mm))

    story.append(
        Paragraph(
            "Executive Summary",
            styles["section"],
        )
    )

    summary = [
        [
            _paragraph("<b>Total</b>", styles["small"]),
            _paragraph("<b>Critical</b>", styles["small"]),
            _paragraph("<b>High</b>", styles["small"]),
            _paragraph("<b>Medium</b>", styles["small"]),
            _paragraph("<b>Low</b>", styles["small"]),
            _paragraph("<b>Info</b>", styles["small"]),
        ],
        [
            _paragraph(len(findings), styles["small_bold"]),
            _paragraph(counts["critical"], styles["small_bold"]),
            _paragraph(counts["high"], styles["small_bold"]),
            _paragraph(counts["medium"], styles["small_bold"]),
            _paragraph(counts["low"], styles["small_bold"]),
            _paragraph(counts["info"], styles["small_bold"]),
        ],
    ]

    summary_table = _table(
        summary,
        [30 * mm] * 6,
    )
    story.append(summary_table)

    if lifecycle:
        story.append(
            Paragraph(
                "Finding Lifecycle",
                styles["section"],
            )
        )

        lifecycle_table = [
            [
                _paragraph("<b>New</b>", styles["small"]),
                _paragraph("<b>Open</b>", styles["small"]),
                _paragraph("<b>Reopened</b>", styles["small"]),
                _paragraph("<b>Resolved</b>", styles["small"]),
            ],
            [
                _paragraph(lifecycle.get("new", 0), styles["small_bold"]),
                _paragraph(lifecycle.get("open", 0), styles["small_bold"]),
                _paragraph(lifecycle.get("reopened", 0), styles["small_bold"]),
                _paragraph(lifecycle.get("resolved", 0), styles["small_bold"]),
            ],
        ]

        story.append(
            _table(
                lifecycle_table,
                [42 * mm] * 4,
            )
        )

        story.append(
            Spacer(1, 2 * mm)
        )

        story.append(
            Paragraph(
                (
                    "Previous scan: "
                    f"{_text(lifecycle.get('previous_scan_id') or 'None')}"
                ),
                styles["small"],
            )
        )

    story.append(
        Paragraph(
            "Security Findings",
            styles["section"],
        )
    )

    if not findings:
        story.append(
            Paragraph(
                "No security findings were produced by this scan.",
                styles["body"],
            )
        )
    else:
        for index, finding in enumerate(findings, start=1):
            finding_header = Paragraph(
                (
                    f"{index}. {_text(finding.rule_id)} — "
                    f"{_text(finding.title)}"
                ),
                styles["finding_title"],
            )

            overview = [
                [
                    _paragraph("<b>Severity</b>", styles["small"]),
                    _paragraph("<b>Risk</b>", styles["small"]),
                    _paragraph("<b>Resource Type</b>", styles["small"]),
                    _paragraph("<b>Resource ID</b>", styles["small"]),
                ],
                [
                    _severity_badge(finding.severity, styles),
                    _paragraph(finding.risk_level, styles["small"]),
                    _paragraph(finding.resource_type, styles["small"]),
                    _paragraph(finding.resource_id, styles["small"]),
                ],
            ]

            finding_table = _table(
                overview,
                [35 * mm, 35 * mm, 50 * mm, 100 * mm],
            )

            evidence = Paragraph(
                f"<b>Evidence</b><br/><font name=\"Courier\">"
                f"{_jsonish(finding.evidence)}"
                f"</font>",
                styles["mono"],
            )

            compliance = finding.compliance or []
            if isinstance(compliance, list):
                compliance_text = "<br/>".join(
                    _text(item) for item in compliance
                ) or "—"
            else:
                compliance_text = _text(compliance)

            details = [
                [
                    _paragraph("<b>Description</b>", styles["small_bold"]),
                    _paragraph(
                        finding.description,
                        styles["small"],
                    ),
                ],
                [
                    _paragraph("<b>Remediation</b>", styles["small_bold"]),
                    _paragraph(
                        finding.remediation,
                        styles["small"],
                    ),
                ],
                [
                    _paragraph("<b>Compliance</b>", styles["small_bold"]),
                    Paragraph(
                        compliance_text,
                        styles["small"],
                    ),
                ],
                [
                    _paragraph("<b>Evidence</b>", styles["small_bold"]),
                    evidence,
                ],
            ]

            details_table = _table(
                details,
                [32 * mm, 188 * mm],
                header=False,
            )

            story.append(
                KeepTogether(
                    [
                        finding_header,
                        finding_table,
                        Spacer(1, 2 * mm),
                        details_table,
                        Spacer(1, 5 * mm),
                    ]
                )
            )

    story.append(
        Paragraph(
            "Execution Errors",
            styles["section"],
        )
    )

    if not execution_errors:
        story.append(
            Paragraph(
                "No execution errors were recorded.",
                styles["body"],
            )
        )
    else:
        error_rows = [
            [
                _paragraph("<b>Service</b>", styles["small"]),
                _paragraph("<b>Error Type</b>", styles["small"]),
                _paragraph("<b>Error Code</b>", styles["small"]),
                _paragraph("<b>Message</b>", styles["small"]),
                _paragraph("<b>Created</b>", styles["small"]),
            ]
        ]

        for error in execution_errors:
            error_rows.append(
                [
                    _paragraph(error.service, styles["small"]),
                    _paragraph(error.error_type, styles["small"]),
                    _paragraph(error.error_code or "—", styles["small"]),
                    _paragraph(error.message, styles["small"]),
                    _paragraph(
                        _format_dt(error.created_at),
                        styles["small"],
                    ),
                ]
            )

        story.append(
            _table(
                error_rows,
                [35 * mm, 40 * mm, 35 * mm, 105 * mm, 45 * mm],
            )
        )

    story.append(Spacer(1, 6 * mm))
    story.append(
        HRFlowable(
            width="100%",
            thickness=0.5,
            color=colors.HexColor("#E4E7EC"),
        )
    )
    story.append(Spacer(1, 3 * mm))
    story.append(
        Paragraph(
            "Generated by CloudSentinel.",
            styles["footer"],
        )
    )

    document.build(story)

    return buffer.getvalue()
