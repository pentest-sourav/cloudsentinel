from datetime import datetime, timezone
from types import SimpleNamespace

from reporting.pdf_report import render_scan_pdf


def make_scan():
    return SimpleNamespace(
        id=42,
        provider="aws",
        status="completed",
        started_at=datetime(
            2026,
            9,
            26,
            10,
            0,
            tzinfo=timezone.utc,
        ),
        completed_at=datetime(
            2026,
            9,
            26,
            10,
            5,
            tzinfo=timezone.utc,
        ),
    )


def make_finding():
    return SimpleNamespace(
        id=1,
        rule_id="CS-AWS-S3-001",
        title="S3 bucket is publicly accessible",
        severity="HIGH",
        risk_level="HIGH",
        risk_score=82.5,
        provider="aws",
        resource_type="s3_bucket",
        resource_id="demo-bucket",
        description="Bucket permits public access.",
        evidence={
            "public_access": True,
            "bucket": "demo-bucket",
        },
        remediation="Block public access.",
        compliance=[
            "AWS Security Hub S3.1",
            "CIS AWS Foundations",
        ],
    )


def test_render_scan_pdf_returns_valid_pdf_document():
    pdf = render_scan_pdf(
        scan=make_scan(),
        findings=[make_finding()],
        execution_errors=[],
        lifecycle={
            "new": 1,
            "open": 0,
            "reopened": 0,
            "resolved": 0,
            "previous_scan_id": None,
        },
    )

    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF-")
    assert b"%%EOF" in pdf


def test_render_scan_pdf_handles_empty_results():
    pdf = render_scan_pdf(
        scan=make_scan(),
        findings=[],
        execution_errors=[],
        lifecycle=None,
    )

    assert pdf.startswith(b"%PDF-")
    assert b"%%EOF" in pdf


def test_render_scan_pdf_escapes_untrusted_values():
    finding = make_finding()
    finding.resource_id = "<script>alert(1)</script>"
    finding.description = "<img src=x onerror=alert(1)>"

    pdf = render_scan_pdf(
        scan=make_scan(),
        findings=[finding],
        execution_errors=[],
    )

    assert pdf.startswith(b"%PDF-")
    assert b"%%EOF" in pdf
