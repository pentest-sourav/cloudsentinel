from datetime import datetime, timezone
from types import SimpleNamespace

from reporting.html_report import render_scan_report


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


def test_render_scan_report_contains_security_content():
    html = render_scan_report(
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

    assert "CloudSentinel Security Assessment" in html
    assert "CS-AWS-S3-001" in html
    assert "S3 bucket is publicly accessible" in html
    assert "Block public access." in html
    assert "AWS Security Hub S3.1" in html
    assert "Total Findings" in html
    assert ">1<" in html


def test_render_scan_report_escapes_untrusted_values():
    finding = make_finding()
    finding.resource_id = "<script>alert(1)</script>"
    finding.description = "<img src=x onerror=alert(1)>"

    html = render_scan_report(
        scan=make_scan(),
        findings=[finding],
        execution_errors=[],
    )

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_render_scan_report_handles_empty_results():
    html = render_scan_report(
        scan=make_scan(),
        findings=[],
        execution_errors=[],
    )

    assert "No security findings were produced" in html
    assert "No execution errors were recorded" in html
