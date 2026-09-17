from engine.findings.model import Finding, Severity
from engine.risk.context import build_risk_context


def test_context_uses_explicit_evidence():
    finding = Finding(
        rule_id="CS-AWS-S3-001",
        title="Test Finding",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="s3_bucket",
        resource_id="test-bucket",
        description="Test finding",
        evidence={
            "internet_exposed": True,
            "sensitive_data": True,
            "asset_criticality": 4,
            "exploitability": 3,
        },
    )

    context = build_risk_context(finding)

    assert context.internet_exposed is True
    assert context.sensitive_data is True
    assert context.asset_criticality == 4
    assert context.exploitability == 3


def test_context_defaults_when_evidence_is_missing():
    finding = Finding(
        rule_id="CS-AWS-S3-002",
        title="Test Finding",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="s3_bucket",
        resource_id="test-bucket",
        description="Test finding",
    )

    context = build_risk_context(finding)

    assert context.internet_exposed is False
    assert context.sensitive_data is False
    assert context.asset_criticality == 1
    assert context.exploitability == 1
