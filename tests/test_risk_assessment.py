from engine.findings.model import Finding, Severity
from engine.risk.assessment import assess_finding_risk
from engine.risk.model import RiskContext, RiskLevel


def test_assessment_uses_finding_severity():
    finding = Finding(
        rule_id="CS-AWS-S3-001",
        title="Test Finding",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="s3_bucket",
        resource_id="test-bucket",
        description="Test finding",
    )

    result = assess_finding_risk(
        finding=finding,
        context=RiskContext(),
    )

    assert result.level == RiskLevel.HIGH
    assert result.score == 7.0


def test_assessment_includes_context():
    finding = Finding(
        rule_id="CS-AWS-S3-001",
        title="Test Finding",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="s3_bucket",
        resource_id="test-bucket",
        description="Test finding",
    )

    result = assess_finding_risk(
        finding=finding,
        context=RiskContext(
            internet_exposed=True,
            sensitive_data=True,
            asset_criticality=5,
            exploitability=5,
        ),
    )

    assert result.score == 9.0
    assert result.level == RiskLevel.CRITICAL
