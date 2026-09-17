from engine.findings.model import Finding, Severity
from engine.risk.assessment import assess_finding_risk
from engine.risk.context import build_risk_context
from engine.risk.model import RiskLevel


def test_finding_to_risk_pipeline():
    finding = Finding(
        rule_id="CS-AWS-S3-001",
        title="S3 Public Access",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="s3_bucket",
        resource_id="test-bucket",
        description="Bucket has a public access signal.",
        evidence={
            "internet_exposed": True,
            "sensitive_data": True,
            "asset_criticality": 4,
            "exploitability": 3,
        },
    )

    context = build_risk_context(finding)

    risk = assess_finding_risk(
        finding=finding,
        context=context,
    )

    assert risk.score == 10.0
    assert risk.level == RiskLevel.CRITICAL

    assert risk.factors["base_severity"] == 7.0
    assert risk.factors["internet_exposure"] == 1.0
    assert risk.factors["sensitive_data"] == 1.0
    assert risk.factors["asset_criticality"] == 0.75
    assert risk.factors["exploitability"] == 0.5
