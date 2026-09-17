from engine.findings.model import Finding, Severity
from engine.risk.assessment import assess_finding_risk
from engine.risk.enrichment import enrich_risk_context


def test_s3_public_access_finding_gets_higher_risk_when_exposed():
    finding = Finding(
        rule_id="CS-AWS-S3-001",
        title="S3 Public Access Block Not Fully Enabled",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="s3_bucket",
        resource_id="public-test-bucket",
        description="Test S3 exposure.",
        evidence={
            "configuration": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
            "reason": "BlockPublicAcls is disabled.",
            "public_access_signal": True,
        },
        remediation="Enable S3 Public Access Block.",
        compliance=["CIS AWS Foundations"],
    )

    context = enrich_risk_context(finding)

    risk = assess_finding_risk(
        finding=finding,
        context=context,
    )

    assert context.internet_exposed is True
    assert risk.score == 8.0
    assert risk.level.value == "high"
