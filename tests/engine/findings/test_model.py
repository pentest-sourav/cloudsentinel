from engine.findings.model import Finding, Severity


def test_finding_creation():
    finding = Finding(
        rule_id="CS-AWS-S3-001",
        title="S3 Public Access Block Not Fully Enabled",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="s3_bucket",
        resource_id="my-test-bucket",
        description="S3 public access protection is not fully enabled.",
        evidence={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": True,
        },
        remediation="Enable all S3 Public Access Block settings.",
        compliance=["CIS AWS Foundations"],
    )

    assert finding.rule_id == "CS-AWS-S3-001"
    assert finding.title == "S3 Public Access Block Not Fully Enabled"
    assert finding.severity == Severity.HIGH
    assert finding.provider == "aws"
    assert finding.resource_type == "s3_bucket"
    assert finding.resource_id == "my-test-bucket"
    assert finding.evidence["BlockPublicAcls"] is False
    assert finding.remediation.startswith("Enable")
    assert "CIS AWS Foundations" in finding.compliance


def test_finding_defaults():
    finding = Finding(
        rule_id="CS-TEST-001",
        title="Test Finding",
        severity=Severity.INFO,
        provider="aws",
        resource_type="test",
        resource_id="test-resource",
        description="Test description.",
    )

    assert finding.evidence == {}
    assert finding.remediation == ""
    assert finding.compliance == []


def test_severity_values():
    assert Severity.CRITICAL.value == "critical"
    assert Severity.HIGH.value == "high"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.LOW.value == "low"
    assert Severity.INFO.value == "info"
