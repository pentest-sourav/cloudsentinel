from engine.findings.model import Finding, Severity
from engine.rules.aws.ec2.imdsv1 import (
    build_imdsv1_finding,
    check_imdsv1,
)


def test_imdsv1_enabled_is_detected():
    result = check_imdsv1(
        instance_id="i-001",
        metadata_http_tokens="optional",
    )

    assert result is not None
    assert result.instance_id == "i-001"
    assert result.http_tokens == "optional"


def test_imdsv2_required_is_not_detected():
    result = check_imdsv1(
        instance_id="i-002",
        metadata_http_tokens="required",
    )

    assert result is None


def test_imdsv1_finding_contains_expected_details():
    result = check_imdsv1(
        instance_id="i-001",
        metadata_http_tokens="optional",
    )

    finding = build_imdsv1_finding(result)

    assert isinstance(finding, Finding)

    assert finding.rule_id == "CS-AWS-EC2-003"
    assert finding.severity == Severity.HIGH
    assert finding.provider == "aws"
    assert finding.resource_type == "ec2_instance"
    assert finding.resource_id == "i-001"

    assert finding.evidence["instance_id"] == "i-001"
    assert finding.evidence["http_tokens"] == "optional"
