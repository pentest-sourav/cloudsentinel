from engine.findings.model import Finding, Severity
from engine.rules.aws.ec2.public_exposure import (
    build_public_ec2_finding,
    check_public_ec2_exposure,
)


def test_public_ec2_instance_is_detected():
    result = check_public_ec2_exposure(
        instance_id="i-001",
        public_ip="203.0.113.10",
    )

    assert result is not None
    assert result.instance_id == "i-001"
    assert result.public_ip == "203.0.113.10"


def test_ec2_without_public_ip_is_not_detected():
    result = check_public_ec2_exposure(
        instance_id="i-002",
        public_ip=None,
    )

    assert result is None


def test_public_ec2_finding_contains_expected_details():
    result = check_public_ec2_exposure(
        instance_id="i-001",
        public_ip="203.0.113.10",
    )

    finding = build_public_ec2_finding(result)

    assert isinstance(finding, Finding)

    assert finding.rule_id == "CS-AWS-EC2-002"
    assert finding.severity == Severity.MEDIUM
    assert finding.provider == "aws"
    assert finding.resource_type == "ec2_instance"
    assert finding.resource_id == "i-001"

    assert finding.evidence["instance_id"] == "i-001"
    assert finding.evidence["public_ip"] == "203.0.113.10"
    assert finding.evidence["internet_exposed"] is True
