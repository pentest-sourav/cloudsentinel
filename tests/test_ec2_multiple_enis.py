from engine.findings.model import Finding, Severity
from engine.rules.aws.ec2.multiple_enis import (
    MultipleENIResult,
    build_multiple_enis_finding,
    check_multiple_enis,
)


def test_instance_with_multiple_enis_is_detected():
    result = check_multiple_enis(
        instance_id="i-001",
        network_interface_count=2,
    )

    assert result is not None
    assert isinstance(result, MultipleENIResult)
    assert result.instance_id == "i-001"
    assert result.network_interface_count == 2


def test_instance_with_single_eni_is_not_detected():
    result = check_multiple_enis(
        instance_id="i-002",
        network_interface_count=1,
    )

    assert result is None


def test_instance_with_zero_enis_is_not_detected():
    result = check_multiple_enis(
        instance_id="i-003",
        network_interface_count=0,
    )

    assert result is None


def test_multiple_enis_finding_contains_expected_details():
    result = check_multiple_enis(
        instance_id="i-001",
        network_interface_count=3,
    )

    assert result is not None

    finding = build_multiple_enis_finding(result)

    assert isinstance(finding, Finding)
    assert finding.rule_id == "CS-AWS-EC2-008"
    assert finding.severity == Severity.LOW
    assert finding.provider == "aws"
    assert finding.resource_type == "ec2_instance"
    assert finding.resource_id == "i-001"

    assert finding.evidence["instance_id"] == "i-001"
    assert finding.evidence["network_interface_count"] == 3

    assert finding.remediation
