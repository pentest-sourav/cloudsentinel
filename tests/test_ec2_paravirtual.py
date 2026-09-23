from engine.findings.model import Finding, Severity
from engine.rules.aws.ec2.paravirtual import (
    ParavirtualResult,
    build_paravirtual_finding,
    check_paravirtual,
)


def test_paravirtual_instance_is_detected():
    result = check_paravirtual(
        instance_id="i-001",
        virtualization_type="paravirtual",
    )

    assert result is not None
    assert isinstance(result, ParavirtualResult)
    assert result.instance_id == "i-001"
    assert result.virtualization_type == "paravirtual"


def test_hvm_instance_is_not_detected():
    result = check_paravirtual(
        instance_id="i-002",
        virtualization_type="hvm",
    )

    assert result is None


def test_paravirtual_detection_is_case_insensitive():
    result = check_paravirtual(
        instance_id="i-003",
        virtualization_type="PARAVIRTUAL",
    )

    assert result is not None


def test_missing_virtualization_type_is_not_detected():
    result = check_paravirtual(
        instance_id="i-004",
        virtualization_type=None,
    )

    assert result is None


def test_paravirtual_finding_contains_expected_details():
    result = check_paravirtual(
        instance_id="i-001",
        virtualization_type="paravirtual",
    )

    assert result is not None

    finding = build_paravirtual_finding(result)

    assert isinstance(finding, Finding)
    assert finding.rule_id == "CS-AWS-EC2-009"
    assert finding.severity == Severity.MEDIUM
    assert finding.provider == "aws"
    assert finding.resource_type == "ec2_instance"
    assert finding.resource_id == "i-001"

    assert finding.evidence["instance_id"] == "i-001"
    assert finding.evidence["virtualization_type"] == "paravirtual"

    assert finding.remediation
