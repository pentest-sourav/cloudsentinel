from engine.findings.model import Finding, Severity
from engine.rules.aws.ec2.unused_elastic_ip import (
    UnusedElasticIPResult,
    build_unused_elastic_ip_finding,
    check_unused_elastic_ip,
)


def test_unassociated_elastic_ip_is_detected():
    result = check_unused_elastic_ip(
        allocation_id="eipalloc-001",
        public_ip="203.0.113.10",
        instance_id=None,
        network_interface_id=None,
        associated=False,
    )

    assert result is not None
    assert isinstance(result, UnusedElasticIPResult)
    assert result.allocation_id == "eipalloc-001"
    assert result.public_ip == "203.0.113.10"


def test_associated_elastic_ip_is_not_detected():
    result = check_unused_elastic_ip(
        allocation_id="eipalloc-002",
        public_ip="203.0.113.11",
        instance_id="i-001",
        network_interface_id="eni-001",
        associated=True,
    )

    assert result is None


def test_unused_elastic_ip_finding_contains_expected_details():
    result = check_unused_elastic_ip(
        allocation_id="eipalloc-001",
        public_ip="203.0.113.10",
        instance_id=None,
        network_interface_id=None,
        associated=False,
    )

    assert result is not None

    finding = build_unused_elastic_ip_finding(result)

    assert isinstance(finding, Finding)
    assert finding.rule_id == "CS-AWS-EC2-007"
    assert finding.severity == Severity.LOW
    assert finding.provider == "aws"
    assert finding.resource_type == "ec2_elastic_ip"
    assert finding.resource_id == "eipalloc-001"

    assert finding.evidence["allocation_id"] == "eipalloc-001"
    assert finding.evidence["public_ip"] == "203.0.113.10"
    assert finding.evidence["associated"] is False

    assert finding.remediation
    assert "release" in finding.remediation.lower()


def test_unassociated_elastic_ip_without_public_ip_is_still_detected():
    result = check_unused_elastic_ip(
        allocation_id="eipalloc-003",
        public_ip=None,
        instance_id=None,
        network_interface_id=None,
        associated=False,
    )

    assert result is not None
