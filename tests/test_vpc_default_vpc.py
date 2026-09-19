from engine.rules.aws.vpc.default_vpc import (
    build_default_vpc_finding,
    check_default_vpc,
)


def test_detects_default_vpc():
    result = check_default_vpc(
        vpc_id="vpc-123456789",
        cidr_block="172.31.0.0/16",
        is_default=True,
    )

    assert result is not None
    assert result.vpc_id == "vpc-123456789"
    assert result.cidr_block == "172.31.0.0/16"


def test_ignores_non_default_vpc():
    result = check_default_vpc(
        vpc_id="vpc-987654321",
        cidr_block="10.0.0.0/16",
        is_default=False,
    )

    assert result is None


def test_builds_medium_severity_finding():
    result = check_default_vpc(
        vpc_id="vpc-123456789",
        cidr_block="172.31.0.0/16",
        is_default=True,
    )

    assert result is not None

    finding = build_default_vpc_finding(result)

    assert finding.rule_id == "CS-AWS-VPC-001"
    assert finding.severity.value == "medium"
    assert finding.resource_type == "vpc"
    assert finding.resource_id == "vpc-123456789"
    assert finding.evidence["is_default"] is True
