from engine.rules.aws.vpc.orphaned_internet_gateway import (
    build_orphaned_internet_gateway_finding,
    check_orphaned_internet_gateway,
)


def test_orphaned_internet_gateway_is_detected():
    result = check_orphaned_internet_gateway(
        internet_gateway_id="igw-123456789",
        vpc_id=None,
        state=None,
    )

    assert result is not None
    assert result.internet_gateway_id == "igw-123456789"


def test_attached_internet_gateway_is_not_flagged():
    result = check_orphaned_internet_gateway(
        internet_gateway_id="igw-123456789",
        vpc_id="vpc-123456789",
        state="available",
    )

    assert result is None


def test_orphaned_internet_gateway_finding():
    result = check_orphaned_internet_gateway(
        internet_gateway_id="igw-123456789",
        vpc_id=None,
        state=None,
    )

    finding = build_orphaned_internet_gateway_finding(result)

    assert finding.rule_id == "CS-AWS-VPC-002"
    assert finding.severity.value == "low"
    assert finding.resource_type == "internet_gateway"
    assert finding.resource_id == "igw-123456789"
