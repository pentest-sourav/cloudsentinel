from engine.findings.model import Severity
from engine.rules.aws.vpc.unrestricted_network_acl import (
    build_unrestricted_network_acl_finding,
    check_unrestricted_network_acl,
)


def test_detects_unrestricted_ipv4_inbound_rule():
    result = check_unrestricted_network_acl(
        network_acl_id="acl-123",
        vpc_id="vpc-123",
        is_default=False,
        rule_number=100,
        egress=False,
        rule_action="allow",
        protocol="-1",
        cidr_block="0.0.0.0/0",
        ipv6_cidr_block=None,
    )

    assert result is not None
    assert result.network_acl_id == "acl-123"
    assert result.egress is False


def test_detects_unrestricted_ipv6_outbound_rule():
    result = check_unrestricted_network_acl(
        network_acl_id="acl-123",
        vpc_id="vpc-123",
        is_default=False,
        rule_number=100,
        egress=True,
        rule_action="allow",
        protocol="-1",
        cidr_block=None,
        ipv6_cidr_block="::/0",
    )

    assert result is not None
    assert result.ipv6_cidr_block == "::/0"
    assert result.egress is True


def test_does_not_flag_default_network_acl():
    result = check_unrestricted_network_acl(
        network_acl_id="acl-default",
        vpc_id="vpc-123",
        is_default=True,
        rule_number=100,
        egress=False,
        rule_action="allow",
        protocol="-1",
        cidr_block="0.0.0.0/0",
        ipv6_cidr_block=None,
    )

    assert result is None


def test_does_not_flag_denied_rule():
    result = check_unrestricted_network_acl(
        network_acl_id="acl-123",
        vpc_id="vpc-123",
        is_default=False,
        rule_number=100,
        egress=False,
        rule_action="deny",
        protocol="-1",
        cidr_block="0.0.0.0/0",
        ipv6_cidr_block=None,
    )

    assert result is None


def test_does_not_flag_restricted_cidr():
    result = check_unrestricted_network_acl(
        network_acl_id="acl-123",
        vpc_id="vpc-123",
        is_default=False,
        rule_number=100,
        egress=False,
        rule_action="allow",
        protocol="-1",
        cidr_block="10.0.0.0/16",
        ipv6_cidr_block=None,
    )

    assert result is None


def test_does_not_flag_specific_protocol():
    result = check_unrestricted_network_acl(
        network_acl_id="acl-123",
        vpc_id="vpc-123",
        is_default=False,
        rule_number=100,
        egress=False,
        rule_action="allow",
        protocol="6",
        cidr_block="0.0.0.0/0",
        ipv6_cidr_block=None,
    )

    assert result is None


def test_builds_medium_severity_finding():
    result = check_unrestricted_network_acl(
        network_acl_id="acl-123",
        vpc_id="vpc-123",
        is_default=False,
        rule_number=100,
        egress=False,
        rule_action="allow",
        protocol="-1",
        cidr_block="0.0.0.0/0",
        ipv6_cidr_block=None,
    )

    assert result is not None

    finding = build_unrestricted_network_acl_finding(result)

    assert finding.rule_id == "CS-AWS-VPC-005"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_type == "network_acl"
    assert finding.resource_id == "acl-123"
    assert finding.evidence["direction"] == "inbound"
