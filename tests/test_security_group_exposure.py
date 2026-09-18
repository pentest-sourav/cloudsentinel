from scanner.aws.models.security_group import SecurityGroupRule
from engine.rules.aws.ec2.security_group_exposure import (
    check_security_group_exposure,
)


def test_public_ipv4_ssh_is_detected():
    rule = SecurityGroupRule(
        protocol="tcp",
        from_port=22,
        to_port=22,
        ipv4_cidr="0.0.0.0/0",
    )

    result = check_security_group_exposure(
        security_group_id="sg-123",
        rule=rule,
    )

    assert result is not None
    assert result.is_exposed is True
    assert result.security_group_id == "sg-123"
    assert result.management_service == "SSH"
    assert result.exposure_type == "ssh_port_range"


def test_public_ipv6_ssh_is_detected():
    rule = SecurityGroupRule(
        protocol="tcp",
        from_port=22,
        to_port=22,
        ipv6_cidr="::/0",
    )

    result = check_security_group_exposure(
        security_group_id="sg-123",
        rule=rule,
    )

    assert result is not None
    assert result.is_exposed is True
    assert result.management_service == "SSH"


def test_public_ipv4_rdp_is_detected():
    rule = SecurityGroupRule(
        protocol="tcp",
        from_port=3389,
        to_port=3389,
        ipv4_cidr="0.0.0.0/0",
    )

    result = check_security_group_exposure(
        security_group_id="sg-456",
        rule=rule,
    )

    assert result is not None
    assert result.management_service == "RDP"
    assert result.exposure_type == "rdp_port_range"


def test_private_cidr_is_not_detected():
    rule = SecurityGroupRule(
        protocol="tcp",
        from_port=22,
        to_port=22,
        ipv4_cidr="10.0.0.0/8",
    )

    result = check_security_group_exposure(
        security_group_id="sg-private",
        rule=rule,
    )

    assert result is None


def test_security_group_reference_is_not_detected():
    rule = SecurityGroupRule(
        protocol="tcp",
        from_port=22,
        to_port=22,
        source_security_group_id="sg-source",
    )

    result = check_security_group_exposure(
        security_group_id="sg-target",
        rule=rule,
    )

    assert result is None


def test_public_https_is_not_management_exposure():
    rule = SecurityGroupRule(
        protocol="tcp",
        from_port=443,
        to_port=443,
        ipv4_cidr="0.0.0.0/0",
    )

    result = check_security_group_exposure(
        security_group_id="sg-web",
        rule=rule,
    )

    assert result is None


def test_non_tcp_management_port_is_not_detected():
    rule = SecurityGroupRule(
        protocol="udp",
        from_port=22,
        to_port=22,
        ipv4_cidr="0.0.0.0/0",
    )

    result = check_security_group_exposure(
        security_group_id="sg-udp",
        rule=rule,
    )

    assert result is None


def test_all_ports_public_exposure_is_detected():
    rule = SecurityGroupRule(
        protocol="-1",
        from_port=None,
        to_port=None,
        ipv4_cidr="0.0.0.0/0",
    )

    result = check_security_group_exposure(
        security_group_id="sg-all",
        rule=rule,
    )

    assert result is not None
    assert result.is_exposed is True
    assert result.exposure_type == "all_ports"

def test_public_ipv4_port_range_containing_ssh_is_detected():
    rule = SecurityGroupRule(
        protocol="tcp",
        from_port=20,
        to_port=25,
        ipv4_cidr="0.0.0.0/0",
    )

    result = check_security_group_exposure(
        security_group_id="sg-range-ssh",
        rule=rule,
    )

    assert result is not None
    assert result.management_service == "SSH"
    assert result.exposure_type == "ssh_port_range"


def test_public_ipv4_port_range_containing_rdp_is_detected():
    rule = SecurityGroupRule(
        protocol="tcp",
        from_port=3380,
        to_port=3390,
        ipv4_cidr="0.0.0.0/0",
    )

    result = check_security_group_exposure(
        security_group_id="sg-range-rdp",
        rule=rule,
    )

    assert result is not None
    assert result.management_service == "RDP"
    assert result.exposure_type == "rdp_port_range"


def test_public_non_management_port_range_is_not_detected():
    rule = SecurityGroupRule(
        protocol="tcp",
        from_port=1000,
        to_port=2000,
        ipv4_cidr="0.0.0.0/0",
    )

    result = check_security_group_exposure(
        security_group_id="sg-non-management",
        rule=rule,
    )

    assert result is None
