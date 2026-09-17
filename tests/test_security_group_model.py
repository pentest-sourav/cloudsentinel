import pytest

from scanner.aws.models.security_group import SecurityGroupRule


def test_security_group_rule_creation():
    rule = SecurityGroupRule(
        protocol="tcp",
        from_port=22,
        to_port=22,
        ipv4_cidr="0.0.0.0/0",
    )

    assert rule.protocol == "tcp"
    assert rule.from_port == 22
    assert rule.to_port == 22
    assert rule.ipv4_cidr == "0.0.0.0/0"


def test_ipv4_cidr_source():
    rule = SecurityGroupRule(
        protocol="tcp",
        from_port=22,
        to_port=22,
        ipv4_cidr="0.0.0.0/0",
    )

    assert rule.is_cidr_source is True
    assert rule.is_all_ipv4 is True
    assert rule.is_all_ipv6 is False


def test_ipv6_cidr_source():
    rule = SecurityGroupRule(
        protocol="tcp",
        from_port=3389,
        to_port=3389,
        ipv6_cidr="::/0",
    )

    assert rule.is_cidr_source is True
    assert rule.is_all_ipv6 is True
    assert rule.is_all_ipv4 is False


def test_security_group_reference():
    rule = SecurityGroupRule(
        protocol="tcp",
        from_port=8080,
        to_port=8080,
        source_security_group_id="sg-123456",
    )

    assert rule.source_security_group_id == "sg-123456"
    assert rule.is_cidr_source is False


def test_security_group_rule_is_immutable():
    rule = SecurityGroupRule(
        protocol="tcp",
        from_port=22,
        to_port=22,
        ipv4_cidr="0.0.0.0/0",
    )

    with pytest.raises(
        AttributeError,
        match="cannot assign to field",
    ):
        rule.from_port = 443
