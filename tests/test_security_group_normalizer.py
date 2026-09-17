from scanner.aws.models.security_group import SecurityGroupRule
from scanner.aws.models.security_group_normalizer import (
    SecurityGroupNormalizer,
)


def test_normalize_ipv4_ingress_rule():
    permission = {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [
            {"CidrIp": "0.0.0.0/0"},
        ],
    }

    rules = SecurityGroupNormalizer.normalize_ingress_rule(
        permission
    )

    assert rules == [
        SecurityGroupRule(
            protocol="tcp",
            from_port=22,
            to_port=22,
            ipv4_cidr="0.0.0.0/0",
        )
    ]


def test_normalize_ipv6_ingress_rule():
    permission = {
        "IpProtocol": "tcp",
        "FromPort": 3389,
        "ToPort": 3389,
        "Ipv6Ranges": [
            {"CidrIpv6": "::/0"},
        ],
    }

    rules = SecurityGroupNormalizer.normalize_ingress_rule(
        permission
    )

    assert rules == [
        SecurityGroupRule(
            protocol="tcp",
            from_port=3389,
            to_port=3389,
            ipv6_cidr="::/0",
        )
    ]


def test_normalize_security_group_reference():
    permission = {
        "IpProtocol": "tcp",
        "FromPort": 8080,
        "ToPort": 8080,
        "UserIdGroupPairs": [
            {"GroupId": "sg-123456"},
        ],
    }

    rules = SecurityGroupNormalizer.normalize_ingress_rule(
        permission
    )

    assert rules == [
        SecurityGroupRule(
            protocol="tcp",
            from_port=8080,
            to_port=8080,
            source_security_group_id="sg-123456",
        )
    ]


def test_normalize_multiple_source_types():
    permission = {
        "IpProtocol": "tcp",
        "FromPort": 443,
        "ToPort": 443,
        "IpRanges": [
            {"CidrIp": "0.0.0.0/0"},
        ],
        "Ipv6Ranges": [
            {"CidrIpv6": "::/0"},
        ],
        "UserIdGroupPairs": [
            {"GroupId": "sg-123456"},
        ],
    }

    rules = SecurityGroupNormalizer.normalize_ingress_rule(
        permission
    )

    assert len(rules) == 3

    assert rules[0].ipv4_cidr == "0.0.0.0/0"
    assert rules[1].ipv6_cidr == "::/0"
    assert rules[2].source_security_group_id == "sg-123456"


def test_normalize_multiple_permissions():
    security_group = {
        "GroupId": "sg-001",
        "GroupName": "web",
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [
                    {"CidrIp": "0.0.0.0/0"},
                ],
            },
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [
                    {"CidrIp": "10.0.0.0/8"},
                ],
            },
        ],
    }

    rules = SecurityGroupNormalizer.normalize_security_group(
        security_group
    )

    assert len(rules) == 2
    assert rules[0].from_port == 22
    assert rules[1].from_port == 443


def test_normalize_empty_security_group():
    security_group = {
        "GroupId": "sg-empty",
        "IpPermissions": [],
    }

    rules = SecurityGroupNormalizer.normalize_security_group(
        security_group
    )

    assert rules == []


def test_normalize_permission_with_no_sources():
    permission = {
        "IpProtocol": "-1",
    }

    rules = SecurityGroupNormalizer.normalize_ingress_rule(
        permission
    )

    assert rules == []
