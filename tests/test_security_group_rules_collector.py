from scanner.aws.collectors.security_group_rules import (
    SecurityGroupRuleCollector,
)
from scanner.aws.models.security_group import SecurityGroupRule


def test_collect_converts_ipv4_rule():
    security_groups = [
        {
            "GroupId": "sg-001",
            "GroupName": "web",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0",
                        }
                    ],
                }
            ],
        }
    ]

    collector = SecurityGroupRuleCollector()

    result = collector.collect(security_groups)

    assert len(result) == 1
    assert result[0]["security_group_id"] == "sg-001"
    assert result[0]["rule"] == SecurityGroupRule(
        protocol="tcp",
        from_port=22,
        to_port=22,
        ipv4_cidr="0.0.0.0/0",
    )


def test_collect_converts_ipv6_rule():
    security_groups = [
        {
            "GroupId": "sg-002",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3389,
                    "ToPort": 3389,
                    "Ipv6Ranges": [
                        {
                            "CidrIpv6": "::/0",
                        }
                    ],
                }
            ],
        }
    ]

    collector = SecurityGroupRuleCollector()

    result = collector.collect(security_groups)

    assert len(result) == 1
    assert result[0]["security_group_id"] == "sg-002"
    assert result[0]["rule"] == SecurityGroupRule(
        protocol="tcp",
        from_port=3389,
        to_port=3389,
        ipv6_cidr="::/0",
    )


def test_collect_converts_security_group_reference():
    security_groups = [
        {
            "GroupId": "sg-target",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 8080,
                    "ToPort": 8080,
                    "UserIdGroupPairs": [
                        {
                            "GroupId": "sg-source",
                        }
                    ],
                }
            ],
        }
    ]

    collector = SecurityGroupRuleCollector()

    result = collector.collect(security_groups)

    assert len(result) == 1
    assert result[0]["security_group_id"] == "sg-target"
    assert result[0]["rule"] == SecurityGroupRule(
        protocol="tcp",
        from_port=8080,
        to_port=8080,
        source_security_group_id="sg-source",
    )


def test_collect_multiple_rules():
    security_groups = [
        {
            "GroupId": "sg-web",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0",
                        }
                    ],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0",
                        }
                    ],
                },
            ],
        }
    ]

    collector = SecurityGroupRuleCollector()

    result = collector.collect(security_groups)

    assert len(result) == 2

    assert result[0]["security_group_id"] == "sg-web"
    assert result[0]["rule"].from_port == 22

    assert result[1]["security_group_id"] == "sg-web"
    assert result[1]["rule"].from_port == 443


def test_collect_multiple_security_groups():
    security_groups = [
        {
            "GroupId": "sg-001",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0",
                        }
                    ],
                }
            ],
        },
        {
            "GroupId": "sg-002",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3389,
                    "ToPort": 3389,
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0",
                        }
                    ],
                }
            ],
        },
    ]

    collector = SecurityGroupRuleCollector()

    result = collector.collect(security_groups)

    assert len(result) == 2
    assert result[0]["security_group_id"] == "sg-001"
    assert result[1]["security_group_id"] == "sg-002"


def test_collect_skips_security_group_without_id():
    security_groups = [
        {
            "GroupName": "invalid",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0",
                        }
                    ],
                }
            ],
        }
    ]

    collector = SecurityGroupRuleCollector()

    result = collector.collect(security_groups)

    assert result == []


def test_collect_empty_security_groups():
    collector = SecurityGroupRuleCollector()

    result = collector.collect([])

    assert result == []
