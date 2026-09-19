from engine.rules.aws.security_groups.unrestricted_inbound import (
    check_unrestricted_inbound,
)


def test_detects_ipv4_unrestricted_inbound():
    rule = {
        "IpProtocol": "-1",
        "IpRanges": [
            {"CidrIp": "0.0.0.0/0"},
        ],
        "Ipv6Ranges": [],
    }

    result = check_unrestricted_inbound(
        group_id="sg-test",
        group_name="test",
        inbound_rule=rule,
    )

    assert result is not None
    assert result.group_id == "sg-test"
    assert result.cidr == "0.0.0.0/0"


def test_detects_ipv6_unrestricted_inbound():
    rule = {
        "IpProtocol": "-1",
        "IpRanges": [],
        "Ipv6Ranges": [
            {"CidrIpv6": "::/0"},
        ],
    }

    result = check_unrestricted_inbound(
        group_id="sg-test",
        group_name="test",
        inbound_rule=rule,
    )

    assert result is not None
    assert result.cidr == "::/0"


def test_ignores_restricted_cidr():
    rule = {
        "IpProtocol": "-1",
        "IpRanges": [
            {"CidrIp": "10.0.0.0/16"},
        ],
        "Ipv6Ranges": [],
    }

    result = check_unrestricted_inbound(
        group_id="sg-test",
        group_name="test",
        inbound_rule=rule,
    )

    assert result is None


def test_ignores_security_group_source():
    rule = {
        "IpProtocol": "-1",
        "IpRanges": [],
        "Ipv6Ranges": [],
        "UserIdGroupPairs": [
            {"GroupId": "sg-other"},
        ],
    }

    result = check_unrestricted_inbound(
        group_id="sg-test",
        group_name="test",
        inbound_rule=rule,
    )

    assert result is None

def test_builds_unrestricted_inbound_finding():
    from engine.rules.aws.security_groups.unrestricted_inbound import (
        UnrestrictedInboundResult,
        build_unrestricted_inbound_finding,
    )

    result = UnrestrictedInboundResult(
        group_id="sg-test",
        group_name="web-sg",
        cidr="0.0.0.0/0",
    )

    finding = build_unrestricted_inbound_finding(result)

    assert finding.rule_id == "CS-AWS-SG-001"
    assert finding.severity.value == "high"
    assert finding.provider == "aws"
    assert finding.resource_type == "security_group"
    assert finding.resource_id == "sg-test"
    assert finding.evidence["cidr"] == "0.0.0.0/0"
    assert finding.evidence["group_name"] == "web-sg"
    assert "CIS AWS Foundations" in finding.compliance
