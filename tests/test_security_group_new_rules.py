from engine.rules.aws.security_groups.authorized_ports import (
    check_authorized_ports,
)
from engine.rules.aws.security_groups.high_risk_ports import (
    check_high_risk_ports,
)
from engine.rules.aws.security_groups.remote_admin_ipv4 import (
    check_remote_admin_ipv4,
)
from engine.rules.aws.security_groups.remote_admin_ipv6 import (
    check_remote_admin_ipv6,
)
from engine.rules.aws.security_groups.unused import (
    check_unused_security_group,
)


def rule(
    protocol="tcp",
    from_port=22,
    to_port=22,
    ipv4=None,
    ipv6=None,
):
    return {
        "IpProtocol": protocol,
        "FromPort": from_port,
        "ToPort": to_port,
        "IpRanges": [{"CidrIp": ipv4}] if ipv4 else [],
        "Ipv6Ranges": [{"CidrIpv6": ipv6}] if ipv6 else [],
    }


# EC2.18

def test_ec2_18_allows_unrestricted_https():
    assert check_authorized_ports(
        "sg-1", "web", rule(from_port=443, to_port=443, ipv4="0.0.0.0/0")
    ) is None


def test_ec2_18_allows_unrestricted_http():
    assert check_authorized_ports(
        "sg-1", "web", rule(from_port=80, to_port=80, ipv4="0.0.0.0/0")
    ) is None


def test_ec2_18_detects_unrestricted_ssh():
    result = check_authorized_ports(
        "sg-1", "web", rule(from_port=22, to_port=22, ipv4="0.0.0.0/0")
    )
    assert result is not None
    assert result.cidr == "0.0.0.0/0"


def test_ec2_18_detects_unrestricted_ipv6_ssh():
    result = check_authorized_ports(
        "sg-1", "web", rule(from_port=22, to_port=22, ipv6="::/0")
    )
    assert result is not None
    assert result.cidr == "::/0"


def test_ec2_18_detects_all_protocols():
    result = check_authorized_ports(
        "sg-1",
        "web",
        rule(protocol="-1", from_port=None, to_port=None, ipv4="0.0.0.0/0"),
    )
    assert result is not None


# EC2.19

def test_ec2_19_detects_high_risk_mysql():
    result = check_high_risk_ports(
        "sg-1", "db", rule(from_port=3306, to_port=3306, ipv4="0.0.0.0/0")
    )
    assert result is not None


def test_ec2_19_detects_high_risk_ipv6_rdp():
    result = check_high_risk_ports(
        "sg-1", "db", rule(from_port=3389, to_port=3389, ipv6="::/0")
    )
    assert result is not None


def test_ec2_19_ignores_safe_port():
    assert check_high_risk_ports(
        "sg-1", "web", rule(from_port=443, to_port=443, ipv4="0.0.0.0/0")
    ) is None


def test_ec2_19_detects_all_protocols():
    result = check_high_risk_ports(
        "sg-1",
        "web",
        rule(protocol="-1", from_port=None, to_port=None, ipv4="0.0.0.0/0"),
    )
    assert result is not None


# EC2.22

def test_ec2_22_detects_unused_security_group():
    result = check_unused_security_group(
        "sg-unused", "unused", 0, False
    )
    assert result is not None
    assert result.attached_eni_count == 0


def test_ec2_22_ignores_used_security_group():
    assert check_unused_security_group(
        "sg-used", "used", 1, False
    ) is None


def test_ec2_22_ignores_default_security_group():
    assert check_unused_security_group(
        "sg-default", "default", 0, True
    ) is None


# EC2.53

def test_ec2_53_detects_ipv4_ssh():
    result = check_remote_admin_ipv4(
        "sg-1", "admin", rule(from_port=22, to_port=22, ipv4="0.0.0.0/0")
    )
    assert result is not None


def test_ec2_53_detects_ipv4_rdp():
    result = check_remote_admin_ipv4(
        "sg-1", "admin", rule(from_port=3389, to_port=3389, ipv4="0.0.0.0/0")
    )
    assert result is not None


def test_ec2_53_ignores_restricted_source():
    assert check_remote_admin_ipv4(
        "sg-1", "admin", rule(from_port=22, to_port=22, ipv4="10.0.0.0/8")
    ) is None


# EC2.54

def test_ec2_54_detects_ipv6_ssh():
    result = check_remote_admin_ipv6(
        "sg-1", "admin", rule(from_port=22, to_port=22, ipv6="::/0")
    )
    assert result is not None


def test_ec2_54_detects_ipv6_rdp():
    result = check_remote_admin_ipv6(
        "sg-1", "admin", rule(from_port=3389, to_port=3389, ipv6="::/0")
    )
    assert result is not None


def test_ec2_54_ignores_restricted_source():
    assert check_remote_admin_ipv6(
        "sg-1", "admin", rule(from_port=22, to_port=22, ipv6="2001:db8::/32")
    ) is None
