from engine.findings.model import Finding, Severity
from engine.rules.aws.ec2.security_group_exposure import (
    SecurityGroupExposureResult,
    build_security_group_exposure_finding,
)
from scanner.aws.models.security_group import SecurityGroupRule


def test_build_ssh_exposure_finding():
    rule = SecurityGroupRule(
        protocol="tcp",
        from_port=22,
        to_port=22,
        ipv4_cidr="0.0.0.0/0",
    )

    result = SecurityGroupExposureResult(
        security_group_id="sg-123",
        rule=rule,
        exposure_type="ssh_port_range",
        management_service="SSH",
    )

    finding = build_security_group_exposure_finding(result)

    assert isinstance(finding, Finding)
    assert finding.rule_id == "CS-AWS-EC2-001"
    assert finding.title == "SSH Port Exposed to the Internet"
    assert finding.severity == Severity.HIGH
    assert finding.provider == "aws"
    assert finding.resource_type == "ec2_security_group"
    assert finding.resource_id == "sg-123"


def test_finding_contains_network_evidence():
    rule = SecurityGroupRule(
        protocol="tcp",
        from_port=22,
        to_port=22,
        ipv4_cidr="0.0.0.0/0",
    )

    result = SecurityGroupExposureResult(
        security_group_id="sg-evidence",
        rule=rule,
        exposure_type="ssh_port_range",
        management_service="SSH",
    )

    finding = build_security_group_exposure_finding(result)

    assert finding.evidence["security_group_id"] == "sg-evidence"
    assert finding.evidence["protocol"] == "tcp"
    assert finding.evidence["from_port"] == 22
    assert finding.evidence["to_port"] == 22
    assert finding.evidence["ipv4_cidr"] == "0.0.0.0/0"
    assert finding.evidence["source"] == "0.0.0.0/0"
    assert finding.evidence["exposure_type"] == "ssh_port_range"
    assert finding.evidence["management_service"] == "SSH"


def test_build_rdp_exposure_finding():
    rule = SecurityGroupRule(
        protocol="tcp",
        from_port=3389,
        to_port=3389,
        ipv6_cidr="::/0",
    )

    result = SecurityGroupExposureResult(
        security_group_id="sg-rdp",
        rule=rule,
        exposure_type="rdp_port_range",
        management_service="RDP",
    )

    finding = build_security_group_exposure_finding(result)

    assert finding.title == "RDP Port Exposed to the Internet"
    assert finding.severity == Severity.HIGH
    assert finding.evidence["source"] == "::/0"
    assert finding.evidence["ipv6_cidr"] == "::/0"


def test_build_all_ports_exposure_finding():
    rule = SecurityGroupRule(
        protocol="-1",
        from_port=None,
        to_port=None,
        ipv4_cidr="0.0.0.0/0",
    )

    result = SecurityGroupExposureResult(
        security_group_id="sg-all",
        rule=rule,
        exposure_type="all_ports",
        management_service=None,
    )

    finding = build_security_group_exposure_finding(result)

    assert finding.title == "Management Ports Exposed to the Internet"
    assert finding.evidence["source"] == "0.0.0.0/0"
    assert finding.evidence["exposure_type"] == "all_ports"
    assert finding.evidence["from_port"] is None
    assert finding.evidence["to_port"] is None


def test_finding_has_remediation():
    rule = SecurityGroupRule(
        protocol="tcp",
        from_port=22,
        to_port=22,
        ipv4_cidr="0.0.0.0/0",
    )

    result = SecurityGroupExposureResult(
        security_group_id="sg-remediation",
        rule=rule,
        exposure_type="ssh_port_range",
        management_service="SSH",
    )

    finding = build_security_group_exposure_finding(result)

    assert finding.remediation
    assert "trusted source" in finding.remediation


def test_finding_has_compliance_mapping():
    rule = SecurityGroupRule(
        protocol="tcp",
        from_port=3389,
        to_port=3389,
        ipv4_cidr="0.0.0.0/0",
    )

    result = SecurityGroupExposureResult(
        security_group_id="sg-compliance",
        rule=rule,
        exposure_type="rdp_port_range",
        management_service="RDP",
    )

    finding = build_security_group_exposure_finding(result)

    assert "CIS AWS Foundations" in finding.compliance
