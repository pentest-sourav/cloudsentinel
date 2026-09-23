from engine.findings.model import Severity
from engine.rules.aws.vpc.default_security_group import (
    build_default_security_group_finding,
    check_default_security_group,
)


def test_default_security_group_flags_inbound_or_outbound_rules():
    result = check_default_security_group(
        group_id="sg-default",
        vpc_id="vpc-123",
        group_name="default",
        inbound_rule_count=1,
        outbound_rule_count=0,
    )

    assert result is not None
    assert result.group_id == "sg-default"


def test_default_security_group_allows_empty_group():
    result = check_default_security_group(
        group_id="sg-default",
        vpc_id="vpc-123",
        group_name="default",
        inbound_rule_count=0,
        outbound_rule_count=0,
    )

    assert result is None


def test_default_security_group_finding():
    result = check_default_security_group(
        group_id="sg-default",
        vpc_id="vpc-123",
        group_name="default",
        inbound_rule_count=1,
        outbound_rule_count=1,
    )

    finding = build_default_security_group_finding(result)

    assert finding.rule_id == "CS-AWS-VPC-003"
    assert finding.severity == Severity.HIGH
    assert finding.resource_type == "security_group"
    assert finding.resource_id == "sg-default"
