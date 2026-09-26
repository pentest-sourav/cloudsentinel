from engine.findings.model import Severity
from engine.rules.aws.network_firewall.protection import (
    build_deletion_protection_finding,
    build_default_fragment_action_finding,
    build_default_full_packet_action_finding,
    build_logging_finding,
    build_multi_az_finding,
    build_policy_rule_group_finding,
    build_stateless_rule_group_not_empty_finding,
    build_subnet_change_protection_finding,
    check_deletion_protection,
    check_default_fragment_action,
    check_default_full_packet_action,
    check_logging,
    check_multi_az,
    check_policy_rule_group,
    check_stateless_rule_group_not_empty,
    check_subnet_change_protection,
)


def test_multi_az_passes_with_two_zones():
    assert check_multi_az(
        "arn:fw",
        2,
        ["ap-south-1a", "ap-south-1b"],
    ) is None


def test_multi_az_fails_with_one_zone():
    result = check_multi_az(
        "arn:fw",
        1,
        ["ap-south-1a"],
    )

    finding = build_multi_az_finding(result)

    assert finding.rule_id == "CS-AWS-NETWORKFIREWALL-001"
    assert finding.severity == Severity.MEDIUM


def test_logging_passes_when_enabled():
    assert check_logging(
        "arn:fw",
        True,
        1,
    ) is None


def test_logging_fails_when_disabled():
    result = check_logging(
        "arn:fw",
        False,
        0,
    )

    finding = build_logging_finding(result)

    assert finding.rule_id == "CS-AWS-NETWORKFIREWALL-002"


def test_policy_rule_group_passes_when_group_exists():
    assert check_policy_rule_group(
        "arn:policy",
        True,
        1,
        0,
    ) is None


def test_policy_rule_group_fails_when_no_group_exists():
    result = check_policy_rule_group(
        "arn:policy",
        False,
        0,
        0,
    )

    finding = build_policy_rule_group_finding(result)

    assert finding.rule_id == "CS-AWS-NETWORKFIREWALL-003"


def test_full_packet_drop_passes():
    assert check_default_full_packet_action(
        "arn:policy",
        ["aws:drop"],
    ) is None


def test_full_packet_forward_passes():
    assert check_default_full_packet_action(
        "arn:policy",
        ["aws:forward_to_sfe"],
    ) is None


def test_full_packet_pass_action_fails():
    result = check_default_full_packet_action(
        "arn:policy",
        ["aws:pass"],
    )

    finding = build_default_full_packet_action_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-NETWORKFIREWALL-004"


def test_fragment_drop_passes():
    assert check_default_fragment_action(
        "arn:policy",
        ["aws:drop"],
    ) is None


def test_fragment_forward_passes():
    assert check_default_fragment_action(
        "arn:policy",
        ["aws:forward_to_sfe"],
    ) is None


def test_fragment_pass_action_fails():
    result = check_default_fragment_action(
        "arn:policy",
        ["aws:pass"],
    )

    finding = build_default_fragment_action_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-NETWORKFIREWALL-005"


def test_stateless_rule_group_with_rules_passes():
    assert check_stateless_rule_group_not_empty(
        "arn:group",
        1,
    ) is None


def test_empty_stateless_rule_group_fails():
    result = check_stateless_rule_group_not_empty(
        "arn:group",
        0,
    )

    finding = build_stateless_rule_group_not_empty_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-NETWORKFIREWALL-006"


def test_deletion_protection_passes():
    assert check_deletion_protection(
        "arn:fw",
        True,
    ) is None


def test_deletion_protection_fails():
    result = check_deletion_protection(
        "arn:fw",
        False,
    )

    finding = build_deletion_protection_finding(result)

    assert finding.rule_id == "CS-AWS-NETWORKFIREWALL-009"


def test_subnet_change_protection_passes():
    assert check_subnet_change_protection(
        "arn:fw",
        True,
    ) is None


def test_subnet_change_protection_fails():
    result = check_subnet_change_protection(
        "arn:fw",
        False,
    )

    finding = build_subnet_change_protection_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-NETWORKFIREWALL-010"
