from engine.rules.registry.ssm_registry import (
    SSM_RULES,
)


def test_ssm_registry_contains_expected_rules():
    rules = list(SSM_RULES)

    assert len(rules) == 6

    assert [
        rule.rule_id
        for rule in rules
    ] == [
        "CS-AWS-SSM-001",
        "CS-AWS-SSM-002",
        "CS-AWS-SSM-003",
        "CS-AWS-SSM-004",
        "CS-AWS-SSM-005",
        "CS-AWS-SSM-006",
    ]


def test_ssm_registry_data_sources_are_valid():
    rules = list(SSM_RULES)

    expected = {
        "CS-AWS-SSM-001": "ssm_ec2_management",
        "CS-AWS-SSM-002": "ssm_compliance",
        "CS-AWS-SSM-003": "ssm_compliance",
        "CS-AWS-SSM-004": "ssm_document_permissions",
        "CS-AWS-SSM-005": "ssm_automation_logging",
        "CS-AWS-SSM-006": "ssm_public_sharing_setting",
    }

    assert {
        rule.rule_id: rule.data_source
        for rule in rules
    } == expected
