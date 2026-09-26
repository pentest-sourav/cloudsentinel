from engine.rules.registry.detective_registry import (
    DETECTIVE_RULES,
)


def test_detective_registry_contains_expected_control():
    rules = DETECTIVE_RULES.list_rules()

    assert [
        rule.rule_id
        for rule in rules
    ] == [
        "CS-AWS-DETECTIVE-001",
    ]


def test_detective_registry_uses_expected_data_source():
    rules = DETECTIVE_RULES.list_rules()

    assert rules[0].data_source == "graphs"
    assert rules[0].collection_mode == "multiple"


def test_detective_registry_has_expected_arguments():
    rules = DETECTIVE_RULES.list_rules()

    assert rules[0].check_arguments == [
        "resource_name",
        "resource_arn",
        "resource_type",
        "tag_data_available",
        "has_non_system_tags",
    ]
