from engine.rules.registry.stepfunctions_registry import (
    STEPFUNCTIONS_RULES,
)


def test_stepfunctions_registry_contains_expected_rules():
    rules = STEPFUNCTIONS_RULES.list_rules()

    assert [rule.rule_id for rule in rules] == [
        "CS-AWS-SFN-001",
        "CS-AWS-SFN-002",
    ]


def test_stepfunctions_registry_uses_expected_sources():
    rules = STEPFUNCTIONS_RULES.list_rules()

    assert rules[0].data_source == (
        "stepfunctions_state_machines"
    )
    assert rules[1].data_source == (
        "stepfunctions_activities"
    )

    for rule in rules:
        assert rule.collection_mode == "multiple"
