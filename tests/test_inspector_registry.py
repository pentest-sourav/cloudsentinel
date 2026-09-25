from engine.rules.registry.inspector_registry import (
    INSPECTOR_RULES,
)


def test_inspector_registry_contains_expected_rules():
    rule_ids = {
        rule.rule_id
        for rule in INSPECTOR_RULES.rules
    }

    assert rule_ids == {
        "CS-AWS-INSPECTOR-001",
        "CS-AWS-INSPECTOR-002",
        "CS-AWS-INSPECTOR-003",
        "CS-AWS-INSPECTOR-004",
    }


def test_inspector_rules_use_account_data_source():
    for rule in INSPECTOR_RULES.rules:
        assert rule.data_source == "inspector_account"
        assert rule.collection_mode == "multiple"
