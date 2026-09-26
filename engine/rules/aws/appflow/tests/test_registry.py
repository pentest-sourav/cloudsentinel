from engine.rules.registry.appflow_registry import (
    APPFLOW_RULES,
)


def test_appflow_registry_contains_appflow_1():
    rules = APPFLOW_RULES.list_rules()

    assert len(rules) == 1
    assert rules[0].rule_id == "CS-AWS-APPFLOW-001"
    assert rules[0].data_source == "appflow_flows"
    assert rules[0].collection_mode == "multiple"
