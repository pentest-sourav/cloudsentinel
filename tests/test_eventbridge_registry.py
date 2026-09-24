from engine.rules.registry.eventbridge_registry import (
    EVENTBRIDGE_RULES,
)


def test_eventbridge_registry_contains_expected_rules():
    rules = EVENTBRIDGE_RULES.list_rules()

    assert [rule.rule_id for rule in rules] == [
        "CS-AWS-EVENTBRIDGE-002",
        "CS-AWS-EVENTBRIDGE-003",
        "CS-AWS-EVENTBRIDGE-004",
    ]


def test_eventbridge_registry_uses_expected_sources():
    rules = EVENTBRIDGE_RULES.list_rules()

    assert rules[0].data_source == "eventbridge_event_buses"
    assert rules[1].data_source == "eventbridge_event_buses"
    assert rules[2].data_source == "eventbridge_global_endpoints"

    for rule in rules:
        assert rule.collection_mode == "multiple"
