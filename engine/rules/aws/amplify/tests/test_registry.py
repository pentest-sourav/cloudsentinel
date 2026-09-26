from engine.rules.registry.amplify_registry import (
    AMPLIFY_RULES,
)


def test_amplify_registry_contains_expected_rules():
    rules = list(AMPLIFY_RULES)

    rule_ids = {
        rule.rule_id
        for rule in rules
    }

    assert rule_ids == {
        "CS-AWS-AMPLIFY-001",
        "CS-AWS-AMPLIFY-002",
    }


def test_amplify_registry_uses_expected_data_sources():
    rules = list(AMPLIFY_RULES)

    sources = {
        rule.data_source
        for rule in rules
    }

    assert sources == {
        "amplify_apps",
        "amplify_branches",
    }
