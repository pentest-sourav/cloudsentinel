from engine.rules.registry.apprunner_registry import (
    APPRUNNER_RULES,
)


def test_apprunner_registry_contains_expected_rules():
    rules = list(APPRUNNER_RULES)

    rule_ids = {
        rule.rule_id
        for rule in rules
    }

    assert rule_ids == {
        "CS-AWS-APPRUNNER-001",
        "CS-AWS-APPRUNNER-002",
    }


def test_apprunner_registry_uses_expected_data_sources():
    rules = list(APPRUNNER_RULES)

    sources = {
        rule.data_source
        for rule in rules
    }

    assert sources == {
        "apprunner_services",
        "apprunner_vpc_connectors",
    }
