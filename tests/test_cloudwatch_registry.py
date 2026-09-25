from engine.rules.model import RuleDefinition
from engine.rules.registry.cloudwatch_registry import (
    CLOUDWATCH_RULES,
)


EXPECTED_RULE_IDS = {
    "CS-AWS-CLOUDWATCH-001",
    "CS-AWS-CLOUDWATCH-002",
    "CS-AWS-CLOUDWATCH-003",
}


def test_cloudwatch_registry_contains_expected_rules():
    rules = list(CLOUDWATCH_RULES)

    assert {
        rule.rule_id
        for rule in rules
    } == EXPECTED_RULE_IDS


def test_cloudwatch_registry_has_unique_rule_ids():
    rule_ids = [
        rule.rule_id
        for rule in CLOUDWATCH_RULES
    ]

    assert len(rule_ids) == len(set(rule_ids))


def test_cloudwatch_registry_contains_rule_definitions():
    for rule in CLOUDWATCH_RULES:
        assert isinstance(
            rule,
            RuleDefinition,
        )


def test_cloudwatch_registry_uses_valid_collection_modes():
    for rule in CLOUDWATCH_RULES:
        assert rule.collection_mode in {
            "single",
            "multiple",
        }


def test_cloudwatch_registry_uses_correct_data_sources():
    sources = {
        rule.rule_id: rule.data_source
        for rule in CLOUDWATCH_RULES
    }

    assert sources == {
        "CS-AWS-CLOUDWATCH-001": (
            "cloudwatch_alarms"
        ),
        "CS-AWS-CLOUDWATCH-002": (
            "cloudwatch_alarms"
        ),
        "CS-AWS-CLOUDWATCH-003": (
            "cloudwatch_log_groups"
        ),
    }
