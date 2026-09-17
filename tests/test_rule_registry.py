import pytest

from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


def dummy_check(**kwargs):
    return kwargs


def dummy_build_finding(result):
    return result


def make_rule(rule_id: str) -> RuleDefinition:
    return RuleDefinition(
        rule_id=rule_id,
        name=f"rule-{rule_id}",
        data_source="test_source",
        collection_mode="single",
        check_arguments=["value"],
        check=dummy_check,
        build_finding=dummy_build_finding,
    )


def test_registry_stores_rules():
    rules = [
        make_rule("TEST-001"),
        make_rule("TEST-002"),
    ]

    registry = RuleRegistry(rules)

    assert len(registry) == 2
    assert registry.list_rules() == rules


def test_registry_get_rule():
    rule = make_rule("TEST-001")
    registry = RuleRegistry([rule])

    result = registry.get_rule("TEST-001")

    assert result is rule


def test_registry_rejects_duplicate_rule_ids():
    rules = [
        make_rule("TEST-001"),
        make_rule("TEST-001"),
    ]

    with pytest.raises(
        ValueError,
        match="Duplicate rule ID: TEST-001",
    ):
        RuleRegistry(rules)


def test_registry_rejects_unknown_rule():
    registry = RuleRegistry(
        [make_rule("TEST-001")]
    )

    with pytest.raises(
        KeyError,
        match="Rule not found: TEST-999",
    ):
        registry.get_rule("TEST-999")
