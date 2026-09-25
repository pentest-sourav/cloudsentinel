from engine.rules.registry.guardduty_handlers import (
    GUARDDUTY_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.guardduty_registry import (
    GUARDDUTY_RULES,
)


def test_guardduty_registry_contains_current_controls():
    assert [
        rule.rule_id
        for rule in GUARDDUTY_RULES.list_rules()
    ] == [
        "CS-AWS-GD-001",
        "CS-AWS-GD-005",
        "CS-AWS-GD-006",
        "CS-AWS-GD-007",
        "CS-AWS-GD-008",
        "CS-AWS-GD-009",
        "CS-AWS-GD-010",
        "CS-AWS-GD-011",
        "CS-AWS-GD-012",
        "CS-AWS-GD-013",
    ]


def test_guardduty_registry_has_handler_for_every_source():
    for rule in GUARDDUTY_RULES.list_rules():
        assert (
            rule.data_source
            in GUARDDUTY_DATA_SOURCE_HANDLERS
        )
