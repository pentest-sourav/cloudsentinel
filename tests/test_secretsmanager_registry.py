from engine.rules.registry.secretsmanager_handlers import (
    SECRETSMANAGER_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.secretsmanager_registry import (
    SECRETSMANAGER_RULES,
)


def test_secretsmanager_registry_contains_current_controls():
    assert [
        rule.rule_id
        for rule in SECRETSMANAGER_RULES.list_rules()
    ] == [
        "CS-AWS-SECRETSMANAGER-001",
        "CS-AWS-SECRETSMANAGER-003",
        "CS-AWS-SECRETSMANAGER-004",
        "CS-AWS-SECRETSMANAGER-005",
    ]


def test_secretsmanager_registry_has_handler_for_every_data_source():
    for rule in SECRETSMANAGER_RULES.list_rules():
        assert (
            rule.data_source
            in SECRETSMANAGER_DATA_SOURCE_HANDLERS
        )
