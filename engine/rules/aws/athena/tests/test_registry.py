from engine.rules.registry.athena_registry import (
    ATHENA_RULES,
)


def test_athena_registry_contains_only_active_controls():
    rule_ids = [
        rule.rule_id
        for rule in ATHENA_RULES.rules
    ]

    assert rule_ids == [
        "CS-AWS-ATHENA-002",
        "CS-AWS-ATHENA-003",
        "CS-AWS-ATHENA-004",
    ]
