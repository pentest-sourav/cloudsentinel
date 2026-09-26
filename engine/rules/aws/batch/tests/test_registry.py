from engine.rules.registry.batch_registry import (
    BATCH_RULES,
)


def test_batch_registry_contains_all_security_hub_controls():
    assert [
        rule.rule_id
        for rule in BATCH_RULES.rules
    ] == [
        "CS-AWS-BATCH-001",
        "CS-AWS-BATCH-002",
        "CS-AWS-BATCH-003",
        "CS-AWS-BATCH-004",
    ]
