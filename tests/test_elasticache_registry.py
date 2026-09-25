from engine.rules.registry.elasticache_registry import (
    ELASTICACHE_RULES,
)


def test_elasticache_registry_contains_all_seven_controls():
    rules = list(ELASTICACHE_RULES)

    assert len(rules) == 7

    assert [
        rule.rule_id
        for rule in rules
    ] == [
        "CS-AWS-ELASTICACHE-001",
        "CS-AWS-ELASTICACHE-002",
        "CS-AWS-ELASTICACHE-003",
        "CS-AWS-ELASTICACHE-004",
        "CS-AWS-ELASTICACHE-005",
        "CS-AWS-ELASTICACHE-006",
        "CS-AWS-ELASTICACHE-007",
    ]
