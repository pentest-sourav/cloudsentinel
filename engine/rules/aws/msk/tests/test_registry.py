from engine.rules.registry.msk_registry import MSK_RULES


def test_msk_registry_contains_expected_rules():
    assert [
        rule.rule_id
        for rule in MSK_RULES.rules
    ] == [
        "CS-AWS-MSK-001",
        "CS-AWS-MSK-002",
        "CS-AWS-MSK-003",
        "CS-AWS-MSK-004",
        "CS-AWS-MSK-005",
        "CS-AWS-MSK-006",
    ]
