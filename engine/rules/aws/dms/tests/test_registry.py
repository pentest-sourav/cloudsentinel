from engine.rules.registry.dms_registry import DMS_RULES


def test_dms_registry_contains_all_controls():
    assert [
        rule.rule_id
        for rule in DMS_RULES.rules
    ] == [
        "CS-AWS-DMS-001",
        "CS-AWS-DMS-002",
        "CS-AWS-DMS-003",
        "CS-AWS-DMS-004",
        "CS-AWS-DMS-005",
        "CS-AWS-DMS-006",
        "CS-AWS-DMS-007",
        "CS-AWS-DMS-008",
        "CS-AWS-DMS-009",
        "CS-AWS-DMS-010",
        "CS-AWS-DMS-011",
        "CS-AWS-DMS-012",
        "CS-AWS-DMS-013",
    ]
