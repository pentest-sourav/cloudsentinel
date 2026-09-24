from engine.rules.registry.dynamodb_registry import (
    DYNAMODB_RULES,
)


def test_dynamodb_registry_contains_expected_rules():
    rules = DYNAMODB_RULES.list_rules()

    assert [rule.rule_id for rule in rules] == [
        "CS-AWS-DYNAMODB-001",
        "CS-AWS-DYNAMODB-002",
        "CS-AWS-DYNAMODB-003",
        "CS-AWS-DYNAMODB-004",
        "CS-AWS-DYNAMODB-005",
        "CS-AWS-DYNAMODB-006",
        "CS-AWS-DYNAMODB-007",
    ]


def test_dynamodb_registry_uses_expected_sources():
    rules = DYNAMODB_RULES.list_rules()

    assert rules[0].data_source == "dynamodb_tables"
    assert rules[1].data_source == "dynamodb_tables"
    assert rules[2].data_source == "dynamodb_dax_clusters"
    assert rules[3].data_source == "dynamodb_tables"
    assert rules[4].data_source == "dynamodb_tables"
    assert rules[5].data_source == "dynamodb_tables"
    assert rules[6].data_source == "dynamodb_dax_clusters"

    for rule in rules:
        assert rule.collection_mode == "multiple"
