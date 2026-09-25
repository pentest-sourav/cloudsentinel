from engine.rules.registry.opensearch_registry import (
    OPENSEARCH_RULES,
)


def test_opensearch_registry_contains_expected_rules():
    rules = OPENSEARCH_RULES.list_rules()

    assert [rule.rule_id for rule in rules] == [
        "CS-AWS-OPENSEARCH-001",
        "CS-AWS-OPENSEARCH-002",
        "CS-AWS-OPENSEARCH-003",
        "CS-AWS-OPENSEARCH-004",
        "CS-AWS-OPENSEARCH-005",
        "CS-AWS-OPENSEARCH-006",
        "CS-AWS-OPENSEARCH-007",
        "CS-AWS-OPENSEARCH-008",
        "CS-AWS-OPENSEARCH-009",
        "CS-AWS-OPENSEARCH-010",
        "CS-AWS-OPENSEARCH-011",
    ]


def test_opensearch_registry_uses_expected_source():
    rules = OPENSEARCH_RULES.list_rules()

    for rule in rules:
        assert rule.data_source == "opensearch_domains"
        assert rule.collection_mode == "multiple"
