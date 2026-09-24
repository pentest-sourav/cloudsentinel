from engine.rules.registry.sns_registry import SNS_RULES


def test_sns_registry_contains_expected_rules():
    rules = SNS_RULES.list_rules()

    assert [rule.rule_id for rule in rules] == [
        "CS-AWS-SNS-001",
        "CS-AWS-SNS-002",
        "CS-AWS-SNS-003",
        "CS-AWS-SNS-004",
    ]


def test_sns_registry_uses_multiple_collection_mode():
    for rule in SNS_RULES.list_rules():
        assert rule.collection_mode == "multiple"
        assert rule.data_source == "sns_security"
