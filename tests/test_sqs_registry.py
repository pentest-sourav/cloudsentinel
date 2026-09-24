from engine.rules.registry.sqs_registry import SQS_RULES


def test_sqs_registry_contains_expected_rules():
    rules = SQS_RULES.list_rules()

    assert [rule.rule_id for rule in rules] == [
        "CS-AWS-SQS-001",
        "CS-AWS-SQS-002",
        "CS-AWS-SQS-003",
    ]


def test_sqs_registry_uses_multiple_collection_mode():
    for rule in SQS_RULES.list_rules():
        assert rule.collection_mode == "multiple"
        assert rule.data_source == "sqs_queues"
