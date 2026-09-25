from engine.rules.registry.kinesis_registry import KINESIS_RULES


def test_kinesis_registry_contains_expected_rules():
    assert len(KINESIS_RULES) == 3

    assert [
        rule.rule_id
        for rule in KINESIS_RULES.list_rules()
    ] == [
        "CS-AWS-KINESIS-001",
        "CS-AWS-KINESIS-002",
        "CS-AWS-KINESIS-003",
    ]


def test_kinesis_rule_data_sources():
    for rule_id in (
        "CS-AWS-KINESIS-001",
        "CS-AWS-KINESIS-002",
        "CS-AWS-KINESIS-003",
    ):
        assert (
            KINESIS_RULES
            .get_rule(rule_id)
            .data_source
            == "kinesis_streams"
        )
