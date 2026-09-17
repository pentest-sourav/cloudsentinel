from engine.rules.model import RuleDefinition


def test_rule_definition_stores_rule_metadata():
    def check(**kwargs):
        return kwargs

    def build_finding(result):
        return result

    rule = RuleDefinition(
        rule_id="CS-TEST-001",
        name="test_rule",
        data_source="test_source",
        collection_mode="single",
        check_arguments=["value"],
        check=check,
        build_finding=build_finding,
    )

    assert rule.rule_id == "CS-TEST-001"
    assert rule.name == "test_rule"
    assert rule.data_source == "test_source"
    assert rule.collection_mode == "single"
    assert rule.check_arguments == ["value"]
    assert rule.check is check
    assert rule.build_finding is build_finding


def test_rule_definition_supports_multiple_collection_mode():
    rule = RuleDefinition(
        rule_id="CS-TEST-002",
        name="multiple_rule",
        data_source="users",
        collection_mode="multiple",
        check_arguments=["username"],
        check=lambda **kwargs: kwargs,
        build_finding=lambda result: result,
    )

    assert rule.collection_mode == "multiple"
