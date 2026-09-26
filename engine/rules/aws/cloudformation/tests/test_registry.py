from engine.rules.registry.cloudformation_registry import (
    CLOUDFORMATION_RULES,
)


def test_cloudformation_registry_contains_only_active_controls():
    assert [
        rule.rule_id
        for rule in CLOUDFORMATION_RULES.list_rules()
    ] == [
        "CS-AWS-CLOUDFORMATION-002",
        "CS-AWS-CLOUDFORMATION-003",
        "CS-AWS-CLOUDFORMATION-004",
    ]


def test_cloudformation_registry_uses_expected_data_source():
    assert [
        (
            rule.rule_id,
            rule.data_source,
            rule.collection_mode,
        )
        for rule in CLOUDFORMATION_RULES.list_rules()
    ] == [
        (
            "CS-AWS-CLOUDFORMATION-002",
            "cloudformation_stacks",
            "multiple",
        ),
        (
            "CS-AWS-CLOUDFORMATION-003",
            "cloudformation_stacks",
            "multiple",
        ),
        (
            "CS-AWS-CLOUDFORMATION-004",
            "cloudformation_stacks",
            "multiple",
        ),
    ]
