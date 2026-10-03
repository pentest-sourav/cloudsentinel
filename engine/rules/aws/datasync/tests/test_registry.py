from engine.rules.registry.datasync_registry import (
    DATASYNC_RULES,
)


def test_datasync_registry_contains_expected_controls():
    rules = DATASYNC_RULES.list_rules()

    assert [
        rule.rule_id
        for rule in rules
    ] == [
        "CS-AWS-DATASYNC-001",
        "CS-AWS-DATASYNC-002",
    ]


def test_datasync_registry_maps_expected_data_sources():
    rules = DATASYNC_RULES.list_rules()

    assert [
        rule.data_source
        for rule in rules
    ] == [
        "tasks",
        "tasks",
    ]


def test_datasync_registry_uses_multiple_collection_mode():
    rules = DATASYNC_RULES.list_rules()

    assert all(
        rule.collection_mode == "multiple"
        for rule in rules
    )


def test_datasync_registry_has_expected_arguments():
    rules = DATASYNC_RULES.list_rules()

    assert rules[0].check_arguments == [
        "resource_name",
        "resource_arn",
        "resource_type",
        "task_mode",
        "log_level",
        "cloudwatch_log_group_arn",
    ]

    assert rules[1].check_arguments == [
        "resource_name",
        "resource_arn",
        "resource_type",
        "tag_data_available",
        "has_non_system_tags",
        "tags",
    ]
