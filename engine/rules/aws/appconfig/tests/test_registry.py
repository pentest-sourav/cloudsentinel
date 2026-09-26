from engine.rules.registry.appconfig_registry import (
    APPCONFIG_RULES,
)


def test_appconfig_registry_contains_four_active_controls():
    assert len(APPCONFIG_RULES) == 4

    assert [
        rule.rule_id
        for rule in APPCONFIG_RULES.list_rules()
    ] == [
        "CS-AWS-APPCONFIG-001",
        "CS-AWS-APPCONFIG-002",
        "CS-AWS-APPCONFIG-003",
        "CS-AWS-APPCONFIG-004",
    ]


def test_appconfig_registry_data_sources_are_correct():
    assert [
        rule.data_source
        for rule in APPCONFIG_RULES.list_rules()
    ] == [
        "appconfig_applications",
        "appconfig_configuration_profiles",
        "appconfig_environments",
        "appconfig_extension_associations",
    ]


def test_appconfig_rules_use_multiple_collection_mode():
    assert all(
        rule.collection_mode == "multiple"
        for rule in APPCONFIG_RULES.list_rules()
    )
