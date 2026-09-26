from engine.rules.registry.config_registry import CONFIG_RULES


def test_config_registry_contains_expected_rules():
    rules = CONFIG_RULES.list_rules()

    assert [
        rule.rule_id
        for rule in rules
    ] == [
        "CS-AWS-CONFIG-001",
        "CS-AWS-CONFIG-002",
    ]


def test_config_registry_uses_expected_data_sources():
    rules = CONFIG_RULES.list_rules()

    assert [
        (
            rule.rule_id,
            rule.data_source,
            rule.collection_mode,
        )
        for rule in rules
    ] == [
        (
            "CS-AWS-CONFIG-001",
            "config_account",
            "single",
        ),
        (
            "CS-AWS-CONFIG-002",
            "config_recorders",
            "multiple",
        ),
    ]
