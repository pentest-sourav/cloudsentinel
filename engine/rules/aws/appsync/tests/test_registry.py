from engine.rules.registry.appsync_handlers import (
    APPSYNC_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.appsync_registry import (
    APPSYNC_RULES,
)


def test_appsync_registry_contains_expected_rules():
    rule_ids = [
        rule.rule_id
        for rule in APPSYNC_RULES.rules
    ]

    assert rule_ids == [
        "CS-AWS-APPSYNC-002",
        "CS-AWS-APPSYNC-004",
        "CS-AWS-APPSYNC-005",
    ]


def test_appsync_handlers_cover_all_data_sources():
    assert set(APPSYNC_DATA_SOURCE_HANDLERS) == {
        "appsync_graphql_apis",
    }
