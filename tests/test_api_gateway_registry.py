from engine.rules.registry.api_gateway_handlers import (
    APIGATEWAY_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.api_gateway_registry import (
    APIGATEWAY_RULES,
)


def test_api_gateway_registry_contains_all_current_controls():
    rule_ids = {
        rule.rule_id
        for rule in APIGATEWAY_RULES.list_rules()
    }

    assert rule_ids == {
        "CS-AWS-APIGATEWAY-001",
        "CS-AWS-APIGATEWAY-002",
        "CS-AWS-APIGATEWAY-003",
        "CS-AWS-APIGATEWAY-004",
        "CS-AWS-APIGATEWAY-005",
        "CS-AWS-APIGATEWAY-008",
        "CS-AWS-APIGATEWAY-009",
        "CS-AWS-APIGATEWAY-010",
        "CS-AWS-APIGATEWAY-011",
    }


def test_api_gateway_registry_has_handlers_for_all_sources():
    sources = {
        rule.data_source
        for rule in APIGATEWAY_RULES.list_rules()
    }

    assert sources == set(
        APIGATEWAY_DATA_SOURCE_HANDLERS
    )
