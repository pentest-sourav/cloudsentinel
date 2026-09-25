from engine.rules.registry.waf_handlers import (
    WAF_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.waf_registry import WAF_RULES


def test_waf_registry_contains_current_controls():
    assert [
        rule.rule_id
        for rule in WAF_RULES.list_rules()
    ] == [
        "CS-AWS-WAF-010",
        "CS-AWS-WAF-011",
        "CS-AWS-WAF-012",
    ]


def test_waf_registry_has_handler_for_every_data_source():
    for rule in WAF_RULES.list_rules():
        assert rule.data_source in WAF_DATA_SOURCE_HANDLERS
