from engine.rules.registry.acm_handlers import (
    ACM_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.acm_registry import (
    ACM_RULES,
)


def test_acm_registry_contains_current_controls():
    assert [
        rule.rule_id
        for rule in ACM_RULES.list_rules()
    ] == [
        "CS-AWS-ACM-001",
        "CS-AWS-ACM-002",
        "CS-AWS-ACM-003",
    ]


def test_acm_registry_has_handler_for_every_data_source():
    for rule in ACM_RULES.list_rules():
        assert (
            rule.data_source
            in ACM_DATA_SOURCE_HANDLERS
        )
