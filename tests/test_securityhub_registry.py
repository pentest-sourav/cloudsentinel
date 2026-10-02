from engine.rules.registry.securityhub_handlers import (
    SECURITYHUB_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.securityhub_registry import (
    SECURITYHUB_RULES,
)


def test_securityhub_registry_contains_current_controls():
    assert [
        rule.rule_id
        for rule in SECURITYHUB_RULES.list_rules()
    ] == [
        "CS-AWS-SH-001",
        "CS-AWS-SH-002",
    ]


def test_securityhub_registry_has_handler_for_every_source():
    for rule in SECURITYHUB_RULES.list_rules():
        assert (
            rule.data_source
            in SECURITYHUB_DATA_SOURCE_HANDLERS
        )
