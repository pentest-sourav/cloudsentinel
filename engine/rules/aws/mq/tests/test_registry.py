from engine.rules.registry.mq_handlers import (
    MQ_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.mq_registry import MQ_RULES


def test_mq_registry_contains_expected_rules():
    rule_ids = [
        rule.rule_id
        for rule in MQ_RULES.rules
    ]

    assert rule_ids == [
        "CS-AWS-MQ-002",
        "CS-AWS-MQ-004",
        "CS-AWS-MQ-005",
        "CS-AWS-MQ-006",
    ]


def test_mq_handlers_cover_all_data_sources():
    assert set(MQ_DATA_SOURCE_HANDLERS) == {
        "mq_brokers",
    }
