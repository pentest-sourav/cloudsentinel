from engine.rules.registry.elb_handlers import (
    ELB_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.elb_registry import ELB_RULES


def test_elb_registry_contains_expected_rules():
    rule_ids = [
        rule.rule_id
        for rule in ELB_RULES.rules
    ]

    assert rule_ids == [
        "CS-AWS-ELB-001",
        "CS-AWS-ELB-002",
        "CS-AWS-ELB-003",
        "CS-AWS-ELB-004",
        "CS-AWS-ELB-005",
        "CS-AWS-ELB-006",
        "CS-AWS-ELB-007",
        "CS-AWS-ELB-008",
        "CS-AWS-ELB-009",
    ]


def test_elb_handlers_cover_all_data_sources():
    assert set(ELB_DATA_SOURCE_HANDLERS) == {
        "elb_load_balancers",
    }
