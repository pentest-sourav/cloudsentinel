from engine.rules.registry.eks_handlers import (
    EKS_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.eks_registry import EKS_RULES


def test_eks_registry_contains_current_controls():
    assert [
        rule.rule_id
        for rule in EKS_RULES.list_rules()
    ] == [
        "CS-AWS-EKS-001",
        "CS-AWS-EKS-002",
        "CS-AWS-EKS-006",
        "CS-AWS-EKS-007",
        "CS-AWS-EKS-008",
        "CS-AWS-EKS-009",
    ]


def test_eks_registry_has_handler_for_every_data_source():
    for rule in EKS_RULES.list_rules():
        assert rule.data_source in EKS_DATA_SOURCE_HANDLERS
