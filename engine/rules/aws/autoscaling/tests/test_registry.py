from engine.rules.registry.autoscaling_registry import (
    AUTOSCALING_RULES,
)


def test_autoscaling_registry_contains_only_active_controls():
    rule_ids = [
        rule.rule_id
        for rule in AUTOSCALING_RULES.rules
    ]

    assert rule_ids == [
        "CS-AWS-AUTOSCALING-001",
        "CS-AWS-AUTOSCALING-002",
        "CS-AWS-AUTOSCALING-003",
        "CS-AWS-AUTOSCALING-005",
        "CS-AWS-AUTOSCALING-006",
        "CS-AWS-AUTOSCALING-009",
        "CS-AWS-AUTOSCALING-010",
    ]


def test_autoscaling_registry_has_valid_rule_contracts():
    for rule in AUTOSCALING_RULES.rules:
        assert rule.data_source == "autoscaling_groups"
        assert rule.collection_mode == "multiple"
        assert callable(rule.check)
        assert callable(rule.build_finding)
        assert rule.check_arguments
