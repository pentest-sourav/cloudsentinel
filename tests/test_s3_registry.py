from engine.rules.model import RuleDefinition
from engine.rules.registry.s3_registry import S3_RULES


EXPECTED_RULE_IDS = {
    "CS-AWS-S3-001",
    "CS-AWS-S3-002",
    "CS-AWS-S3-003",
    "CS-AWS-S3-004",
    "CS-AWS-S3-005",
    "CS-AWS-S3-006",
    "CS-AWS-S3-007",
    "CS-AWS-S3-008",
    "CS-AWS-S3-009",
}


def test_s3_registry_contains_all_rules():
    rule_ids = {
        rule.rule_id
        for rule in S3_RULES
    }

    assert rule_ids == EXPECTED_RULE_IDS


def test_s3_registry_rules_have_required_fields():
    for rule in S3_RULES:
        assert isinstance(rule, RuleDefinition)

        assert rule.rule_id
        assert rule.name
        assert rule.data_source
        assert rule.collection_mode
        assert rule.check_arguments
        assert callable(rule.check)
        assert callable(rule.build_finding)


def test_s3_registry_rule_ids_are_unique():
    rule_ids = [
        rule.rule_id
        for rule in S3_RULES
    ]

    assert len(rule_ids) == len(set(rule_ids))


def test_s3_registry_collection_modes_are_valid():
    allowed_modes = {
        "single",
        "multiple",
    }

    for rule in S3_RULES:
        assert rule.collection_mode in allowed_modes
