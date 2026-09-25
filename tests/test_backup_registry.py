from engine.rules.model import RuleDefinition
from engine.rules.registry.backup_registry import BACKUP_RULES


EXPECTED_RULE_IDS = {
    "CS-AWS-BACKUP-001",
    "CS-AWS-BACKUP-002",
    "CS-AWS-BACKUP-003",
    "CS-AWS-BACKUP-004",
}


def test_backup_registry_contains_all_rules():
    rule_ids = {
        rule.rule_id
        for rule in BACKUP_RULES
    }

    assert rule_ids == EXPECTED_RULE_IDS


def test_backup_registry_rules_have_required_fields():
    for rule in BACKUP_RULES:
        assert isinstance(rule, RuleDefinition)
        assert rule.rule_id
        assert rule.name
        assert rule.data_source
        assert rule.collection_mode
        assert rule.check_arguments
        assert callable(rule.check)
        assert callable(rule.build_finding)


def test_backup_registry_rule_ids_are_unique():
    rule_ids = [
        rule.rule_id
        for rule in BACKUP_RULES
    ]

    assert len(rule_ids) == len(set(rule_ids))


def test_backup_registry_collection_modes_are_valid():
    allowed_modes = {
        "single",
        "multiple",
    }

    for rule in BACKUP_RULES:
        assert rule.collection_mode in allowed_modes


def test_backup_registry_uses_expected_data_sources():
    sources = {
        rule.rule_id: rule.data_source
        for rule in BACKUP_RULES
    }

    assert sources == {
        "CS-AWS-BACKUP-001": "backup_recovery_points",
        "CS-AWS-BACKUP-002": "backup_plans",
        "CS-AWS-BACKUP-003": "backup_plans",
        "CS-AWS-BACKUP-004": "backup_vaults",
    }
