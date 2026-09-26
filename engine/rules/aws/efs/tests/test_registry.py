from engine.rules.registry.efs_handlers import (
    EFS_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.efs_registry import EFS_RULES


def test_efs_registry_contains_expected_rules():
    rule_ids = [
        rule.rule_id
        for rule in EFS_RULES.rules
    ]

    assert rule_ids == [
        "CS-AWS-EFS-001",
        "CS-AWS-EFS-002",
        "CS-AWS-EFS-003",
        "CS-AWS-EFS-004",
    ]


def test_efs_handlers_cover_all_data_sources():
    assert set(EFS_DATA_SOURCE_HANDLERS) == {
        "efs_file_systems",
        "efs_access_points",
    }
