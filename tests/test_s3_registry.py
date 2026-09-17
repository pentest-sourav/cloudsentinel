from engine.rules.registry.s3_registry import S3_RULES


EXPECTED_RULE_IDS = [
    "CS-AWS-S3-001",
    "CS-AWS-S3-002",
    "CS-AWS-S3-003",
    "CS-AWS-S3-004",
    "CS-AWS-S3-005",
    "CS-AWS-S3-006",
    "CS-AWS-S3-007",
    "CS-AWS-S3-008",
]


def test_s3_registry_contains_all_rules():
    rule_ids = [
        rule["rule_id"]
        for rule in S3_RULES
    ]

    assert rule_ids == EXPECTED_RULE_IDS


def test_s3_registry_rules_have_required_fields():
    for rule in S3_RULES:
        assert "rule_id" in rule
        assert "name" in rule
        assert "check" in rule
        assert "build_finding" in rule

        assert callable(rule["check"])
        assert callable(rule["build_finding"])


def test_s3_registry_rule_ids_are_unique():
    rule_ids = [
        rule["rule_id"]
        for rule in S3_RULES
    ]

    assert len(rule_ids) == len(set(rule_ids))

from pathlib import Path


def test_s3_scanner_does_not_contain_rule_dispatch_branches():
    scanner_source = Path(
        "scanner/aws/scanners/s3.py"
    ).read_text()

    assert 'if rule_name ==' not in scanner_source
    assert 'elif rule_name ==' not in scanner_source
