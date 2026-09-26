from engine.rules.registry.codebuild_registry import (
    CODEBUILD_RULES,
)


def test_codebuild_registry_contains_all_active_controls():
    rule_ids = {
        rule.rule_id
        for rule in CODEBUILD_RULES.rules
    }

    assert rule_ids == {
        "CS-AWS-CODEBUILD-001",
        "CS-AWS-CODEBUILD-002",
        "CS-AWS-CODEBUILD-003",
        "CS-AWS-CODEBUILD-004",
        "CS-AWS-CODEBUILD-005",
    }


def test_codebuild_registry_does_not_include_retired_control():
    rule_ids = {
        rule.rule_id
        for rule in CODEBUILD_RULES.rules
    }

    assert not any(
        rule_id.endswith("-006")
        for rule_id in rule_ids
    )
