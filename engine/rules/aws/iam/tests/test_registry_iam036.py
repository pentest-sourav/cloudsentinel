from engine.rules.registry.iam_registry import IAM_RULES


def test_iam036_is_registered():
    rule = next(
        rule
        for rule in IAM_RULES.rules
        if rule.rule_id == "CS-AWS-IAM-036"
    )

    assert rule.name == "access_analyzer_security_warning"
    assert rule.data_source == (
        "access_analyzer_policy_validation"
    )
    assert rule.collection_mode == "multiple"
    assert "finding_type" in rule.check_arguments
    assert "issue_code" in rule.check_arguments
