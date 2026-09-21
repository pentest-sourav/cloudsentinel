from engine.rules.model import RuleDefinition
from engine.rules.registry.iam_registry import IAM_RULES


def test_iam_registry_contains_root_mfa_rule():
    rule_ids = [rule.rule_id for rule in IAM_RULES]

    assert "CS-AWS-IAM-001" in rule_ids
    assert "CS-AWS-IAM-002" in rule_ids


def test_iam_registry_contains_multiple_active_access_keys_rule():
    rule_ids = [rule.rule_id for rule in IAM_RULES]

    assert "CS-AWS-IAM-017" in rule_ids


def test_iam_registry_contains_multiple_authentication_methods_rule():
    rule_ids = [rule.rule_id for rule in IAM_RULES]

    assert "CS-AWS-IAM-018" in rule_ids


def test_iam_registry_contains_access_key_never_used_rule():
    rule_ids = [rule.rule_id for rule in IAM_RULES]

    assert "CS-AWS-IAM-019" in rule_ids


def test_iam_registry_contains_no_active_authentication_credential_rule():
    rule_ids = [rule.rule_id for rule in IAM_RULES]

    assert "CS-AWS-IAM-020" in rule_ids


def test_iam_registry_contains_root_access_key_rule():
    rule_ids = [rule.rule_id for rule in IAM_RULES]

    assert "CS-AWS-IAM-021" in rule_ids


def test_iam_registry_contains_user_attached_policy_rule():
    rule_ids = [rule.rule_id for rule in IAM_RULES]

    assert "CS-AWS-IAM-022" in rule_ids


def test_iam_registry_has_required_fields():
    for rule in IAM_RULES:
        assert isinstance(rule, RuleDefinition)

        assert rule.rule_id
        assert rule.name
        assert rule.data_source
        assert rule.collection_mode
        assert rule.check_arguments
        assert callable(rule.check)
        assert callable(rule.build_finding)


def test_iam_registry_rule_ids_are_unique():
    rule_ids = [rule.rule_id for rule in IAM_RULES]

    assert len(rule_ids) == len(set(rule_ids))


def test_iam_rules_have_valid_data_sources():
    allowed_data_sources = {
        "root_mfa",
        "root_access_key",
        "user_attached_policies",
        "iam_users",
        "iam_access_keys",
        "password_policy",
        "credential_report",
        "broad_user_policies",
        "broad_group_policies",
        "broad_user_inline_policies",
        "broad_group_inline_policies",
        "broad_action_restricted_resources",
        "multiple_active_access_keys",
        "multiple_authentication_methods",
        "access_key_last_used",
        "no_active_authentication_credentials",
    }

    for rule in IAM_RULES:
        assert rule.data_source in allowed_data_sources


def test_iam_rules_have_valid_collection_modes():
    allowed_modes = {
        "single",
        "multiple",
    }

    for rule in IAM_RULES:
        assert rule.collection_mode in allowed_modes
