from engine.rules.registry.iam_registry import IAM_RULES


def test_iam_registry_contains_password_policy_symbols_rule():
    rule = IAM_RULES.get_rule("CS-AWS-IAM-006")

    assert rule is not None
    assert rule.rule_id == "CS-AWS-IAM-006"
    assert rule.name == "password_policy_symbols"
    assert rule.data_source == "password_policy"
    assert rule.collection_mode == "single"


def test_iam_registry_password_policy_symbols_rule_has_expected_arguments():
    rule = IAM_RULES.get_rule("CS-AWS-IAM-006")

    assert rule.check_arguments == [
        "require_symbols",
    ]


def test_iam_registry_password_policy_symbols_rule_has_check_and_finding_builder():
    rule = IAM_RULES.get_rule("CS-AWS-IAM-006")

    assert callable(rule.check)
    assert callable(rule.build_finding)


def test_iam_registry_contains_password_policy_numbers_rule():
    rule = IAM_RULES.get_rule("CS-AWS-IAM-007")

    assert rule is not None
    assert rule.rule_id == "CS-AWS-IAM-007"
    assert rule.name == "password_policy_numbers"
    assert rule.data_source == "password_policy"
    assert rule.collection_mode == "single"


def test_iam_registry_password_policy_numbers_rule_has_expected_arguments():
    rule = IAM_RULES.get_rule("CS-AWS-IAM-007")

    assert rule.check_arguments == [
        "require_numbers",
    ]


def test_iam_registry_password_policy_numbers_rule_has_check_and_finding_builder():
    rule = IAM_RULES.get_rule("CS-AWS-IAM-007")

    assert callable(rule.check)
    assert callable(rule.build_finding)


def test_iam_registry_contains_password_policy_uppercase_rule():
    rule = IAM_RULES.get_rule("CS-AWS-IAM-008")

    assert rule is not None
    assert rule.rule_id == "CS-AWS-IAM-008"
    assert rule.name == "password_policy_uppercase"
    assert rule.data_source == "password_policy"
    assert rule.collection_mode == "single"


def test_iam_registry_password_policy_uppercase_rule_has_expected_arguments():
    rule = IAM_RULES.get_rule("CS-AWS-IAM-008")

    assert rule.check_arguments == [
        "require_uppercase",
    ]


def test_iam_registry_password_policy_uppercase_rule_has_check_and_finding_builder():
    rule = IAM_RULES.get_rule("CS-AWS-IAM-008")

    assert callable(rule.check)
    assert callable(rule.build_finding)


def test_iam_registry_contains_password_policy_lowercase_rule():
    rule = IAM_RULES.get_rule("CS-AWS-IAM-009")

    assert rule is not None
    assert rule.rule_id == "CS-AWS-IAM-009"
    assert rule.name == "password_policy_lowercase"
    assert rule.data_source == "password_policy"
    assert rule.collection_mode == "single"


def test_iam_registry_password_policy_lowercase_rule_has_expected_arguments():
    rule = IAM_RULES.get_rule("CS-AWS-IAM-009")

    assert rule.check_arguments == [
        "require_lowercase",
    ]


def test_iam_registry_password_policy_lowercase_rule_has_check_and_finding_builder():
    rule = IAM_RULES.get_rule("CS-AWS-IAM-009")

    assert callable(rule.check)
    assert callable(rule.build_finding)


def test_iam_registry_contains_password_reuse_rule():
    rule = IAM_RULES.get_rule("CS-AWS-IAM-010")

    assert rule is not None
    assert rule.rule_id == "CS-AWS-IAM-010"
    assert rule.name == "password_reuse"
    assert rule.data_source == "password_policy"
    assert rule.collection_mode == "single"


def test_iam_registry_password_reuse_rule_has_expected_arguments():
    rule = IAM_RULES.get_rule("CS-AWS-IAM-010")

    assert rule.check_arguments == [
        "password_reuse_prevention",
    ]


def test_iam_registry_password_reuse_rule_has_check_and_finding_builder():
    rule = IAM_RULES.get_rule("CS-AWS-IAM-010")

    assert callable(rule.check)
    assert callable(rule.build_finding)


def test_iam_registry_contains_unused_console_password_rule():
    rule = IAM_RULES.get_rule("CS-AWS-IAM-011")

    assert rule is not None
    assert rule.rule_id == "CS-AWS-IAM-011"
    assert rule.name == "unused_console_password"
    assert rule.data_source == "credential_report"
    assert rule.collection_mode == "multiple"


def test_iam_registry_unused_console_password_rule_has_expected_arguments():
    rule = IAM_RULES.get_rule("CS-AWS-IAM-011")

    assert rule.check_arguments == [
        "username",
        "password_enabled",
        "password_last_used",
        "current_time",
    ]


def test_iam_registry_unused_console_password_rule_has_check_and_finding_builder():
    rule = IAM_RULES.get_rule("CS-AWS-IAM-011")

    assert callable(rule.check)
    assert callable(rule.build_finding)


def test_iam_registry_contains_broad_action_restricted_resource_rule():
    rule = IAM_RULES.get_rule("CS-AWS-IAM-016")

    assert rule is not None
    assert rule.rule_id == "CS-AWS-IAM-016"
    assert rule.name == "broad_action_restricted_resource"
    assert rule.data_source == "broad_action_restricted_resources"
    assert rule.collection_mode == "multiple"


def test_iam_registry_broad_action_restricted_resource_rule_has_expected_arguments():
    rule = IAM_RULES.get_rule("CS-AWS-IAM-016")

    assert rule.check_arguments == [
        "permission_source",
        "resource_id",
        "principal_type",
        "principal_id",
        "username",
        "group_name",
        "policy_name",
        "policy_arn",
        "policy_version_id",
        "statement_index",
        "effect",
        "action",
        "resource",
        "condition",
    ]


def test_iam_registry_broad_action_restricted_resource_rule_has_check_and_finding_builder():
    rule = IAM_RULES.get_rule("CS-AWS-IAM-016")

    assert callable(rule.check)
    assert callable(rule.build_finding)
