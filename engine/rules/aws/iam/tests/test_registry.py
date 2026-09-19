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
