from engine.rules.registry.iam_registry import IAM_RULES


def test_iam_registry_contains_root_mfa_rule():
    rule_ids = [rule["rule_id"] for rule in IAM_RULES]

    assert rule_ids == [
        "CS-AWS-IAM-001",
        "CS-AWS-IAM-002",
    ]


def test_iam_registry_has_required_fields():
    required_fields = {
        "rule_id",
        "name",
        "data_source",
        "check",
        "build_finding",
    }

    for rule in IAM_RULES:
        assert required_fields.issubset(rule.keys())
        assert callable(rule["check"])
        assert callable(rule["build_finding"])

def test_iam_registry_rule_ids_are_unique():
    rule_ids = [rule["rule_id"] for rule in IAM_RULES]

    assert len(rule_ids) == len(set(rule_ids))

def test_iam_rules_have_valid_data_sources():
    allowed_data_sources = {
        "root_mfa",
        "iam_users",
    }

    for rule in IAM_RULES:
        assert rule["data_source"] in allowed_data_sources

def test_iam_rules_have_valid_collection_modes():
    allowed_modes = {
        "single",
        "multiple",
    }

    for rule in IAM_RULES:
        assert rule["collection_mode"] in allowed_modes
