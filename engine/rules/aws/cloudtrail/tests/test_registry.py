from engine.rules.aws.cloudtrail.registry import CLOUDTRAIL_RULES


def test_cloudtrail_registry_contains_logging_rule():
    rule = CLOUDTRAIL_RULES.get_rule("CS-AWS-CT-001")

    assert rule is not None
    assert rule.rule_id == "CS-AWS-CT-001"
    assert rule.name == "cloudtrail_logging_enabled"
    assert rule.data_source == "cloudtrail_trails"
    assert rule.collection_mode == "multiple"


def test_cloudtrail_registry_rule_has_expected_arguments():
    rule = CLOUDTRAIL_RULES.get_rule("CS-AWS-CT-001")

    assert rule.check_arguments == [
        "trail_arn",
        "name",
        "is_logging",
    ]


def test_cloudtrail_registry_rule_has_check_and_finding_builder():
    rule = CLOUDTRAIL_RULES.get_rule("CS-AWS-CT-001")

    assert callable(rule.check)
    assert callable(rule.build_finding)

def test_cloudtrail_registry_contains_no_trail_rule():
    rule = CLOUDTRAIL_RULES.get_rule("CS-AWS-CT-002")

    assert rule is not None
    assert rule.rule_id == "CS-AWS-CT-002"
    assert rule.name == "cloudtrail_trail_configured"
    assert rule.data_source == "cloudtrail_account"
    assert rule.collection_mode == "single"

def test_cloudtrail_registry_no_trail_rule_has_expected_arguments():
    rule = CLOUDTRAIL_RULES.get_rule("CS-AWS-CT-002")

    assert rule.check_arguments == [
        "trail_count",
    ]

    assert callable(rule.check)
    assert callable(rule.build_finding)


def test_cloudtrail_registry_contains_multi_region_rule():
    rule = CLOUDTRAIL_RULES.get_rule("CS-AWS-CT-004")

    assert rule is not None
    assert rule.rule_id == "CS-AWS-CT-004"
    assert rule.name == "cloudtrail_multi_region"
    assert rule.data_source == "cloudtrail_trails"
    assert rule.collection_mode == "multiple"


def test_cloudtrail_registry_multi_region_rule_has_expected_arguments():
    rule = CLOUDTRAIL_RULES.get_rule("CS-AWS-CT-004")

    assert rule.check_arguments == [
        "trail_arn",
        "name",
        "is_multi_region_trail",
    ]

    assert callable(rule.check)
    assert callable(rule.build_finding)


def test_cloudtrail_registry_contains_global_service_events_rule():
    rule = CLOUDTRAIL_RULES.get_rule("CS-AWS-CT-005")

    assert rule is not None
    assert rule.rule_id == "CS-AWS-CT-005"
    assert rule.name == "cloudtrail_global_service_events"
    assert rule.data_source == "cloudtrail_trails"
    assert rule.collection_mode == "multiple"


def test_cloudtrail_registry_global_service_events_rule_has_expected_arguments():
    rule = CLOUDTRAIL_RULES.get_rule("CS-AWS-CT-005")

    assert rule.check_arguments == [
        "trail_arn",
        "name",
        "include_global_service_events",
    ]

    assert callable(rule.check)
    assert callable(rule.build_finding)


def test_cloudtrail_registry_contains_encryption_rule():
    rule = CLOUDTRAIL_RULES.get_rule("CS-AWS-CT-006")

    assert rule is not None
    assert rule.rule_id == "CS-AWS-CT-006"
    assert rule.name == "cloudtrail_encryption"
    assert rule.data_source == "cloudtrail_trails"
    assert rule.collection_mode == "multiple"


def test_cloudtrail_registry_encryption_rule_has_expected_arguments():
    rule = CLOUDTRAIL_RULES.get_rule("CS-AWS-CT-006")

    assert rule.check_arguments == [
        "trail_arn",
        "name",
        "kms_key_id",
    ]

    assert callable(rule.check)
    assert callable(rule.build_finding)
