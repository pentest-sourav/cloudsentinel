from engine.rules.aws.cloudtrail.registry import CLOUDTRAIL_RULES


def test_ct013_registry_definition():
    rule = CLOUDTRAIL_RULES.get_rule("CS-AWS-CT-013")

    assert rule is not None
    assert rule.rule_id == "CS-AWS-CT-013"
    assert rule.name == "cloudtrail_event_data_store_ingestion"
    assert rule.data_source == "cloudtrail_event_data_stores"
    assert rule.collection_mode == "multiple"
    assert rule.check_arguments == [
        "event_data_store_arn",
        "name",
        "status",
    ]
    assert callable(rule.check)
    assert callable(rule.build_finding)


def test_ct014_registry_definition():
    rule = CLOUDTRAIL_RULES.get_rule("CS-AWS-CT-014")

    assert rule is not None
    assert rule.rule_id == "CS-AWS-CT-014"
    assert rule.name == "cloudtrail_event_data_store_management_events"
    assert rule.data_source == "cloudtrail_event_data_stores"
    assert rule.collection_mode == "multiple"
    assert rule.check_arguments == [
        "event_data_store_arn",
        "name",
        "management_events_enabled",
    ]
    assert callable(rule.check)
    assert callable(rule.build_finding)


def test_ct015_registry_definition():
    rule = CLOUDTRAIL_RULES.get_rule("CS-AWS-CT-015")

    assert rule is not None
    assert rule.rule_id == "CS-AWS-CT-015"
    assert rule.name == "cloudtrail_event_data_store_multi_region"
    assert rule.data_source == "cloudtrail_event_data_stores"
    assert rule.collection_mode == "multiple"
    assert rule.check_arguments == [
        "event_data_store_arn",
        "name",
        "multi_region_enabled",
    ]
    assert callable(rule.check)
    assert callable(rule.build_finding)


def test_ct016_registry_definition():
    rule = CLOUDTRAIL_RULES.get_rule("CS-AWS-CT-016")

    assert rule is not None
    assert rule.rule_id == "CS-AWS-CT-016"
    assert rule.name == "cloudtrail_event_data_store_organization"
    assert rule.data_source == "cloudtrail_event_data_stores"
    assert rule.collection_mode == "multiple"
    assert rule.check_arguments == [
        "event_data_store_arn",
        "name",
        "organization_enabled",
    ]
    assert callable(rule.check)
    assert callable(rule.build_finding)
