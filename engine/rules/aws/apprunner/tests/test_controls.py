from engine.findings.model import Severity
from engine.rules.aws.apprunner.controls import (
    build_apprunner_service_tags_finding,
    build_apprunner_vpc_connector_tags_finding,
    check_apprunner_service_tags,
    check_apprunner_vpc_connector_tags,
)


SERVICE_ARN = (
    "arn:aws:apprunner:ap-south-1:123456789012:"
    "service/frontend/1234567890abcdef1234567890abcdef"
)

CONNECTOR_ARN = (
    "arn:aws:apprunner:ap-south-1:123456789012:"
    "vpcconnector/frontend/1/"
    "1234567890abcdef1234567890abcdef"
)


def test_apprunner_service_tags_passes_when_tagged():
    assert (
        check_apprunner_service_tags(
            "frontend",
            SERVICE_ARN,
            True,
            True,
        )
        is None
    )


def test_apprunner_service_tags_skips_when_tag_data_unavailable():
    assert (
        check_apprunner_service_tags(
            "frontend",
            SERVICE_ARN,
            False,
            False,
        )
        is None
    )


def test_apprunner_service_tags_fails_when_untagged():
    result = check_apprunner_service_tags(
        "frontend",
        SERVICE_ARN,
        True,
        False,
    )

    assert result is not None
    assert result.reason == "missing_non_system_tags"
    assert result.resource_type == "apprunner_service"

    finding = build_apprunner_service_tags_finding(result)

    assert finding.rule_id == "CS-AWS-APPRUNNER-001"
    assert finding.severity == Severity.LOW
    assert finding.resource_type == "apprunner_service"
    assert finding.resource_id == SERVICE_ARN
    assert "AWS Security Hub AppRunner.1" in finding.compliance


def test_apprunner_vpc_connector_tags_passes_when_tagged():
    assert (
        check_apprunner_vpc_connector_tags(
            "frontend",
            CONNECTOR_ARN,
            True,
            True,
        )
        is None
    )


def test_apprunner_vpc_connector_tags_skips_when_tag_data_unavailable():
    assert (
        check_apprunner_vpc_connector_tags(
            "frontend",
            CONNECTOR_ARN,
            False,
            False,
        )
        is None
    )


def test_apprunner_vpc_connector_tags_fails_when_untagged():
    result = check_apprunner_vpc_connector_tags(
        "frontend",
        CONNECTOR_ARN,
        True,
        False,
    )

    assert result is not None
    assert result.reason == "missing_non_system_tags"
    assert result.resource_type == "apprunner_vpc_connector"

    finding = build_apprunner_vpc_connector_tags_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-APPRUNNER-002"
    assert finding.severity == Severity.LOW
    assert finding.resource_type == "apprunner_vpc_connector"
    assert finding.resource_id == CONNECTOR_ARN
    assert "AWS Security Hub AppRunner.2" in finding.compliance
