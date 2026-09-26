from engine.findings.model import Severity
from engine.rules.aws.appsync.protection import (
    build_appsync_api_key_authentication_finding,
    build_appsync_field_logging_finding,
    build_appsync_tags_finding,
    check_appsync_api_key_authentication,
    check_appsync_field_logging,
    check_appsync_tags,
)


def test_field_logging_error_passes():
    assert (
        check_appsync_field_logging(
            "api-1",
            "ERROR",
        )
        is None
    )


def test_field_logging_all_passes():
    assert (
        check_appsync_field_logging(
            "api-1",
            "ALL",
        )
        is None
    )


def test_field_logging_none_fails():
    result = check_appsync_field_logging(
        "api-1",
        "NONE",
    )

    finding = build_appsync_field_logging_finding(
        result
    )

    assert (
        finding.rule_id
        == "CS-AWS-APPSYNC-002"
    )
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_id == "api-1"
    assert (
        finding.evidence["field_log_level"]
        == "NONE"
    )


def test_missing_field_logging_fails():
    result = check_appsync_field_logging(
        "api-1",
        None,
    )

    assert result is not None
    assert (
        result.reason
        == "field_level_logging_disabled"
    )


def test_tagged_api_passes():
    assert (
        check_appsync_tags(
            "api-1",
            True,
        )
        is None
    )


def test_untagged_api_fails():
    result = check_appsync_tags(
        "api-1",
        False,
    )

    finding = build_appsync_tags_finding(result)

    assert (
        finding.rule_id
        == "CS-AWS-APPSYNC-004"
    )
    assert finding.severity == Severity.LOW
    assert finding.resource_id == "api-1"
    assert (
        finding.evidence["has_non_system_tags"]
        is False
    )


def test_api_key_primary_auth_fails():
    result = check_appsync_api_key_authentication(
        "api-1",
        "API_KEY",
        [],
    )

    finding = (
        build_appsync_api_key_authentication_finding(
            result
        )
    )

    assert (
        finding.rule_id
        == "CS-AWS-APPSYNC-005"
    )
    assert finding.severity == Severity.HIGH
    assert finding.resource_id == "api-1"
    assert (
        "API_KEY"
        in finding.evidence[
            "configured_authentication_types"
        ]
    )


def test_api_key_additional_auth_fails():
    result = check_appsync_api_key_authentication(
        "api-1",
        "AWS_IAM",
        ["API_KEY"],
    )

    assert result is not None

    finding = (
        build_appsync_api_key_authentication_finding(
            result
        )
    )

    assert finding.severity == Severity.HIGH
    assert (
        finding.evidence[
            "authentication_type"
        ]
        == "AWS_IAM"
    )
    assert (
        "API_KEY"
        in finding.evidence[
            "additional_authentication_types"
        ]
    )


def test_non_api_key_auth_passes():
    assert (
        check_appsync_api_key_authentication(
            "api-1",
            "AWS_IAM",
            [
                "AMAZON_COGNITO_USER_POOLS",
                "OPENID_CONNECT",
            ],
        )
        is None
    )
