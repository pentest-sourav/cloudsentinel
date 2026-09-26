from engine.findings.model import Severity
from engine.rules.aws.athena.protection import (
    build_athena_data_catalog_tags_finding,
    build_athena_workgroup_logging_finding,
    build_athena_workgroup_tags_finding,
    check_athena_data_catalog_tags,
    check_athena_workgroup_logging,
    check_athena_workgroup_tags,
)


def test_data_catalog_tags_pass_when_non_system_tag_exists():
    assert check_athena_data_catalog_tags(
        "AwsDataCatalog",
        "arn",
        True,
        True,
    ) is None


def test_data_catalog_tags_skip_when_tag_data_unavailable():
    assert check_athena_data_catalog_tags(
        "AwsDataCatalog",
        None,
        False,
        False,
    ) is None


def test_data_catalog_tags_fail_without_non_system_tags():
    result = check_athena_data_catalog_tags(
        "AwsDataCatalog",
        "arn",
        True,
        False,
    )

    assert result is not None

    finding = build_athena_data_catalog_tags_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-ATHENA-002"
    assert finding.severity == Severity.LOW


def test_workgroup_tags_pass_with_non_system_tag():
    assert check_athena_workgroup_tags(
        "primary",
        "arn",
        True,
        True,
    ) is None


def test_workgroup_tags_fail_without_non_system_tags():
    result = check_athena_workgroup_tags(
        "primary",
        "arn",
        True,
        False,
    )

    assert result is not None

    finding = build_athena_workgroup_tags_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-ATHENA-003"
    assert finding.severity == Severity.LOW


def test_workgroup_logging_passes_when_metrics_enabled():
    assert check_athena_workgroup_logging(
        "primary",
        True,
    ) is None


def test_workgroup_logging_skips_when_value_unknown():
    assert check_athena_workgroup_logging(
        "primary",
        None,
    ) is None


def test_workgroup_logging_fails_when_metrics_disabled():
    result = check_athena_workgroup_logging(
        "primary",
        False,
    )

    assert result is not None

    finding = build_athena_workgroup_logging_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-ATHENA-004"
    assert finding.severity == Severity.MEDIUM
