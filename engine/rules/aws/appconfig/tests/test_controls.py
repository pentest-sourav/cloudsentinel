from engine.findings.model import Severity
from engine.rules.aws.appconfig.controls import (
    build_appconfig_application_tags_finding,
    build_appconfig_configuration_profile_tags_finding,
    build_appconfig_environment_tags_finding,
    build_appconfig_extension_association_tags_finding,
    check_appconfig_application_tags,
    check_appconfig_configuration_profile_tags,
    check_appconfig_environment_tags,
    check_appconfig_extension_association_tags,
)


BASE = {
    "resource_name": "payments",
    "resource_arn": (
        "arn:aws:appconfig:ap-south-1:"
        "123456789012:application/app1"
    ),
    "resource_type": "appconfig_application",
}


def test_application_tags_pass_when_non_system_tag_exists():
    assert check_appconfig_application_tags(
        **BASE,
        tag_data_available=True,
        has_non_system_tags=True,
    ) is None


def test_application_tags_fail_when_no_non_system_tags_exist():
    result = check_appconfig_application_tags(
        **BASE,
        tag_data_available=True,
        has_non_system_tags=False,
    )

    assert result is not None
    assert result.reason == "missing_non_system_tags"
    assert result.evidence["has_non_system_tags"] is False


def test_application_tags_skip_when_tag_data_unavailable():
    assert check_appconfig_application_tags(
        **BASE,
        tag_data_available=False,
        has_non_system_tags=False,
    ) is None


def test_configuration_profile_tags_fail():
    result = check_appconfig_configuration_profile_tags(
        resource_name="production",
        resource_arn=(
            "arn:aws:appconfig:ap-south-1:"
            "123456789012:application/app1/"
            "configurationprofile/profile1"
        ),
        resource_type="appconfig_configuration_profile",
        tag_data_available=True,
        has_non_system_tags=False,
    )

    assert result is not None


def test_environment_tags_fail():
    result = check_appconfig_environment_tags(
        resource_name="production",
        resource_arn=(
            "arn:aws:appconfig:ap-south-1:"
            "123456789012:application/app1/"
            "environment/env1"
        ),
        resource_type="appconfig_environment",
        tag_data_available=True,
        has_non_system_tags=False,
    )

    assert result is not None


def test_extension_association_tags_fail():
    result = check_appconfig_extension_association_tags(
        resource_name="assoc1",
        resource_arn=(
            "arn:aws:appconfig:ap-south-1:"
            "123456789012:extensionassociation/assoc1"
        ),
        resource_type="appconfig_extension_association",
        tag_data_available=True,
        has_non_system_tags=False,
    )

    assert result is not None


def test_invalid_resource_is_skipped():
    assert check_appconfig_application_tags(
        resource_name="",
        resource_arn=BASE["resource_arn"],
        resource_type=BASE["resource_type"],
        tag_data_available=True,
        has_non_system_tags=False,
    ) is None


def test_application_finding_contains_expected_metadata():
    result = check_appconfig_application_tags(
        **BASE,
        tag_data_available=True,
        has_non_system_tags=False,
    )

    finding = build_appconfig_application_tags_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-APPCONFIG-001"
    assert finding.severity == Severity.LOW
    assert finding.provider == "aws"
    assert finding.resource_type == "appconfig_application"
    assert finding.resource_id == BASE["resource_arn"]
    assert finding.compliance == [
        "AWS Security Hub AppConfig.1"
    ]


def test_all_finding_builders_use_correct_rule_ids():
    application = check_appconfig_application_tags(
        **BASE,
        tag_data_available=True,
        has_non_system_tags=False,
    )

    profile = check_appconfig_configuration_profile_tags(
        resource_name="profile",
        resource_arn="arn:profile",
        resource_type="appconfig_configuration_profile",
        tag_data_available=True,
        has_non_system_tags=False,
    )

    environment = check_appconfig_environment_tags(
        resource_name="environment",
        resource_arn="arn:environment",
        resource_type="appconfig_environment",
        tag_data_available=True,
        has_non_system_tags=False,
    )

    association = check_appconfig_extension_association_tags(
        resource_name="association",
        resource_arn="arn:association",
        resource_type="appconfig_extension_association",
        tag_data_available=True,
        has_non_system_tags=False,
    )

    assert (
        build_appconfig_application_tags_finding(
            application
        ).rule_id
        == "CS-AWS-APPCONFIG-001"
    )

    assert (
        build_appconfig_configuration_profile_tags_finding(
            profile
        ).rule_id
        == "CS-AWS-APPCONFIG-002"
    )

    assert (
        build_appconfig_environment_tags_finding(
            environment
        ).rule_id
        == "CS-AWS-APPCONFIG-003"
    )

    assert (
        build_appconfig_extension_association_tags_finding(
            association
        ).rule_id
        == "CS-AWS-APPCONFIG-004"
    )
