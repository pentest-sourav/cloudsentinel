from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class AppConfigResourceResult:
    resource_name: str
    resource_arn: str
    resource_type: str
    reason: str
    evidence: dict


def _finding(
    result: AppConfigResourceResult,
    rule_id: str,
    title: str,
    description: str,
    remediation: str,
    compliance_control: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=Severity.LOW,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_arn,
        description=description,
        evidence={
            "resource_name": result.resource_name,
            "resource_arn": result.resource_arn,
            "configuration_issue": result.reason,
            **result.evidence,
        },
        remediation=remediation,
        compliance=[
            f"AWS Security Hub {compliance_control}",
        ],
    )


def _check_tags(
    resource_name: str,
    resource_arn: str,
    resource_type: str,
    tag_data_available: bool,
    has_non_system_tags: bool,
) -> AppConfigResourceResult | None:
    if not resource_name or not resource_arn:
        return None

    if not tag_data_available:
        return None

    if has_non_system_tags:
        return None

    return AppConfigResourceResult(
        resource_name=resource_name,
        resource_arn=resource_arn,
        resource_type=resource_type,
        reason="missing_non_system_tags",
        evidence={
            "has_non_system_tags": False,
        },
    )


def check_appconfig_application_tags(
    resource_name: str,
    resource_arn: str,
    resource_type: str,
    tag_data_available: bool,
    has_non_system_tags: bool,
) -> AppConfigResourceResult | None:
    return _check_tags(
        resource_name,
        resource_arn,
        resource_type,
        tag_data_available,
        has_non_system_tags,
    )


def build_appconfig_application_tags_finding(
    result: AppConfigResourceResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-APPCONFIG-001",
        "AppConfig Application Is Not Tagged",
        (
            f"AWS AppConfig application "
            f"{result.resource_name} does not have any "
            "non-system tags."
        ),
        (
            "Add the required organizational tags to the "
            "AppConfig application. CloudSentinel evaluates "
            "baseline presence of at least one non-system "
            "tag; Security Hub AppConfig.1 can additionally "
            "enforce configured requiredKeyTags."
        ),
        "AppConfig.1",
    )


def check_appconfig_configuration_profile_tags(
    resource_name: str,
    resource_arn: str,
    resource_type: str,
    tag_data_available: bool,
    has_non_system_tags: bool,
) -> AppConfigResourceResult | None:
    return _check_tags(
        resource_name,
        resource_arn,
        resource_type,
        tag_data_available,
        has_non_system_tags,
    )


def build_appconfig_configuration_profile_tags_finding(
    result: AppConfigResourceResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-APPCONFIG-002",
        "AppConfig Configuration Profile Is Not Tagged",
        (
            f"AWS AppConfig configuration profile "
            f"{result.resource_name} does not have any "
            "non-system tags."
        ),
        (
            "Add the required organizational tags to the "
            "AppConfig configuration profile. CloudSentinel "
            "evaluates baseline presence of at least one "
            "non-system tag; Security Hub AppConfig.2 can "
            "additionally enforce configured requiredKeyTags."
        ),
        "AppConfig.2",
    )


def check_appconfig_environment_tags(
    resource_name: str,
    resource_arn: str,
    resource_type: str,
    tag_data_available: bool,
    has_non_system_tags: bool,
) -> AppConfigResourceResult | None:
    return _check_tags(
        resource_name,
        resource_arn,
        resource_type,
        tag_data_available,
        has_non_system_tags,
    )


def build_appconfig_environment_tags_finding(
    result: AppConfigResourceResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-APPCONFIG-003",
        "AppConfig Environment Is Not Tagged",
        (
            f"AWS AppConfig environment "
            f"{result.resource_name} does not have any "
            "non-system tags."
        ),
        (
            "Add the required organizational tags to the "
            "AppConfig environment. CloudSentinel evaluates "
            "baseline presence of at least one non-system "
            "tag; Security Hub AppConfig.3 can additionally "
            "enforce configured requiredKeyTags."
        ),
        "AppConfig.3",
    )


def check_appconfig_extension_association_tags(
    resource_name: str,
    resource_arn: str,
    resource_type: str,
    tag_data_available: bool,
    has_non_system_tags: bool,
) -> AppConfigResourceResult | None:
    return _check_tags(
        resource_name,
        resource_arn,
        resource_type,
        tag_data_available,
        has_non_system_tags,
    )


def build_appconfig_extension_association_tags_finding(
    result: AppConfigResourceResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-APPCONFIG-004",
        "AppConfig Extension Association Is Not Tagged",
        (
            f"AWS AppConfig extension association "
            f"{result.resource_name} does not have any "
            "non-system tags."
        ),
        (
            "Add the required organizational tags to the "
            "AppConfig extension association. CloudSentinel "
            "evaluates baseline presence of at least one "
            "non-system tag; Security Hub AppConfig.4 can "
            "additionally enforce configured requiredKeyTags."
        ),
        "AppConfig.4",
    )
