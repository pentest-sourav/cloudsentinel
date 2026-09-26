from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class AppRunnerResourceResult:
    resource_name: str
    resource_arn: str
    resource_type: str
    reason: str
    evidence: dict


def _finding(
    result: AppRunnerResourceResult,
    rule_id: str,
    title: str,
    severity: Severity,
    description: str,
    remediation: str,
    compliance_control: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
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


def check_apprunner_service_tags(
    service_name: str,
    service_arn: str,
    tag_data_available: bool,
    has_non_system_tags: bool,
) -> AppRunnerResourceResult | None:
    if not service_name or not service_arn:
        return None

    if not tag_data_available:
        return None

    if has_non_system_tags:
        return None

    return AppRunnerResourceResult(
        resource_name=service_name,
        resource_arn=service_arn,
        resource_type="apprunner_service",
        reason="missing_non_system_tags",
        evidence={
            "has_non_system_tags": False,
        },
    )


def build_apprunner_service_tags_finding(
    result: AppRunnerResourceResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-APPRUNNER-001",
        "App Runner Service Is Not Tagged",
        Severity.LOW,
        (
            f"App Runner service {result.resource_name} "
            "does not have any non-system tags."
        ),
        (
            "Add the required organizational tags to the "
            "App Runner service. CloudSentinel evaluates the "
            "baseline presence of at least one non-system tag; "
            "Security Hub AppRunner.1 can additionally enforce "
            "configured requiredKeyTags."
        ),
        "AppRunner.1",
    )


def check_apprunner_vpc_connector_tags(
    connector_name: str,
    connector_arn: str,
    tag_data_available: bool,
    has_non_system_tags: bool,
) -> AppRunnerResourceResult | None:
    if not connector_name or not connector_arn:
        return None

    if not tag_data_available:
        return None

    if has_non_system_tags:
        return None

    return AppRunnerResourceResult(
        resource_name=connector_name,
        resource_arn=connector_arn,
        resource_type="apprunner_vpc_connector",
        reason="missing_non_system_tags",
        evidence={
            "has_non_system_tags": False,
        },
    )


def build_apprunner_vpc_connector_tags_finding(
    result: AppRunnerResourceResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-APPRUNNER-002",
        "App Runner VPC Connector Is Not Tagged",
        Severity.LOW,
        (
            f"App Runner VPC connector {result.resource_name} "
            "does not have any non-system tags."
        ),
        (
            "Add the required organizational tags to the "
            "App Runner VPC connector. CloudSentinel evaluates "
            "the baseline presence of at least one non-system "
            "tag; Security Hub AppRunner.2 can additionally "
            "enforce configured requiredKeyTags."
        ),
        "AppRunner.2",
    )
