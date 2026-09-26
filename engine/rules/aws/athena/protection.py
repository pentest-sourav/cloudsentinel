from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class AthenaTagResult:
    resource_name: str
    resource_arn: str | None
    reason: str


@dataclass(frozen=True)
class AthenaLoggingResult:
    workgroup_name: str
    reason: str


def check_athena_data_catalog_tags(
    catalog_name: str,
    catalog_arn: str | None,
    tag_data_available: bool,
    has_non_system_tags: bool,
) -> AthenaTagResult | None:
    if (
        not catalog_name
        or not tag_data_available
    ):
        return None

    if has_non_system_tags:
        return None

    return AthenaTagResult(
        resource_name=catalog_name,
        resource_arn=catalog_arn,
        reason="missing_non_system_tags",
    )


def build_athena_data_catalog_tags_finding(
    result: AthenaTagResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ATHENA-002",
        title="AWS Athena Data Catalog Is Not Tagged",
        severity=Severity.LOW,
        provider="aws",
        resource_type="athena_data_catalog",
        resource_id=result.resource_name,
        description=(
            f"The AWS Athena data catalog "
            f"{result.resource_name} does not have "
            "any non-system tags."
        ),
        evidence={
            "catalog_name": result.resource_name,
            "catalog_arn": result.resource_arn,
            "configuration_issue": result.reason,
        },
        remediation=(
            "Add the required organizational tags to "
            "the Athena data catalog. CloudSentinel "
            "currently evaluates the baseline presence "
            "of at least one non-system tag; AWS Security "
            "Hub Athena.2 can additionally be configured "
            "with requiredTagKeys."
        ),
        compliance=[
            "AWS Security Hub Athena.2",
        ],
    )


def check_athena_workgroup_tags(
    workgroup_name: str,
    workgroup_arn: str | None,
    tag_data_available: bool,
    has_non_system_tags: bool,
) -> AthenaTagResult | None:
    if (
        not workgroup_name
        or not tag_data_available
    ):
        return None

    if has_non_system_tags:
        return None

    return AthenaTagResult(
        resource_name=workgroup_name,
        resource_arn=workgroup_arn,
        reason="missing_non_system_tags",
    )


def build_athena_workgroup_tags_finding(
    result: AthenaTagResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ATHENA-003",
        title="AWS Athena Workgroup Is Not Tagged",
        severity=Severity.LOW,
        provider="aws",
        resource_type="athena_workgroup",
        resource_id=result.resource_name,
        description=(
            f"The AWS Athena workgroup "
            f"{result.resource_name} does not have "
            "any non-system tags."
        ),
        evidence={
            "workgroup_name": result.resource_name,
            "workgroup_arn": result.resource_arn,
            "configuration_issue": result.reason,
        },
        remediation=(
            "Add the required organizational tags to "
            "the Athena workgroup. CloudSentinel currently "
            "evaluates the baseline presence of at least "
            "one non-system tag; AWS Security Hub Athena.3 "
            "can additionally be configured with "
            "requiredTagKeys."
        ),
        compliance=[
            "AWS Security Hub Athena.3",
        ],
    )


def check_athena_workgroup_logging(
    workgroup_name: str,
    publish_cloudwatch_metrics_enabled: bool | None,
) -> AthenaLoggingResult | None:
    if (
        not workgroup_name
        or publish_cloudwatch_metrics_enabled is None
    ):
        return None

    if publish_cloudwatch_metrics_enabled:
        return None

    return AthenaLoggingResult(
        workgroup_name=workgroup_name,
        reason="cloudwatch_metrics_not_enabled",
    )


def build_athena_workgroup_logging_finding(
    result: AthenaLoggingResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ATHENA-004",
        title="AWS Athena Workgroup Logging Is Not Enabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="athena_workgroup",
        resource_id=result.workgroup_name,
        description=(
            f"The AWS Athena workgroup "
            f"{result.workgroup_name} does not have "
            "CloudWatch metrics publishing enabled."
        ),
        evidence={
            "workgroup_name": result.workgroup_name,
            "configuration_issue": result.reason,
            "publish_cloudwatch_metrics_enabled": False,
        },
        remediation=(
            "Enable PublishCloudWatchMetricsEnabled "
            "for the Athena workgroup so Athena "
            "publishes workgroup metrics to CloudWatch."
        ),
        compliance=[
            "AWS Security Hub Athena.4",
        ],
    )
