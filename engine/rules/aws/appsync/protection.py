from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class AppSyncResult:
    resource_id: str
    reason: str
    evidence: dict


def check_appsync_field_logging(
    resource_id: str,
    field_log_level: str | None,
) -> AppSyncResult | None:
    if not resource_id:
        return None

    if field_log_level in {
        "ERROR",
        "ALL",
        "INFO",
        "DEBUG",
    }:
        return None

    return AppSyncResult(
        resource_id=resource_id,
        reason="field_level_logging_disabled",
        evidence={
            "field_log_level": field_log_level,
        },
    )


def build_appsync_field_logging_finding(
    result: AppSyncResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-APPSYNC-002",
        title=(
            "AWS AppSync GraphQL API Does Not Have "
            "Field-Level Logging Enabled"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="appsync_graphql_api",
        resource_id=result.resource_id,
        description=(
            f"The AWS AppSync GraphQL API "
            f"{result.resource_id} does not have "
            "field-level logging enabled."
        ),
        evidence={
            "configuration_issue": result.reason,
            **result.evidence,
        },
        remediation=(
            "Configure the AppSync GraphQL API field "
            "logging level to ERROR or ALL."
        ),
        compliance=[
            "AWS Security Hub AppSync.2",
            "PCI DSS v4.0.1/10.4.2",
        ],
    )


def check_appsync_tags(
    resource_id: str,
    has_non_system_tags: bool,
) -> AppSyncResult | None:
    if not resource_id:
        return None

    if has_non_system_tags:
        return None

    return AppSyncResult(
        resource_id=resource_id,
        reason="missing_non_system_tags",
        evidence={
            "has_non_system_tags": False,
        },
    )


def build_appsync_tags_finding(
    result: AppSyncResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-APPSYNC-004",
        title="AWS AppSync GraphQL API Is Not Tagged",
        severity=Severity.LOW,
        provider="aws",
        resource_type="appsync_graphql_api",
        resource_id=result.resource_id,
        description=(
            f"The AWS AppSync GraphQL API "
            f"{result.resource_id} does not have "
            "any non-system tags."
        ),
        evidence={
            "configuration_issue": result.reason,
            **result.evidence,
        },
        remediation=(
            "Add meaningful non-system tags to the "
            "AppSync GraphQL API. If your organization "
            "uses required tag keys, ensure all required "
            "keys are present."
        ),
        compliance=[
            "AWS Security Hub AppSync.4",
        ],
    )


def check_appsync_api_key_authentication(
    resource_id: str,
    authentication_type: str | None,
    additional_authentication_types: list[str],
) -> AppSyncResult | None:
    if not resource_id:
        return None

    configured_types: list[str] = []

    if isinstance(authentication_type, str):
        configured_types.append(
            authentication_type
        )

    if isinstance(
        additional_authentication_types,
        list,
    ):
        configured_types.extend(
            auth_type
            for auth_type in additional_authentication_types
            if isinstance(auth_type, str)
        )

    if "API_KEY" not in configured_types:
        return None

    return AppSyncResult(
        resource_id=resource_id,
        reason="api_key_authentication_configured",
        evidence={
            "authentication_type": authentication_type,
            "additional_authentication_types": (
                additional_authentication_types
            ),
            "configured_authentication_types": (
                configured_types
            ),
        },
    )


def build_appsync_api_key_authentication_finding(
    result: AppSyncResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-APPSYNC-005",
        title=(
            "AWS AppSync GraphQL API Uses "
            "API Key Authentication"
        ),
        severity=Severity.HIGH,
        provider="aws",
        resource_type="appsync_graphql_api",
        resource_id=result.resource_id,
        description=(
            f"The AWS AppSync GraphQL API "
            f"{result.resource_id} has API key "
            "authentication configured."
        ),
        evidence={
            "configuration_issue": result.reason,
            **result.evidence,
        },
        remediation=(
            "Use AWS IAM, Amazon Cognito User Pools, "
            "OpenID Connect, or AWS Lambda authorization "
            "instead of API key authentication."
        ),
        compliance=[
            "AWS Security Hub AppSync.5",
            "NIST SP 800-53 Rev. 5 AC-2(1)",
            "NIST SP 800-53 Rev. 5 AC-3",
            "NIST SP 800-53 Rev. 5 AC-3(15)",
            "NIST SP 800-53 Rev. 5 AC-3(7)",
            "NIST SP 800-53 Rev. 5 AC-6",
        ],
    )
