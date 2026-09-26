from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class DMSResult:
    resource_name: str
    resource_arn: str
    resource_type: str
    control_id: str
    reason: str
    evidence: dict[str, Any]


def _result(
    *,
    name: str,
    arn: str,
    resource_type: str,
    control_id: str,
    reason: str,
    evidence: dict[str, Any] | None = None,
) -> DMSResult:
    return DMSResult(
        resource_name=name,
        resource_arn=arn,
        resource_type=resource_type,
        control_id=control_id,
        reason=reason,
        evidence=evidence or {},
    )


def _finding(
    result: DMSResult,
    severity: Severity,
    title: str,
    description: str,
    remediation: str,
) -> Finding:
    return Finding(
        rule_id=(
            "CS-AWS-DMS-"
            f"{result.control_id.split('.')[-1].zfill(3)}"
        ),
        title=title,
        severity=severity,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_arn,
        description=description,
        evidence={
            "resource_name": result.resource_name,
            "resource_arn": result.resource_arn,
            "security_hub_control": result.control_id,
            "configuration_issue": result.reason,
            **result.evidence,
        },
        remediation=remediation,
        compliance=[
            f"AWS Security Hub {result.control_id}",
        ],
    )


# ------------------------------------------------------------
# TAGGING CONTROLS
# ------------------------------------------------------------

def _check_tags(
    *,
    name: str,
    arn: str,
    resource_type: str,
    control_id: str,
    tag_data_available: bool,
    has_non_system_tags: bool,
) -> DMSResult | None:
    if not name or not arn:
        return None

    if not tag_data_available:
        return None

    if has_non_system_tags:
        return None

    return _result(
        name=name,
        arn=arn,
        resource_type=resource_type,
        control_id=control_id,
        reason="missing_non_system_tags",
        evidence={
            "has_non_system_tags": False,
        },
    )


def check_dms_certificate_tags(
    resource_name,
    resource_arn,
    resource_type,
    tag_data_available,
    has_non_system_tags,
):
    return _check_tags(
        name=resource_name,
        arn=resource_arn,
        resource_type=resource_type,
        control_id="DMS.2",
        tag_data_available=tag_data_available,
        has_non_system_tags=has_non_system_tags,
    )


def build_dms_certificate_tags_finding(result):
    return _finding(
        result,
        Severity.LOW,
        "DMS Certificate Is Not Tagged",
        (
            f"AWS DMS certificate "
            f"{result.resource_name} does not have "
            "any non-system tags."
        ),
        (
            "Add the required organizational tags to "
            "the DMS certificate."
        ),
    )


def check_dms_event_subscription_tags(
    resource_name,
    resource_arn,
    resource_type,
    tag_data_available,
    has_non_system_tags,
):
    return _check_tags(
        name=resource_name,
        arn=resource_arn,
        resource_type=resource_type,
        control_id="DMS.3",
        tag_data_available=tag_data_available,
        has_non_system_tags=has_non_system_tags,
    )


def build_dms_event_subscription_tags_finding(result):
    return _finding(
        result,
        Severity.LOW,
        "DMS Event Subscription Is Not Tagged",
        (
            f"AWS DMS event subscription "
            f"{result.resource_name} does not have "
            "any non-system tags."
        ),
        (
            "Add the required organizational tags to "
            "the DMS event subscription."
        ),
    )


def check_dms_replication_instance_tags(
    resource_name,
    resource_arn,
    resource_type,
    tag_data_available,
    has_non_system_tags,
):
    return _check_tags(
        name=resource_name,
        arn=resource_arn,
        resource_type=resource_type,
        control_id="DMS.4",
        tag_data_available=tag_data_available,
        has_non_system_tags=has_non_system_tags,
    )


def build_dms_replication_instance_tags_finding(result):
    return _finding(
        result,
        Severity.LOW,
        "DMS Replication Instance Is Not Tagged",
        (
            f"AWS DMS replication instance "
            f"{result.resource_name} does not have "
            "any non-system tags."
        ),
        (
            "Add the required organizational tags to "
            "the DMS replication instance."
        ),
    )


def check_dms_subnet_group_tags(
    resource_name,
    resource_arn,
    resource_type,
    tag_data_available,
    has_non_system_tags,
):
    return _check_tags(
        name=resource_name,
        arn=resource_arn,
        resource_type=resource_type,
        control_id="DMS.5",
        tag_data_available=tag_data_available,
        has_non_system_tags=has_non_system_tags,
    )


def build_dms_subnet_group_tags_finding(result):
    return _finding(
        result,
        Severity.LOW,
        "DMS Replication Subnet Group Is Not Tagged",
        (
            f"AWS DMS replication subnet group "
            f"{result.resource_name} does not have "
            "any non-system tags."
        ),
        (
            "Add the required organizational tags to "
            "the DMS replication subnet group."
        ),
    )


# ------------------------------------------------------------
# REPLICATION INSTANCE CONTROLS
# ------------------------------------------------------------

def check_dms_not_public(
    resource_name,
    resource_arn,
    resource_type,
    publicly_accessible,
):
    if not resource_name or not resource_arn:
        return None

    if publicly_accessible is False:
        return None

    return _result(
        name=resource_name,
        arn=resource_arn,
        resource_type=resource_type,
        control_id="DMS.1",
        reason="replication_instance_is_public",
        evidence={
            "publicly_accessible": publicly_accessible,
        },
    )


def build_dms_not_public_finding(result):
    return _finding(
        result,
        Severity.CRITICAL,
        "DMS Replication Instance Is Public",
        (
            f"AWS DMS replication instance "
            f"{result.resource_name} is publicly accessible."
        ),
        (
            "Recreate the DMS replication instance without "
            "the Publicly accessible option. AWS DMS does "
            "not allow changing this setting after creation."
        ),
    )


def check_dms_auto_minor_upgrade(
    resource_name,
    resource_arn,
    resource_type,
    auto_minor_version_upgrade,
):
    if not resource_name or not resource_arn:
        return None

    if auto_minor_version_upgrade is True:
        return None

    return _result(
        name=resource_name,
        arn=resource_arn,
        resource_type=resource_type,
        control_id="DMS.6",
        reason="automatic_minor_version_upgrade_disabled",
        evidence={
            "auto_minor_version_upgrade": (
                auto_minor_version_upgrade
            ),
        },
    )


def build_dms_auto_minor_upgrade_finding(result):
    return _finding(
        result,
        Severity.MEDIUM,
        "DMS Automatic Minor Version Upgrade Is Disabled",
        (
            f"DMS replication instance "
            f"{result.resource_name} does not have "
            "automatic minor version upgrade enabled."
        ),
        (
            "Modify the DMS replication instance and "
            "enable automatic minor version upgrades."
        ),
    )


def check_dms_multi_az(
    resource_name,
    resource_arn,
    resource_type,
    multi_az,
):
    if not resource_name or not resource_arn:
        return None

    if multi_az is True:
        return None

    return _result(
        name=resource_name,
        arn=resource_arn,
        resource_type=resource_type,
        control_id="DMS.13",
        reason="multi_az_disabled",
        evidence={
            "multi_az": multi_az,
        },
    )


def build_dms_multi_az_finding(result):
    return _finding(
        result,
        Severity.MEDIUM,
        "DMS Replication Instance Is Not Multi-AZ",
        (
            f"DMS replication instance "
            f"{result.resource_name} is not configured "
            "for Multi-AZ deployment."
        ),
        (
            "Modify the DMS replication instance and "
            "enable Multi-AZ deployment."
        ),
    )


# ------------------------------------------------------------
# REPLICATION TASK LOGGING
# ------------------------------------------------------------

_LOG_SEVERITY_ORDER = {
    "LOGGER_SEVERITY_OFF": 0,
    "LOGGER_SEVERITY_ERROR": 1,
    "LOGGER_SEVERITY_WARNING": 2,
    "LOGGER_SEVERITY_DEFAULT": 3,
    "LOGGER_SEVERITY_DEBUG": 4,
    "LOGGER_SEVERITY_DETAILED_DEBUG": 5,
}


def _logging_ok(
    logging_enabled,
    components,
    required_components,
):
    if logging_enabled is not True:
        return False

    if not isinstance(components, dict):
        return False

    for component in required_components:
        severity = components.get(component)

        if (
            not isinstance(severity, str)
            or _LOG_SEVERITY_ORDER.get(
                severity,
                -1,
            )
            < _LOG_SEVERITY_ORDER[
                "LOGGER_SEVERITY_DEFAULT"
            ]
        ):
            return False

    return True


def check_dms_target_logging(
    resource_name,
    resource_arn,
    resource_type,
    logging_enabled,
    log_components,
):
    if not resource_name or not resource_arn:
        return None

    if _logging_ok(
        logging_enabled,
        log_components,
        {"TARGET_APPLY", "TARGET_LOAD"},
    ):
        return None

    return _result(
        name=resource_name,
        arn=resource_arn,
        resource_type=resource_type,
        control_id="DMS.7",
        reason="target_database_logging_not_configured",
        evidence={
            "logging_enabled": logging_enabled,
            "log_components": log_components,
            "required_components": [
                "TARGET_APPLY",
                "TARGET_LOAD",
            ],
        },
    )


def build_dms_target_logging_finding(result):
    return _finding(
        result,
        Severity.MEDIUM,
        "DMS Target Database Logging Is Not Enabled",
        (
            f"DMS replication task "
            f"{result.resource_name} does not have "
            "required target database logging enabled."
        ),
        (
            "Enable DMS task logging and configure "
            "TARGET_APPLY and TARGET_LOAD with at least "
            "LOGGER_SEVERITY_DEFAULT."
        ),
    )


def check_dms_source_logging(
    resource_name,
    resource_arn,
    resource_type,
    logging_enabled,
    log_components,
):
    if not resource_name or not resource_arn:
        return None

    if _logging_ok(
        logging_enabled,
        log_components,
        {"SOURCE_CAPTURE", "SOURCE_UNLOAD"},
    ):
        return None

    return _result(
        name=resource_name,
        arn=resource_arn,
        resource_type=resource_type,
        control_id="DMS.8",
        reason="source_database_logging_not_configured",
        evidence={
            "logging_enabled": logging_enabled,
            "log_components": log_components,
            "required_components": [
                "SOURCE_CAPTURE",
                "SOURCE_UNLOAD",
            ],
        },
    )


def build_dms_source_logging_finding(result):
    return _finding(
        result,
        Severity.MEDIUM,
        "DMS Source Database Logging Is Not Enabled",
        (
            f"DMS replication task "
            f"{result.resource_name} does not have "
            "required source database logging enabled."
        ),
        (
            "Enable DMS task logging and configure "
            "SOURCE_CAPTURE and SOURCE_UNLOAD with at "
            "least LOGGER_SEVERITY_DEFAULT."
        ),
    )


# ------------------------------------------------------------
# ENDPOINT CONTROLS
# ------------------------------------------------------------

def check_dms_endpoint_ssl(
    resource_name,
    resource_arn,
    resource_type,
    ssl_mode,
):
    if not resource_name or not resource_arn:
        return None

    if (
        isinstance(ssl_mode, str)
        and ssl_mode.lower() != "none"
    ):
        return None

    return _result(
        name=resource_name,
        arn=resource_arn,
        resource_type=resource_type,
        control_id="DMS.9",
        reason="endpoint_ssl_not_configured",
        evidence={
            "ssl_mode": ssl_mode,
        },
    )


def build_dms_endpoint_ssl_finding(result):
    return _finding(
        result,
        Severity.MEDIUM,
        "DMS Endpoint Does Not Use SSL",
        (
            f"DMS endpoint "
            f"{result.resource_name} does not use "
            "an SSL/TLS connection."
        ),
        (
            "Configure the DMS endpoint to use an "
            "SSL/TLS mode appropriate for the database."
        ),
    )


def check_dms_neptune_iam_auth(
    resource_name,
    resource_arn,
    resource_type,
    engine_name,
    neptune_iam_auth_mode,
):
    if not resource_name or not resource_arn:
        return None

    if str(engine_name).lower() != "neptune":
        return None

    if str(neptune_iam_auth_mode).upper() in {
        "REQUIRED",
        "REQUIRED_FOR_ALL_USERS",
        "IAM",
        "ENABLED",
    }:
        return None

    return _result(
        name=resource_name,
        arn=resource_arn,
        resource_type=resource_type,
        control_id="DMS.10",
        reason="neptune_iam_authorization_disabled",
        evidence={
            "engine_name": engine_name,
            "neptune_iam_auth_mode": (
                neptune_iam_auth_mode
            ),
        },
    )


def build_dms_neptune_iam_auth_finding(result):
    return _finding(
        result,
        Severity.MEDIUM,
        "DMS Neptune Endpoint IAM Authorization Is Disabled",
        (
            f"DMS Neptune endpoint "
            f"{result.resource_name} does not have "
            "IAM authorization enabled."
        ),
        (
            "Configure IAM authorization for the DMS "
            "Neptune endpoint."
        ),
    )


def check_dms_mongodb_auth(
    resource_name,
    resource_arn,
    resource_type,
    engine_name,
    mongo_auth_type,
):
    if not resource_name or not resource_arn:
        return None

    if str(engine_name).lower() != "mongodb":
        return None

    if str(mongo_auth_type).lower() in {
        "password",
        "scram",
        "scram_sha_1",
    }:
        return None

    return _result(
        name=resource_name,
        arn=resource_arn,
        resource_type=resource_type,
        control_id="DMS.11",
        reason="mongodb_authentication_not_configured",
        evidence={
            "engine_name": engine_name,
            "mongo_auth_type": mongo_auth_type,
        },
    )


def build_dms_mongodb_auth_finding(result):
    return _finding(
        result,
        Severity.MEDIUM,
        "DMS MongoDB Authentication Is Not Enabled",
        (
            f"DMS MongoDB endpoint "
            f"{result.resource_name} does not have "
            "an authentication mechanism configured."
        ),
        (
            "Configure an authentication mechanism for "
            "the DMS MongoDB endpoint."
        ),
    )


def check_dms_redis_tls(
    resource_name,
    resource_arn,
    resource_type,
    engine_name,
    ssl_mode,
):
    if not resource_name or not resource_arn:
        return None

    if str(engine_name).lower() not in {
        "redis",
        "redisoss",
        "redis_oss",
    }:
        return None

    if (
        isinstance(ssl_mode, str)
        and ssl_mode.lower() != "none"
    ):
        return None

    return _result(
        name=resource_name,
        arn=resource_arn,
        resource_type=resource_type,
        control_id="DMS.12",
        reason="redis_tls_not_configured",
        evidence={
            "engine_name": engine_name,
            "ssl_mode": ssl_mode,
        },
    )


def build_dms_redis_tls_finding(result):
    return _finding(
        result,
        Severity.MEDIUM,
        "DMS Redis OSS Endpoint TLS Is Disabled",
        (
            f"DMS Redis OSS endpoint "
            f"{result.resource_name} does not have "
            "TLS enabled."
        ),
        (
            "Configure SSL/TLS for the DMS Redis OSS "
            "endpoint."
        ),
    )
