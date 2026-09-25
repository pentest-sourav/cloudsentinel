from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


ERROR_LOG_KEY = "ES_APPLICATION_LOGS"


@dataclass(frozen=True)
class OpenSearchErrorLoggingResult:
    domain_arn: str
    domain_name: str
    error_logging_enabled: bool
    log_publishing_options: dict[str, Any]


def check_opensearch_error_logging(
    domain_arn: str,
    domain_name: str,
    log_publishing_options: dict[str, Any],
) -> OpenSearchErrorLoggingResult:
    if not isinstance(log_publishing_options, dict):
        log_publishing_options = {}

    error_config = log_publishing_options.get(
        ERROR_LOG_KEY,
        {},
    )

    if not isinstance(error_config, dict):
        error_config = {}

    enabled = error_config.get("Enabled") is True

    return OpenSearchErrorLoggingResult(
        domain_arn=domain_arn,
        domain_name=domain_name,
        error_logging_enabled=enabled,
        log_publishing_options=log_publishing_options,
    )


def build_opensearch_error_logging_finding(
    result: OpenSearchErrorLoggingResult,
) -> Finding | None:
    if result.error_logging_enabled:
        return None

    return Finding(
        rule_id="CS-AWS-OPENSEARCH-004",
        title="OpenSearch Error Logging To CloudWatch Is Not Enabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="opensearch_domain",
        resource_id=result.domain_arn,
        description=(
            "OpenSearch error/application log publishing to "
            "CloudWatch Logs is not enabled."
        ),
        evidence={
            "domain_name": result.domain_name,
            "error_logging_enabled": (
                result.error_logging_enabled
            ),
            "log_publishing_options": (
                result.log_publishing_options
            ),
        },
        remediation=(
            "Enable OpenSearch application/error log publishing "
            "to CloudWatch Logs."
        ),
        compliance=[
            "AWS Security Hub Opensearch.4",
        ],
    )
