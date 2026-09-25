from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


AUDIT_LOG_KEY = "AUDIT_LOGS"


@dataclass(frozen=True)
class OpenSearchAuditLoggingResult:
    domain_arn: str
    domain_name: str
    audit_logging_enabled: bool
    log_publishing_options: dict[str, Any]


def check_opensearch_audit_logging(
    domain_arn: str,
    domain_name: str,
    log_publishing_options: dict[str, Any],
) -> OpenSearchAuditLoggingResult:
    if not isinstance(log_publishing_options, dict):
        log_publishing_options = {}

    audit_config = log_publishing_options.get(
        AUDIT_LOG_KEY,
        {},
    )

    if not isinstance(audit_config, dict):
        audit_config = {}

    enabled = audit_config.get("Enabled") is True

    return OpenSearchAuditLoggingResult(
        domain_arn=domain_arn,
        domain_name=domain_name,
        audit_logging_enabled=enabled,
        log_publishing_options=log_publishing_options,
    )


def build_opensearch_audit_logging_finding(
    result: OpenSearchAuditLoggingResult,
) -> Finding | None:
    if result.audit_logging_enabled:
        return None

    return Finding(
        rule_id="CS-AWS-OPENSEARCH-005",
        title="OpenSearch Audit Logging Is Not Enabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="opensearch_domain",
        resource_id=result.domain_arn,
        description=(
            "Audit log publishing is not enabled for the "
            "OpenSearch domain."
        ),
        evidence={
            "domain_name": result.domain_name,
            "audit_logging_enabled": (
                result.audit_logging_enabled
            ),
            "log_publishing_options": (
                result.log_publishing_options
            ),
        },
        remediation=(
            "Enable OpenSearch audit log publishing to "
            "CloudWatch Logs."
        ),
        compliance=[
            "AWS Security Hub Opensearch.5",
        ],
    )
