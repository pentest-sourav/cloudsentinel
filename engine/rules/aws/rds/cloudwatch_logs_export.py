from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class RDSCloudWatchLogsExportResult:
    db_instance_id: str
    enabled_cloudwatch_logs_exports: tuple[str, ...]


def _is_aurora_engine(engine: str | None) -> bool:
    if not engine:
        return False

    return engine.lower().startswith("aurora")


def _is_rds_custom_engine(engine: str | None) -> bool:
    if not engine:
        return False

    return engine.lower().startswith("custom-")


def check_rds_cloudwatch_logs_export(
    db_instance_id: str,
    engine: str | None,
    enabled_cloudwatch_logs_exports: list[str] | tuple[str, ...] | None,
) -> RDSCloudWatchLogsExportResult | None:
    """
    Detect RDS instances without any CloudWatch Logs exports.

    Aurora is excluded because its log-export configuration is managed
    at the DB-cluster level.

    RDS Custom is excluded because this control does not safely apply
    to the custom deployment model.

    Missing API data is treated as unknown rather than non-compliant.
    """
    if not db_instance_id:
        return None

    if not engine:
        return None

    if _is_aurora_engine(engine):
        return None

    if _is_rds_custom_engine(engine):
        return None

    if enabled_cloudwatch_logs_exports is None:
        return None

    normalized_logs = tuple(
        sorted(
            {
                str(log_type).strip()
                for log_type in enabled_cloudwatch_logs_exports
                if str(log_type).strip()
            }
        )
    )

    if normalized_logs:
        return None

    return RDSCloudWatchLogsExportResult(
        db_instance_id=db_instance_id,
        enabled_cloudwatch_logs_exports=normalized_logs,
    )


def build_rds_cloudwatch_logs_export_finding(
    result: RDSCloudWatchLogsExportResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-RDS-008",
        title="RDS CloudWatch Log Export Is Disabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="rds_instance",
        resource_id=result.db_instance_id,
        description=(
            f"The RDS instance {result.db_instance_id} "
            "does not export any database logs to Amazon CloudWatch "
            "Logs. Without centralized database log collection, "
            "security monitoring and investigation visibility may "
            "be reduced."
        ),
        evidence={
            "db_instance_id": result.db_instance_id,
            "enabled_cloudwatch_logs_exports": list(
                result.enabled_cloudwatch_logs_exports
            ),
        },
        remediation=(
            "Enable appropriate database log exports to Amazon "
            "CloudWatch Logs based on the database engine and the "
            "application's monitoring and incident-response "
            "requirements."
        ),
    )
