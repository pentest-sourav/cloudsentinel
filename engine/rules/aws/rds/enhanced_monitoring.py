from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class RDSEnhancedMonitoringResult:
    db_instance_id: str
    monitoring_interval: int


def check_rds_enhanced_monitoring(
    db_instance_id: str,
    monitoring_interval: int | None,
) -> RDSEnhancedMonitoringResult | None:
    """
    Detect RDS DB instances without Enhanced Monitoring.

    AWS RDS uses a MonitoringInterval of 0 to disable Enhanced
    Monitoring. Valid enabled intervals are 1, 5, 10, 15, 30,
    and 60 seconds.

    Missing API data is treated as unknown rather than
    non-compliant to avoid false positives.
    """
    if not db_instance_id:
        return None

    if monitoring_interval is None:
        return None

    if monitoring_interval != 0:
        return None

    return RDSEnhancedMonitoringResult(
        db_instance_id=db_instance_id,
        monitoring_interval=monitoring_interval,
    )


def build_rds_enhanced_monitoring_finding(
    result: RDSEnhancedMonitoringResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-RDS-009",
        title="RDS Enhanced Monitoring Is Disabled",
        severity=Severity.LOW,
        provider="aws",
        resource_type="rds_instance",
        resource_id=result.db_instance_id,
        description=(
            f"The RDS instance {result.db_instance_id} "
            "does not have Enhanced Monitoring enabled. "
            "Without Enhanced Monitoring, CloudSentinel has "
            "reduced visibility into operating-system-level "
            "metrics and process activity for the DB instance."
        ),
        evidence={
            "db_instance_id": result.db_instance_id,
            "monitoring_interval": result.monitoring_interval,
        },
        remediation=(
            "Enable Enhanced Monitoring for the RDS instance "
            "and configure an appropriate monitoring interval "
            "such as 1, 5, 10, 15, 30, or 60 seconds."
        ),
        compliance=[
            "AWS Security Hub CSPM RDS.6",
        ],
    )
