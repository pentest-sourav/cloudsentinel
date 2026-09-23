from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class RDSAutoMinorVersionUpgradeResult:
    db_instance_id: str
    auto_minor_version_upgrade: bool


def _is_aurora_engine(engine: str | None) -> bool:
    if not engine:
        return False

    return engine.lower().startswith("aurora")


def _is_rds_custom_engine(engine: str | None) -> bool:
    if not engine:
        return False

    return engine.lower().startswith("custom-")


def check_rds_auto_minor_version_upgrade(
    db_instance_id: str,
    engine: str | None,
    auto_minor_version_upgrade: bool | None,
) -> RDSAutoMinorVersionUpgradeResult | None:
    """
    Detect RDS instances without automatic minor version upgrades.

    Aurora is excluded because Aurora minor-version upgrade behavior
    is governed at the DB-cluster level and requires cluster context.

    RDS Custom is excluded because AWS requires this setting to remain
    disabled for RDS Custom instances.
    """
    if not db_instance_id:
        return None

    if auto_minor_version_upgrade is None:
        return None

    if _is_aurora_engine(engine):
        return None

    if _is_rds_custom_engine(engine):
        return None

    if auto_minor_version_upgrade:
        return None

    return RDSAutoMinorVersionUpgradeResult(
        db_instance_id=db_instance_id,
        auto_minor_version_upgrade=auto_minor_version_upgrade,
    )


def build_rds_auto_minor_version_upgrade_finding(
    result: RDSAutoMinorVersionUpgradeResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-RDS-006",
        title="RDS Automatic Minor Version Upgrade Is Disabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="rds_instance",
        resource_id=result.db_instance_id,
        description=(
            f"The RDS instance {result.db_instance_id} "
            "does not have automatic minor version upgrades enabled. "
            "Automatic minor upgrades help keep supported database "
            "engines current with AWS-provided minor releases and "
            "security updates."
        ),
        evidence={
            "db_instance_id": result.db_instance_id,
            "auto_minor_version_upgrade": (
                result.auto_minor_version_upgrade
            ),
        },
        remediation=(
            "Enable automatic minor version upgrades for the RDS "
            "instance when compatible with the application's "
            "maintenance and upgrade requirements."
        ),
    )
