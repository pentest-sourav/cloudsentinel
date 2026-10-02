from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class RDSResilienceResult:
    resource_id: str
    resource_type: str
    control: str
    evidence: dict


def _result(
    resource_id: str,
    resource_type: str,
    control: str,
    evidence: dict,
) -> RDSResilienceResult:
    return RDSResilienceResult(
        resource_id=resource_id,
        resource_type=resource_type,
        control=control,
        evidence=evidence,
    )


def _finding(
    result: RDSResilienceResult,
    rule_id: str,
    title: str,
    severity: Severity,
    description: str,
    remediation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=description,
        evidence=result.evidence,
        remediation=remediation,
        compliance=[
            "AWS Security Hub CSPM",
        ],
    )


def check_rds_aurora_backtracking(
    db_cluster_id: str,
    engine: str | None,
    backtrack_window: int | None,
) -> RDSResilienceResult | None:
    if not db_cluster_id or not engine:
        return None

    normalized_engine = engine.lower()

    if normalized_engine not in {
        "aurora",
        "aurora-mysql",
    }:
        return None

    if backtrack_window is None:
        return None

    if backtrack_window > 0:
        return None

    return _result(
        db_cluster_id,
        "rds_cluster",
        "aurora_backtracking",
        {
            "db_cluster_id": db_cluster_id,
            "engine": engine,
            "backtrack_window": backtrack_window,
            "backtracking_enabled": False,
        },
    )


def build_rds_aurora_backtracking_finding(
    result: RDSResilienceResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-RDS-030",
        "Aurora MySQL Backtracking Is Disabled",
        Severity.MEDIUM,
        (
            f"Aurora MySQL cluster {result.resource_id} has "
            "backtracking disabled."
        ),
        (
            "Create an Aurora MySQL cluster with backtracking enabled "
            "and configure an appropriate backtrack window."
        ),
    )


def check_rds_cluster_multi_az(
    db_cluster_id: str,
    engine: str | None,
    availability_zone_count: int | None,
) -> RDSResilienceResult | None:
    if not db_cluster_id or availability_zone_count is None:
        return None

    if availability_zone_count >= 2:
        return None

    return _result(
        db_cluster_id,
        "rds_cluster",
        "cluster_multi_az",
        {
            "db_cluster_id": db_cluster_id,
            "engine": engine,
            "availability_zone_count": availability_zone_count,
            "multi_az": False,
        },
    )


def build_rds_cluster_multi_az_finding(
    result: RDSResilienceResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-RDS-031",
        "RDS DB Cluster Is Not Deployed Across Multiple Availability Zones",
        Severity.MEDIUM,
        (
            f"RDS DB cluster {result.resource_id} is associated with "
            "fewer than two Availability Zones."
        ),
        (
            "Configure the RDS DB cluster across multiple Availability "
            "Zones to provide high availability and failover resilience."
        ),
    )


def _parse_aurora_mysql_version(
    version: str,
) -> tuple[int, ...] | None:
    marker = "mysql_aurora."

    if marker not in version:
        return None

    suffix = version.split(marker, 1)[1]

    parts = suffix.split(".")

    if not parts:
        return None

    numbers: list[int] = []

    for part in parts:
        digits = ""

        for character in part:
            if character.isdigit():
                digits += character
            else:
                break

        if not digits:
            return None

        numbers.append(int(digits))

    return tuple(numbers)


def _is_supported_aurora_mysql_global_version(
    version: str,
) -> bool:
    parsed = _parse_aurora_mysql_version(version)

    if parsed is None:
        return False

    minimum_supported = (3, 8, 0)

    if parsed >= minimum_supported:
        return True

    # AWS Security Hub currently lists these Aurora MySQL 3.04.x
    # versions as long-term-support exceptions.
    lts_versions = {
        (3, 4, 0),
        (3, 4, 1),
        (3, 4, 2),
        (3, 4, 3),
    }

    return parsed in lts_versions


def check_rds_global_cluster_supported_version(
    global_cluster_id: str,
    engine: str | None,
    engine_version: str | None,
) -> RDSResilienceResult | None:
    if (
        not global_cluster_id
        or not engine
        or not engine_version
    ):
        return None

    if engine.lower() != "aurora-mysql":
        return None

    if _is_supported_aurora_mysql_global_version(
        engine_version
    ):
        return None

    return _result(
        global_cluster_id,
        "rds_global_cluster",
        "global_cluster_supported_version",
        {
            "global_cluster_id": global_cluster_id,
            "engine": engine,
            "engine_version": engine_version,
            "minimum_supported_version": (
                "8.0.mysql_aurora.3.08.0"
            ),
            "long_term_support_versions": [
                "8.0.mysql_aurora.3.04.0",
                "8.0.mysql_aurora.3.04.1",
                "8.0.mysql_aurora.3.04.2",
                "8.0.mysql_aurora.3.04.3",
            ],
        },
    )


def build_rds_global_cluster_supported_version_finding(
    result: RDSResilienceResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-RDS-032",
        "RDS Global Aurora MySQL Cluster Uses an Unsupported Version",
        Severity.HIGH,
        (
            f"RDS global cluster {result.resource_id} runs "
            f"Aurora MySQL version "
            f"{result.evidence['engine_version']}, which is below "
            "the currently supported Security Hub threshold and "
            "is not one of the listed long-term-support exceptions."
        ),
        (
            "Upgrade the Aurora MySQL global cluster to a currently "
            "supported engine version or an AWS-listed long-term "
            "support version."
        ),
    )
