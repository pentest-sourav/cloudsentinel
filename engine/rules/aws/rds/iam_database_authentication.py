from dataclasses import dataclass

from engine.findings.model import Finding, Severity


_SUPPORTED_ENGINES = {
    "mariadb",
    "mysql",
    "postgres",
}


@dataclass(frozen=True)
class RDSIAMDatabaseAuthenticationResult:
    db_instance_id: str
    engine: str
    iam_database_authentication_enabled: bool


def check_rds_iam_database_authentication(
    db_instance_id: str,
    engine: str | None,
    iam_database_authentication_enabled: bool | None,
) -> RDSIAMDatabaseAuthenticationResult | None:
    """
    Detect supported RDS engines where IAM database authentication
    is disabled.

    IAM database authentication is only evaluated for engines where
    AWS documents support for the feature. Unknown engines are ignored
    rather than being treated as non-compliant.
    """
    if not db_instance_id:
        return None

    if not engine:
        return None

    normalized_engine = engine.strip().lower()

    if normalized_engine not in _SUPPORTED_ENGINES:
        return None

    if iam_database_authentication_enabled is None:
        return None

    if iam_database_authentication_enabled:
        return None

    return RDSIAMDatabaseAuthenticationResult(
        db_instance_id=db_instance_id,
        engine=normalized_engine,
        iam_database_authentication_enabled=(
            iam_database_authentication_enabled
        ),
    )


def build_rds_iam_database_authentication_finding(
    result: RDSIAMDatabaseAuthenticationResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-RDS-007",
        title="RDS IAM Database Authentication Is Disabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="rds_instance",
        resource_id=result.db_instance_id,
        description=(
            f"The RDS {result.engine} instance "
            f"{result.db_instance_id} does not have IAM database "
            "authentication enabled. IAM database authentication "
            "can reduce reliance on long-lived database passwords "
            "by using short-lived AWS authentication tokens."
        ),
        evidence={
            "db_instance_id": result.db_instance_id,
            "engine": result.engine,
            "iam_database_authentication_enabled": (
                result.iam_database_authentication_enabled
            ),
        },
        remediation=(
            "Evaluate whether IAM database authentication is suitable "
            "for the workload and enable it for supported RDS engines "
            "when appropriate. Update applications and database users "
            "to use IAM authentication before removing existing "
            "password-based authentication."
        ),
    )
