from engine.rules.aws.rds.iam_database_authentication import (
    build_rds_iam_database_authentication_finding,
    check_rds_iam_database_authentication,
)


def test_detects_disabled_iam_database_authentication():
    result = check_rds_iam_database_authentication(
        db_instance_id="db-1",
        engine="postgres",
        iam_database_authentication_enabled=False,
    )

    assert result is not None
    assert result.engine == "postgres"

    finding = build_rds_iam_database_authentication_finding(result)

    assert finding.rule_id == "CS-AWS-RDS-007"
    assert finding.severity.value == "medium"


def test_accepts_enabled_iam_database_authentication():
    assert (
        check_rds_iam_database_authentication(
            db_instance_id="db-1",
            engine="mysql",
            iam_database_authentication_enabled=True,
        )
        is None
    )


def test_skips_unsupported_engine():
    assert (
        check_rds_iam_database_authentication(
            db_instance_id="db-1",
            engine="oracle-ee",
            iam_database_authentication_enabled=False,
        )
        is None
    )


def test_skips_missing_engine():
    assert (
        check_rds_iam_database_authentication(
            db_instance_id="db-1",
            engine=None,
            iam_database_authentication_enabled=False,
        )
        is None
    )


def test_skips_missing_iam_authentication_data():
    assert (
        check_rds_iam_database_authentication(
            db_instance_id="db-1",
            engine="mariadb",
            iam_database_authentication_enabled=None,
        )
        is None
    )
