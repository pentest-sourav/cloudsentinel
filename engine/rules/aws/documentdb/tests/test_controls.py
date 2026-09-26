from engine.findings.model import Severity
from engine.rules.aws.documentdb.controls import (
    check_documentdb_audit_logs,
    check_documentdb_backup_retention,
    check_documentdb_deletion_protection,
    check_documentdb_encryption,
    check_documentdb_snapshot_private,
    check_documentdb_tls,
)


def test_encryption_pass_and_fail():
    assert check_documentdb_encryption("cluster-1", True) is None

    result = check_documentdb_encryption("cluster-1", False)

    assert result is not None
    assert result.evidence["storage_encrypted"] is False


def test_backup_retention_requires_seven_days():
    assert check_documentdb_backup_retention("cluster-1", 7) is None
    assert check_documentdb_backup_retention("cluster-1", 14) is None

    result = check_documentdb_backup_retention("cluster-1", 6)

    assert result is not None
    assert result.evidence["minimum_required_days"] == 7


def test_public_snapshot_detection():
    assert check_documentdb_snapshot_private(
        "snapshot-1",
        [],
    ) is None

    assert check_documentdb_snapshot_private(
        "snapshot-1",
        ["123456789012"],
    ) is None

    result = check_documentdb_snapshot_private(
        "snapshot-1",
        ["all"],
    )

    assert result is not None

    # "*" is not the AWS DocumentDB public marker.
    assert check_documentdb_snapshot_private(
        "snapshot-1",
        ["*"],
    ) is None
    assert result.evidence["public_access"] is True


def test_audit_logs_require_audit_export():
    assert check_documentdb_audit_logs(
        "cluster-1",
        ["profiler", "audit"],
    ) is None

    result = check_documentdb_audit_logs(
        "cluster-1",
        ["profiler"],
    )

    assert result is not None
    assert result.evidence["audit_logs_enabled"] is False


def test_deletion_protection():
    assert check_documentdb_deletion_protection(
        "cluster-1",
        True,
    ) is None

    result = check_documentdb_deletion_protection(
        "cluster-1",
        False,
    )

    assert result is not None
    assert result.evidence["deletion_protection"] is False


def test_tls_accepts_strong_values():
    for value in ("tls1.2+", "tls1.3+", "fips-140-3"):
        assert check_documentdb_tls(
            "cluster-1",
            "custom-docdb",
            "in-sync",
            value,
        ) is None


def test_tls_rejects_disabled_and_enabled():
    for value in ("disabled", "enabled"):
        result = check_documentdb_tls(
            "cluster-1",
            "custom-docdb",
            "in-sync",
            value,
        )

        assert result is not None
        assert result.evidence["tls_parameter"] == value


def test_tls_rejects_out_of_sync_parameter_group():
    result = check_documentdb_tls(
        "cluster-1",
        "custom-docdb",
        "applying",
        "tls1.2+",
    )

    assert result is not None
    assert result.evidence["parameter_group_in_sync"] is False


def test_tls_missing_parameter_group_fails_closed():
    result = check_documentdb_tls(
        "cluster-1",
        None,
        None,
        None,
    )

    assert result is not None
    assert result.evidence["parameter_group_in_sync"] is False


def test_finding_severity_contracts():
    from engine.rules.aws.documentdb.controls import (
        build_documentdb_encryption_finding,
        build_documentdb_snapshot_private_finding,
    )

    encryption = check_documentdb_encryption("cluster-1", False)
    snapshot = check_documentdb_snapshot_private("snapshot-1", ["all"])

    assert encryption is not None
    assert snapshot is not None

    assert (
        build_documentdb_encryption_finding(encryption).severity
        == Severity.MEDIUM
    )
    assert (
        build_documentdb_snapshot_private_finding(snapshot).severity
        == Severity.CRITICAL
    )
