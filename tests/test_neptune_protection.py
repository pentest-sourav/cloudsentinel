from engine.findings.model import Severity
from engine.rules.aws.neptune.protection import (
    build_neptune_audit_logging_finding,
    build_neptune_backup_retention_finding,
    build_neptune_deletion_protection_finding,
    build_neptune_encryption_finding,
    build_neptune_iam_authentication_finding,
    build_neptune_multi_az_finding,
    build_neptune_snapshot_encryption_finding,
    build_neptune_snapshot_public_finding,
    check_neptune_audit_logging,
    check_neptune_backup_retention,
    check_neptune_deletion_protection,
    check_neptune_encryption,
    check_neptune_iam_authentication,
    check_neptune_multi_az,
    check_neptune_snapshot_encryption,
    check_neptune_snapshot_public,
)


def test_encryption_rule():
    assert check_neptune_encryption(
        "cluster-1",
        True,
    ) is None

    result = check_neptune_encryption(
        "cluster-1",
        False,
    )

    assert result.db_cluster_id == "cluster-1"
    assert (
        build_neptune_encryption_finding(result).severity
        == Severity.MEDIUM
    )


def test_audit_logging_rule():
    assert check_neptune_audit_logging(
        "cluster-1",
        ["audit", "slowquery"],
    ) is None

    result = check_neptune_audit_logging(
        "cluster-1",
        ["slowquery"],
    )

    assert (
        build_neptune_audit_logging_finding(result).rule_id
        == "CS-AWS-NEPTUNE-002"
    )


def test_public_snapshot_rule():
    assert check_neptune_snapshot_public(
        "snapshot-1",
        False,
    ) is None

    result = check_neptune_snapshot_public(
        "snapshot-1",
        True,
    )

    assert (
        build_neptune_snapshot_public_finding(result).severity
        == Severity.CRITICAL
    )


def test_deletion_protection_rule():
    assert check_neptune_deletion_protection(
        "cluster-1",
        True,
    ) is None

    result = check_neptune_deletion_protection(
        "cluster-1",
        False,
    )

    assert (
        build_neptune_deletion_protection_finding(result).severity
        == Severity.LOW
    )


def test_backup_retention_rule():
    assert check_neptune_backup_retention(
        "cluster-1",
        7,
    ) is None

    result = check_neptune_backup_retention(
        "cluster-1",
        1,
    )

    assert result.db_cluster_id == "cluster-1"


def test_snapshot_encryption_rule():
    assert check_neptune_snapshot_encryption(
        "snapshot-1",
        True,
    ) is None

    result = check_neptune_snapshot_encryption(
        "snapshot-1",
        False,
    )

    assert (
        build_neptune_snapshot_encryption_finding(result).rule_id
        == "CS-AWS-NEPTUNE-006"
    )


def test_iam_authentication_rule():
    assert check_neptune_iam_authentication(
        "cluster-1",
        True,
    ) is None

    result = check_neptune_iam_authentication(
        "cluster-1",
        False,
    )

    assert (
        build_neptune_iam_authentication_finding(result).rule_id
        == "CS-AWS-NEPTUNE-007"
    )


def test_multi_az_rule():
    assert check_neptune_multi_az(
        "cluster-1",
        2,
    ) is None

    result = check_neptune_multi_az(
        "cluster-1",
        1,
    )

    assert (
        build_neptune_multi_az_finding(result).severity
        == Severity.MEDIUM
    )


def test_missing_data_does_not_create_findings():
    assert check_neptune_encryption(
        "cluster-1",
        None,
    ) is None

    assert check_neptune_backup_retention(
        "cluster-1",
        None,
    ) is None

    assert check_neptune_snapshot_public(
        "snapshot-1",
        None,
    ) is None

    assert check_neptune_multi_az(
        "cluster-1",
        None,
    ) is None
