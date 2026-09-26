from engine.findings.model import Severity
from engine.rules.aws.efs.protection import (
    build_efs_access_point_root_directory_finding,
    build_efs_access_point_user_identity_finding,
    build_efs_automatic_backups_finding,
    build_efs_encryption_finding,
    check_efs_access_point_root_directory,
    check_efs_access_point_user_identity,
    check_efs_automatic_backups,
    check_efs_encryption,
)


def test_encrypted_file_system_passes():
    assert (
        check_efs_encryption(
            "fs-1",
            True,
            "kms-key",
        )
        is None
    )


def test_unencrypted_file_system_fails():
    result = check_efs_encryption(
        "fs-1",
        False,
        None,
    )

    finding = build_efs_encryption_finding(result)

    assert finding.rule_id == "CS-AWS-EFS-001"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_id == "fs-1"
    assert finding.evidence["encrypted"] is False


def test_automatic_backup_enabled_passes():
    assert (
        check_efs_automatic_backups(
            "fs-1",
            True,
            "ENABLED",
        )
        is None
    )


def test_automatic_backup_disabled_fails():
    result = check_efs_automatic_backups(
        "fs-1",
        False,
        "DISABLED",
    )

    finding = build_efs_automatic_backups_finding(result)

    assert finding.rule_id == "CS-AWS-EFS-002"
    assert finding.evidence["backup"] is False


def test_root_directory_is_enforced():
    assert (
        check_efs_access_point_root_directory(
            "ap-1",
            "/application",
        )
        is None
    )


def test_root_directory_is_not_enforced():
    result = check_efs_access_point_root_directory(
        "ap-1",
        "/",
    )

    finding = build_efs_access_point_root_directory_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-EFS-003"
    assert finding.evidence["root_directory_enforced"] is False


def test_posix_identity_is_enforced():
    assert (
        check_efs_access_point_user_identity(
            "ap-1",
            1000,
            1000,
        )
        is None
    )


def test_posix_identity_is_missing():
    result = check_efs_access_point_user_identity(
        "ap-1",
        None,
        None,
    )

    finding = build_efs_access_point_user_identity_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-EFS-004"
    assert finding.evidence["user_identity_enforced"] is False
