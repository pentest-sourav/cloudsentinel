from engine.findings.model import Severity
from engine.rules.aws.fsx.protection import (
    build_fsx_lustre_copy_tags_finding,
    build_fsx_ontap_multi_az_finding,
    build_fsx_openzfs_copy_tags_finding,
    build_fsx_openzfs_multi_az_finding,
    build_fsx_windows_multi_az_finding,
    check_fsx_lustre_copy_tags,
    check_fsx_ontap_multi_az,
    check_fsx_openzfs_copy_tags,
    check_fsx_openzfs_multi_az,
    check_fsx_windows_multi_az,
)


def test_openzfs_copy_tags_passes_when_both_enabled():
    assert (
        check_fsx_openzfs_copy_tags(
            "fs-1",
            "OPENZFS",
            True,
            True,
        )
        is None
    )


def test_openzfs_copy_tags_fails_when_backup_copy_disabled():
    result = check_fsx_openzfs_copy_tags(
        "fs-1",
        "OPENZFS",
        False,
        True,
    )

    assert result is not None
    assert result.details["copy_tags_to_backups"] is False

    finding = build_fsx_openzfs_copy_tags_finding(result)

    assert finding.rule_id == "CS-AWS-FSX-001"
    assert finding.severity == Severity.LOW


def test_openzfs_copy_tags_ignores_other_file_system_types():
    assert (
        check_fsx_openzfs_copy_tags(
            "fs-1",
            "LUSTRE",
            False,
            False,
        )
        is None
    )


def test_lustre_copy_tags_passes_when_enabled():
    assert (
        check_fsx_lustre_copy_tags(
            "fs-1",
            "LUSTRE",
            True,
        )
        is None
    )


def test_lustre_copy_tags_fails_when_disabled():
    result = check_fsx_lustre_copy_tags(
        "fs-1",
        "LUSTRE",
        False,
    )

    assert result is not None

    finding = build_fsx_lustre_copy_tags_finding(result)

    assert finding.rule_id == "CS-AWS-FSX-002"
    assert finding.severity == Severity.LOW


def test_openzfs_multi_az_passes():
    assert (
        check_fsx_openzfs_multi_az(
            "fs-1",
            "OPENZFS",
            "MULTI_AZ_1",
        )
        is None
    )


def test_openzfs_multi_az_fails():
    result = check_fsx_openzfs_multi_az(
        "fs-1",
        "OPENZFS",
        "SINGLE_AZ_1",
    )

    assert result is not None

    finding = build_fsx_openzfs_multi_az_finding(result)

    assert finding.rule_id == "CS-AWS-FSX-003"
    assert finding.severity == Severity.MEDIUM


def test_ontap_multi_az_accepts_both_supported_multi_az_types():
    assert (
        check_fsx_ontap_multi_az(
            "fs-1",
            "ONTAP",
            "MULTI_AZ_1",
        )
        is None
    )

    assert (
        check_fsx_ontap_multi_az(
            "fs-2",
            "ONTAP",
            "MULTI_AZ_2",
        )
        is None
    )


def test_ontap_multi_az_fails_single_az():
    result = check_fsx_ontap_multi_az(
        "fs-1",
        "ONTAP",
        "SINGLE_AZ_1",
    )

    assert result is not None

    finding = build_fsx_ontap_multi_az_finding(result)

    assert finding.rule_id == "CS-AWS-FSX-004"
    assert finding.severity == Severity.MEDIUM


def test_windows_multi_az_passes():
    assert (
        check_fsx_windows_multi_az(
            "fs-1",
            "WINDOWS",
            "MULTI_AZ_1",
        )
        is None
    )


def test_windows_multi_az_fails_single_az():
    result = check_fsx_windows_multi_az(
        "fs-1",
        "WINDOWS",
        "SINGLE_AZ_1",
    )

    assert result is not None

    finding = build_fsx_windows_multi_az_finding(result)

    assert finding.rule_id == "CS-AWS-FSX-005"
    assert finding.severity == Severity.MEDIUM


def test_checks_ignore_wrong_file_system_types():
    assert (
        check_fsx_openzfs_multi_az(
            "fs-1",
            "LUSTRE",
            "SINGLE_AZ_1",
        )
        is None
    )

    assert (
        check_fsx_ontap_multi_az(
            "fs-1",
            "WINDOWS",
            "SINGLE_AZ_1",
        )
        is None
    )

    assert (
        check_fsx_windows_multi_az(
            "fs-1",
            "ONTAP",
            "SINGLE_AZ_1",
        )
        is None
    )
