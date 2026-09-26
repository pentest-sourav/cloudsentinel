from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class EFSResult:
    resource_id: str
    resource_type: str
    details: dict


def check_efs_encryption(
    resource_id: str,
    encrypted: bool,
    kms_key_id: str | None,
) -> EFSResult | None:
    if not resource_id:
        return None

    if encrypted:
        return None

    return EFSResult(
        resource_id=resource_id,
        resource_type="efs_file_system",
        details={
            "encrypted": encrypted,
            "kms_key_id": kms_key_id,
        },
    )


def build_efs_encryption_finding(
    result: EFSResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-EFS-001",
        title="EFS file system is not encrypted at rest",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The EFS file system {result.resource_id} "
            "does not have encryption at rest enabled."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Create a new encrypted EFS file system and "
            "migrate the data if encryption was not enabled "
            "when the existing file system was created."
        ),
        compliance=[
            "AWS Security Hub EFS.8",
            "CIS AWS Foundations Benchmark 5.0.0/2.3.1",
        ],
    )


def check_efs_automatic_backups(
    resource_id: str,
    backup: bool,
    backup_policy_status: str | None,
) -> EFSResult | None:
    if not resource_id:
        return None

    if backup or backup_policy_status in {
        "ENABLED",
        "ENABLING",
    }:
        return None

    return EFSResult(
        resource_id=resource_id,
        resource_type="efs_file_system",
        details={
            "backup": backup,
            "backup_policy_status": backup_policy_status,
        },
    )


def build_efs_automatic_backups_finding(
    result: EFSResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-EFS-002",
        title="EFS automatic backups are not enabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The EFS file system {result.resource_id} "
            "does not have automatic backups enabled."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Enable automatic backups for the EFS file "
            "system using its backup policy."
        ),
        compliance=[
            "AWS Security Hub EFS.7",
        ],
    )


def check_efs_access_point_root_directory(
    resource_id: str,
    root_directory_path: str | None,
) -> EFSResult | None:
    if not resource_id:
        return None

    if (
        isinstance(root_directory_path, str)
        and root_directory_path
        and root_directory_path != "/"
    ):
        return None

    return EFSResult(
        resource_id=resource_id,
        resource_type="efs_access_point",
        details={
            "root_directory_path": root_directory_path,
            "root_directory_enforced": False,
        },
    )


def build_efs_access_point_root_directory_finding(
    result: EFSResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-EFS-003",
        title="EFS access point does not enforce a root directory",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The EFS access point {result.resource_id} "
            "does not restrict clients to a dedicated "
            "root directory."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Configure the EFS access point RootDirectory "
            "Path to a dedicated subdirectory instead of "
            "the file system root."
        ),
        compliance=[
            "AWS Security Hub EFS.3",
            "NIST SP 800-53 Rev. 5 AC-6(10)",
        ],
    )


def check_efs_access_point_user_identity(
    resource_id: str,
    posix_uid: int | None,
    posix_gid: int | None,
) -> EFSResult | None:
    if not resource_id:
        return None

    if (
        isinstance(posix_uid, int)
        and isinstance(posix_gid, int)
    ):
        return None

    return EFSResult(
        resource_id=resource_id,
        resource_type="efs_access_point",
        details={
            "posix_uid": posix_uid,
            "posix_gid": posix_gid,
            "user_identity_enforced": False,
        },
    )


def build_efs_access_point_user_identity_finding(
    result: EFSResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-EFS-004",
        title="EFS access point does not enforce a user identity",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The EFS access point {result.resource_id} "
            "does not define a POSIX user identity."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Configure a POSIX UID and GID on the EFS "
            "access point so requests through the access "
            "point use an enforced identity."
        ),
        compliance=[
            "AWS Security Hub EFS.4",
            "NIST SP 800-53 Rev. 5 AC-6(2)",
            "PCI DSS v4.0.1/7.3.1",
        ],
    )
