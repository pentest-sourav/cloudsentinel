from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class FSxResult:
    resource_id: str
    resource_type: str
    details: dict


def check_fsx_openzfs_copy_tags(
    resource_id: str,
    file_system_type: str,
    openzfs_copy_tags_to_backups: bool,
    openzfs_copy_tags_to_volumes: bool,
) -> FSxResult | None:
    if not resource_id:
        return None

    if file_system_type != "OPENZFS":
        return None

    if (
        openzfs_copy_tags_to_backups
        and openzfs_copy_tags_to_volumes
    ):
        return None

    return FSxResult(
        resource_id=resource_id,
        resource_type="fsx_file_system",
        details={
            "file_system_type": file_system_type,
            "copy_tags_to_backups": (
                openzfs_copy_tags_to_backups
            ),
            "copy_tags_to_volumes": (
                openzfs_copy_tags_to_volumes
            ),
        },
    )


def build_fsx_openzfs_copy_tags_finding(
    result: FSxResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-FSX-001",
        title=(
            "FSx for OpenZFS is not configured to "
            "copy tags to backups and volumes"
        ),
        severity=Severity.LOW,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The FSx for OpenZFS file system "
            f"{result.resource_id} is not configured "
            "to copy tags to both backups and volumes."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Configure the FSx for OpenZFS file system "
            "to copy tags to backups and volumes."
        ),
        compliance=[
            "AWS Security Hub FSx.1",
            "NIST SP 800-53 Rev. 5 CA-9(1)",
            "NIST SP 800-53 Rev. 5 CM-2",
            "NIST SP 800-53 Rev. 5 CM-2(2)",
        ],
    )


def check_fsx_lustre_copy_tags(
    resource_id: str,
    file_system_type: str,
    lustre_copy_tags_to_backups: bool,
) -> FSxResult | None:
    if not resource_id:
        return None

    if file_system_type != "LUSTRE":
        return None

    if lustre_copy_tags_to_backups:
        return None

    return FSxResult(
        resource_id=resource_id,
        resource_type="fsx_file_system",
        details={
            "file_system_type": file_system_type,
            "copy_tags_to_backups": (
                lustre_copy_tags_to_backups
            ),
        },
    )


def build_fsx_lustre_copy_tags_finding(
    result: FSxResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-FSX-002",
        title=(
            "FSx for Lustre is not configured to "
            "copy tags to backups"
        ),
        severity=Severity.LOW,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The FSx for Lustre file system "
            f"{result.resource_id} is not configured "
            "to copy tags to backups."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Configure the FSx for Lustre file system "
            "to copy tags to backups."
        ),
        compliance=[
            "AWS Security Hub FSx.2",
            "NIST SP 800-53 Rev. 5 CP-9",
            "NIST SP 800-53 Rev. 5 CM-8",
        ],
    )


def check_fsx_openzfs_multi_az(
    resource_id: str,
    file_system_type: str,
    openzfs_deployment_type: str | None,
) -> FSxResult | None:
    if not resource_id:
        return None

    if file_system_type != "OPENZFS":
        return None

    if openzfs_deployment_type == "MULTI_AZ_1":
        return None

    return FSxResult(
        resource_id=resource_id,
        resource_type="fsx_file_system",
        details={
            "file_system_type": file_system_type,
            "deployment_type": openzfs_deployment_type,
            "required_deployment_type": "MULTI_AZ_1",
        },
    )


def build_fsx_openzfs_multi_az_finding(
    result: FSxResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-FSX-003",
        title=(
            "FSx for OpenZFS is not configured "
            "for Multi-AZ deployment"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The FSx for OpenZFS file system "
            f"{result.resource_id} does not use the "
            "required Multi-AZ deployment type."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Create a new FSx for OpenZFS file system "
            "using the MULTI_AZ_1 deployment type and "
            "migrate the data if the existing deployment "
            "type cannot be changed."
        ),
        compliance=[
            "AWS Security Hub FSx.3",
        ],
    )


def check_fsx_ontap_multi_az(
    resource_id: str,
    file_system_type: str,
    ontap_deployment_type: str | None,
) -> FSxResult | None:
    if not resource_id:
        return None

    if file_system_type != "ONTAP":
        return None

    if ontap_deployment_type in {
        "MULTI_AZ_1",
        "MULTI_AZ_2",
    }:
        return None

    return FSxResult(
        resource_id=resource_id,
        resource_type="fsx_file_system",
        details={
            "file_system_type": file_system_type,
            "deployment_type": ontap_deployment_type,
            "required_deployment_types": [
                "MULTI_AZ_1",
                "MULTI_AZ_2",
            ],
        },
    )


def build_fsx_ontap_multi_az_finding(
    result: FSxResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-FSX-004",
        title=(
            "FSx for NetApp ONTAP is not configured "
            "for Multi-AZ deployment"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The FSx for NetApp ONTAP file system "
            f"{result.resource_id} does not use a "
            "Multi-AZ deployment type."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Create a new FSx for NetApp ONTAP file system "
            "using a Multi-AZ deployment type and migrate "
            "the data if the existing deployment type "
            "cannot be changed."
        ),
        compliance=[
            "AWS Security Hub FSx.4",
        ],
    )


def check_fsx_windows_multi_az(
    resource_id: str,
    file_system_type: str,
    windows_deployment_type: str | None,
) -> FSxResult | None:
    if not resource_id:
        return None

    if file_system_type != "WINDOWS":
        return None

    if windows_deployment_type == "MULTI_AZ_1":
        return None

    return FSxResult(
        resource_id=resource_id,
        resource_type="fsx_file_system",
        details={
            "file_system_type": file_system_type,
            "deployment_type": windows_deployment_type,
            "required_deployment_type": "MULTI_AZ_1",
        },
    )


def build_fsx_windows_multi_az_finding(
    result: FSxResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-FSX-005",
        title=(
            "FSx for Windows File Server is not "
            "configured for Multi-AZ deployment"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The FSx for Windows File Server file system "
            f"{result.resource_id} does not use the "
            "required Multi-AZ deployment type."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Create a new FSx for Windows File Server "
            "file system using the MULTI_AZ_1 deployment "
            "type and migrate the data if the existing "
            "deployment type cannot be changed."
        ),
        compliance=[
            "AWS Security Hub FSx.5",
        ],
    )
