from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class EMRClusterResult:
    cluster_id: str


@dataclass(frozen=True)
class EMRSecurityConfigurationResult:
    security_configuration_name: str


@dataclass(frozen=True)
class EMRBlockPublicAccessResult:
    reason: str


def _cluster_result(
    cluster_id: str,
) -> EMRClusterResult | None:
    if not cluster_id:
        return None

    return EMRClusterResult(
        cluster_id=cluster_id,
    )


def check_emr_primary_node_public_ip(
    cluster_id: str,
    master_has_public_ip: bool | None,
) -> EMRClusterResult | None:
    if not cluster_id or master_has_public_ip is None:
        return None

    if not master_has_public_ip:
        return None

    return _cluster_result(cluster_id)


def build_emr_primary_node_public_ip_finding(
    result: EMRClusterResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-EMR-001",
        title="EMR Cluster Primary Node Has a Public IP Address",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="emr_cluster",
        resource_id=result.cluster_id,
        description=(
            f"The EMR cluster {result.cluster_id} has a primary "
            "node with a public IP address."
        ),
        evidence={
            "cluster_id": result.cluster_id,
            "master_has_public_ip": True,
        },
        remediation=(
            "Remove public IP addressing from EMR primary nodes "
            "and place the cluster in private subnets. Use controlled "
            "access paths such as a bastion host, VPN, or AWS Systems "
            "Manager where administrative access is required."
        ),
        compliance=[
            "AWS Foundational Security Best Practices",
            "NIST SP 800-53 Rev. 5",
        ],
    )


def check_emr_block_public_access(
    block_public_security_group_rules: bool | None,
    has_unsafe_public_access_exception: bool | None,
) -> EMRBlockPublicAccessResult | None:
    if block_public_security_group_rules is None:
        return None

    if block_public_security_group_rules:
        if has_unsafe_public_access_exception:
            return EMRBlockPublicAccessResult(
                reason="unsafe_public_access_exception"
            )

        return None

    return EMRBlockPublicAccessResult(
        reason="block_public_access_disabled"
    )


def build_emr_block_public_access_finding(
    result: EMRBlockPublicAccessResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-EMR-002",
        title="EMR Block Public Access Is Not Securely Configured",
        severity=Severity.CRITICAL,
        provider="aws",
        resource_type="emr_block_public_access_configuration",
        resource_id="regional-configuration",
        description=(
            "Amazon EMR Block Public Access is either disabled or "
            "permits a public security group rule range other than "
            "the documented SSH port 22 exception."
        ),
        evidence={
            "configuration_issue": result.reason,
        },
        remediation=(
            "Enable EMR Block Public Access and restrict permitted "
            "public security group rule exceptions to TCP port 22 "
            "only when such access is explicitly required."
        ),
        compliance=[
            "AWS Foundational Security Best Practices",
            "NIST SP 800-53 Rev. 5",
        ],
    )


def _security_configuration_result(
    name: str,
) -> EMRSecurityConfigurationResult | None:
    if not name:
        return None

    return EMRSecurityConfigurationResult(
        security_configuration_name=name,
    )


def check_emr_at_rest_encryption(
    security_configuration_name: str,
    enable_at_rest_encryption: bool | None,
) -> EMRSecurityConfigurationResult | None:
    if (
        not security_configuration_name
        or enable_at_rest_encryption is None
    ):
        return None

    if enable_at_rest_encryption:
        return None

    return _security_configuration_result(
        security_configuration_name
    )


def build_emr_at_rest_encryption_finding(
    result: EMRSecurityConfigurationResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-EMR-003",
        title="EMR Security Configuration Does Not Enable Encryption at Rest",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="emr_security_configuration",
        resource_id=result.security_configuration_name,
        description=(
            f"The EMR security configuration "
            f"{result.security_configuration_name} does not enable "
            "encryption at rest."
        ),
        evidence={
            "security_configuration_name": (
                result.security_configuration_name
            ),
            "enable_at_rest_encryption": False,
        },
        remediation=(
            "Configure the EMR security configuration with "
            "EnableAtRestEncryption set to true and define the "
            "required encryption key and storage encryption settings."
        ),
        compliance=[
            "AWS Foundational Security Best Practices",
            "NIST SP 800-53 Rev. 5",
        ],
    )


def check_emr_in_transit_encryption(
    security_configuration_name: str,
    enable_in_transit_encryption: bool | None,
) -> EMRSecurityConfigurationResult | None:
    if (
        not security_configuration_name
        or enable_in_transit_encryption is None
    ):
        return None

    if enable_in_transit_encryption:
        return None

    return _security_configuration_result(
        security_configuration_name
    )


def build_emr_in_transit_encryption_finding(
    result: EMRSecurityConfigurationResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-EMR-004",
        title="EMR Security Configuration Does Not Enable Encryption in Transit",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="emr_security_configuration",
        resource_id=result.security_configuration_name,
        description=(
            f"The EMR security configuration "
            f"{result.security_configuration_name} does not enable "
            "encryption in transit."
        ),
        evidence={
            "security_configuration_name": (
                result.security_configuration_name
            ),
            "enable_in_transit_encryption": False,
        },
        remediation=(
            "Configure the EMR security configuration with "
            "EnableInTransitEncryption set to true and provide "
            "the required private key and certificate configuration."
        ),
        compliance=[
            "AWS Foundational Security Best Practices",
            "NIST SP 800-53 Rev. 5",
        ],
    )
