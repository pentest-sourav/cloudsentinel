from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class MSKResult:
    resource_id: str
    resource_type: str
    details: dict


def _result(
    resource_id: str,
    resource_type: str,
    details: dict,
) -> MSKResult | None:
    if not resource_id:
        return None

    return MSKResult(
        resource_id=resource_id,
        resource_type=resource_type,
        details=details,
    )


def check_msk_in_cluster_encryption(
    resource_id: str,
    in_cluster_encryption: bool | None,
) -> MSKResult | None:
    if not isinstance(in_cluster_encryption, bool):
        return None

    if in_cluster_encryption:
        return None

    return _result(
        resource_id,
        "msk_cluster",
        {"in_cluster_encryption": False},
    )


def build_msk_in_cluster_encryption_finding(
    result: MSKResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-MSK-001",
        title="MSK broker-to-broker traffic is not encrypted",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The MSK cluster {result.resource_id} "
            "does not encrypt traffic between broker nodes."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Configure the MSK cluster to encrypt "
            "communication between broker nodes."
        ),
        compliance=[
            "AWS Security Hub MSK.1",
            "NIST SP 800-53 Rev. 5 AC-4",
            "NIST SP 800-53 Rev. 5 SC-13",
            "NIST SP 800-53 Rev. 5 SC-23",
            "NIST SP 800-53 Rev. 5 SC-23(3)",
            "NIST SP 800-53 Rev. 5 SC-7(4)",
            "NIST SP 800-53 Rev. 5 SC-8",
            "NIST SP 800-53 Rev. 5 SC-8(1)",
            "NIST SP 800-53 Rev. 5 SC-8(2)",
            "PCI DSS v4.0.1/4.2.1",
        ],
    )


def check_msk_enhanced_monitoring(
    resource_id: str,
    cluster_type: str | None,
    enhanced_monitoring: str | None,
) -> MSKResult | None:
    if cluster_type != "PROVISIONED":
        return None

    if enhanced_monitoring in {
        "PER_TOPIC_PER_BROKER",
        "PER_TOPIC_PER_PARTITION",
    }:
        return None

    return _result(
        resource_id,
        "msk_cluster",
        {
            "cluster_type": cluster_type,
            "enhanced_monitoring": enhanced_monitoring,
        },
    )


def build_msk_enhanced_monitoring_finding(
    result: MSKResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-MSK-002",
        title="MSK enhanced monitoring is not configured",
        severity=Severity.LOW,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The provisioned MSK cluster {result.resource_id} "
            "does not use at least PER_TOPIC_PER_BROKER "
            "enhanced monitoring."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Configure enhanced monitoring at "
            "PER_TOPIC_PER_BROKER or "
            "PER_TOPIC_PER_PARTITION."
        ),
        compliance=[
            "AWS Security Hub MSK.2",
            "NIST SP 800-53 Rev. 5 CA-7",
            "NIST SP 800-53 Rev. 5 SI-2",
        ],
    )


def check_msk_connector_encryption(
    resource_id: str,
    encryption_type: str | None,
) -> MSKResult | None:
    if encryption_type == "TLS":
        return None

    return _result(
        resource_id,
        "msk_connector",
        {"encryption_type": encryption_type},
    )


def build_msk_connector_encryption_finding(
    result: MSKResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-MSK-003",
        title="MSK Connect connector does not use TLS encryption",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The MSK Connect connector {result.resource_id} "
            "does not use TLS for encryption in transit."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Configure the MSK Connect connector to use "
            "TLS encryption in transit."
        ),
        compliance=[
            "AWS Security Hub MSK.3",
            "PCI DSS v4.0.1/4.2.1",
        ],
    )


def check_msk_public_access(
    resource_id: str,
    cluster_type: str | None,
    public_access_type: str | None,
) -> MSKResult | None:
    if cluster_type != "PROVISIONED":
        return None

    if public_access_type in {
        None,
        "DISABLED",
    }:
        return None

    return _result(
        resource_id,
        "msk_cluster",
        {
            "cluster_type": cluster_type,
            "public_access_type": public_access_type,
        },
    )


def build_msk_public_access_finding(
    result: MSKResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-MSK-004",
        title="MSK cluster has public access enabled",
        severity=Severity.CRITICAL,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The MSK cluster {result.resource_id} "
            "has public broker access enabled."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Disable public access to the MSK cluster "
            "and keep broker connectivity private."
        ),
        compliance=[
            "AWS Security Hub MSK.4",
        ],
    )


def check_msk_connector_logging(
    resource_id: str,
    logging_enabled: bool,
) -> MSKResult | None:
    if logging_enabled:
        return None

    return _result(
        resource_id,
        "msk_connector",
        {"logging_enabled": False},
    )


def build_msk_connector_logging_finding(
    result: MSKResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-MSK-005",
        title="MSK Connect connector logging is disabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The MSK Connect connector {result.resource_id} "
            "does not have worker log delivery enabled."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Enable worker log delivery for the MSK Connect "
            "connector to an appropriate CloudWatch Logs, "
            "S3, or Kinesis Data Firehose destination."
        ),
        compliance=[
            "AWS Security Hub MSK.5",
        ],
    )


def check_msk_unauthenticated_access(
    resource_id: str,
    unauthenticated_access: bool | None,
) -> MSKResult | None:
    if unauthenticated_access is not True:
        return None

    return _result(
        resource_id,
        "msk_cluster",
        {"unauthenticated_access": True},
    )


def build_msk_unauthenticated_access_finding(
    result: MSKResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-MSK-006",
        title="MSK cluster allows unauthenticated access",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The MSK cluster {result.resource_id} "
            "allows clients to connect without authentication."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Disable unauthenticated access and require "
            "an authentication mechanism such as IAM, "
            "SASL/SCRAM, or mutual TLS."
        ),
        compliance=[
            "AWS Security Hub MSK.6",
        ],
    )
