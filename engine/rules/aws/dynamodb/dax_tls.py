from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class DAXTLSResult:
    cluster_arn: str
    cluster_name: str
    endpoint_encryption_type: str | None
    tls_enabled: bool


def check_dax_tls(
    cluster_arn: str,
    cluster_name: str,
    cluster_endpoint_encryption_type: str | None,
) -> DAXTLSResult:
    normalized_type = (
        cluster_endpoint_encryption_type.upper()
        if isinstance(
            cluster_endpoint_encryption_type,
            str,
        )
        else None
    )

    return DAXTLSResult(
        cluster_arn=cluster_arn,
        cluster_name=cluster_name,
        endpoint_encryption_type=normalized_type,
        tls_enabled=normalized_type == "TLS",
    )


def build_dax_tls_finding(
    result: DAXTLSResult,
) -> Finding | None:
    if result.tls_enabled:
        return None

    return Finding(
        rule_id="CS-AWS-DYNAMODB-007",
        title="DAX Cluster Is Not Encrypted In Transit",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="dax_cluster",
        resource_id=result.cluster_arn,
        description=(
            "The DAX cluster endpoint encryption type is not "
            "configured as TLS."
        ),
        evidence={
            "cluster_name": result.cluster_name,
            "endpoint_encryption_type": (
                result.endpoint_encryption_type
            ),
            "tls_enabled": result.tls_enabled,
        },
        remediation=(
            "Create a DAX cluster with TLS endpoint encryption "
            "enabled. AWS does not allow changing this setting "
            "on an existing cluster."
        ),
        compliance=[
            "AWS Security Hub DynamoDB.7",
        ],
    )
