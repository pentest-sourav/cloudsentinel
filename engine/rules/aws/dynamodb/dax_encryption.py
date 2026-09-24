from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class DAXEncryptionResult:
    cluster_arn: str
    cluster_name: str
    encryption_at_rest_enabled: bool
    sse_description: dict[str, Any]


def check_dax_encryption(
    cluster_arn: str,
    cluster_name: str,
    sse_description: dict[str, Any],
) -> DAXEncryptionResult:
    if not isinstance(sse_description, dict):
        sse_description = {}

    enabled = (
        str(
            sse_description.get("Status")
        ).upper()
        == "ENABLED"
    )

    return DAXEncryptionResult(
        cluster_arn=cluster_arn,
        cluster_name=cluster_name,
        encryption_at_rest_enabled=enabled,
        sse_description=sse_description,
    )


def build_dax_encryption_finding(
    result: DAXEncryptionResult,
) -> Finding | None:
    if result.encryption_at_rest_enabled:
        return None

    return Finding(
        rule_id="CS-AWS-DYNAMODB-003",
        title="DAX Cluster Is Not Encrypted At Rest",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="dax_cluster",
        resource_id=result.cluster_arn,
        description=(
            "The DynamoDB Accelerator (DAX) cluster is not "
            "configured with encryption at rest."
        ),
        evidence={
            "cluster_name": result.cluster_name,
            "encryption_at_rest_enabled": (
                result.encryption_at_rest_enabled
            ),
            "sse_description": result.sse_description,
        },
        remediation=(
            "Create a DAX cluster with encryption at rest enabled. "
            "AWS does not allow changing this setting on an existing "
            "cluster."
        ),
        compliance=[
            "AWS Security Hub DynamoDB.3",
        ],
    )
