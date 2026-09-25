from dataclasses import dataclass

from engine.findings.model import Finding, Severity

from engine.rules.aws.eks.common import (
    is_supported_kubernetes_version,
)


@dataclass(frozen=True)
class EKSSupportedVersionResult:
    resource_id: str
    resource_arn: str
    version: str | None


def check_eks_supported_version(
    resource_id: str,
    resource_arn: str,
    version: str | None,
) -> EKSSupportedVersionResult | None:
    if is_supported_kubernetes_version(version):
        return None

    return EKSSupportedVersionResult(
        resource_id=resource_id,
        resource_arn=resource_arn,
        version=version,
    )


def build_eks_supported_version_finding(
    result: EKSSupportedVersionResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-EKS-002",
        title="EKS Cluster Uses an Unsupported Kubernetes Version",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="eks_cluster",
        resource_id=result.resource_id,
        description=(
            "The EKS cluster is running a Kubernetes version "
            "below the current Security Hub supported-version "
            "threshold of 1.34."
        ),
        evidence={
            "cluster_arn": result.resource_arn,
            "kubernetes_version": result.version,
            "minimum_supported_version": "1.34",
        },
        remediation=(
            "Update the EKS cluster to a Kubernetes version "
            "supported by Amazon EKS."
        ),
        compliance=[
            "AWS Security Hub EKS.2",
        ],
    )
