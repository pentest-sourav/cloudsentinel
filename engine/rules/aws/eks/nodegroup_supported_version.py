from dataclasses import dataclass

from engine.findings.model import Finding, Severity

from engine.rules.aws.eks.common import (
    is_supported_kubernetes_version,
)


@dataclass(frozen=True)
class EKSNodegroupSupportedVersionResult:
    resource_id: str
    resource_arn: str
    cluster_name: str
    version: str | None


def check_eks_nodegroup_supported_version(
    resource_id: str,
    resource_arn: str,
    cluster_name: str,
    version: str | None,
) -> EKSNodegroupSupportedVersionResult | None:
    if is_supported_kubernetes_version(version):
        return None

    return EKSNodegroupSupportedVersionResult(
        resource_id=resource_id,
        resource_arn=resource_arn,
        cluster_name=cluster_name,
        version=version,
    )


def build_eks_nodegroup_supported_version_finding(
    result: EKSNodegroupSupportedVersionResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-EKS-009",
        title="EKS Node Group Uses an Unsupported Kubernetes Version",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="eks_nodegroup",
        resource_id=result.resource_id,
        description=(
            "The EKS managed node group is running a "
            "Kubernetes version below the current Security "
            "Hub supported-version threshold of 1.34."
        ),
        evidence={
            "nodegroup_arn": result.resource_arn,
            "cluster_name": result.cluster_name,
            "kubernetes_version": result.version,
            "minimum_supported_version": "1.34",
        },
        remediation=(
            "Update the EKS managed node group to a "
            "Kubernetes version supported by Amazon EKS."
        ),
        compliance=[
            "AWS Security Hub EKS.9",
        ],
    )
