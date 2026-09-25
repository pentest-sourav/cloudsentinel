from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class EKSEndpointPublicAccessResult:
    resource_id: str
    resource_arn: str
    endpoint_public_access: bool | None


def check_eks_endpoint_public_access(
    resource_id: str,
    resource_arn: str,
    endpoint_public_access: bool | None,
) -> EKSEndpointPublicAccessResult | None:
    if endpoint_public_access is False:
        return None

    return EKSEndpointPublicAccessResult(
        resource_id=resource_id,
        resource_arn=resource_arn,
        endpoint_public_access=endpoint_public_access,
    )


def build_eks_endpoint_public_access_finding(
    result: EKSEndpointPublicAccessResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-EKS-001",
        title="EKS Cluster Endpoint Is Publicly Accessible",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="eks_cluster",
        resource_id=result.resource_id,
        description=(
            "The Amazon EKS cluster Kubernetes API endpoint "
            "allows public access."
        ),
        evidence={
            "cluster_arn": result.resource_arn,
            "endpoint_public_access": (
                result.endpoint_public_access
            ),
        },
        remediation=(
            "Disable public access to the EKS cluster endpoint "
            "and use private endpoint access where appropriate."
        ),
        compliance=[
            "AWS Security Hub EKS.1",
        ],
    )
