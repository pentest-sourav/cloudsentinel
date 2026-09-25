from dataclasses import dataclass

from engine.findings.model import Finding, Severity

from engine.rules.aws.eks.common import has_non_system_tags


@dataclass(frozen=True)
class EKSClusterTaggingResult:
    resource_id: str
    resource_arn: str
    tags: dict


def check_eks_cluster_tagging(
    resource_id: str,
    resource_arn: str,
    tags: dict,
) -> EKSClusterTaggingResult | None:
    if has_non_system_tags(tags):
        return None

    return EKSClusterTaggingResult(
        resource_id=resource_id,
        resource_arn=resource_arn,
        tags=tags,
    )


def build_eks_cluster_tagging_finding(
    result: EKSClusterTaggingResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-EKS-006",
        title="EKS Cluster Is Not Tagged",
        severity=Severity.LOW,
        provider="aws",
        resource_type="eks_cluster",
        resource_id=result.resource_id,
        description=(
            "The EKS cluster does not have a non-system tag."
        ),
        evidence={
            "cluster_arn": result.resource_arn,
            "tags": result.tags,
        },
        remediation=(
            "Add at least one meaningful non-system tag to "
            "the EKS cluster."
        ),
        compliance=[
            "AWS Security Hub EKS.6",
        ],
    )
