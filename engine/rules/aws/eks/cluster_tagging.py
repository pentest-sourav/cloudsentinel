from dataclasses import dataclass

from engine.findings.model import Finding, Severity

from engine.rules.aws.eks.common import has_required_tag_keys


@dataclass(frozen=True)
class EKSClusterTaggingResult:
    resource_id: str
    resource_arn: str
    tags: dict
    required_tag_keys: tuple[str, ...]


def check_eks_cluster_tagging(
    resource_id: str,
    resource_arn: str,
    tags: dict,
    required_tag_keys: list[str] | tuple[str, ...] | None = None,
) -> EKSClusterTaggingResult | None:
    from engine.rules.aws.eks.common import (
        normalize_required_tag_keys,
    )

    normalized_required_tag_keys = normalize_required_tag_keys(
        required_tag_keys,
    )

    if has_required_tag_keys(
        tags,
        normalized_required_tag_keys,
    ):
        return None

    return EKSClusterTaggingResult(
        resource_id=resource_id,
        resource_arn=resource_arn,
        tags=tags,
        required_tag_keys=normalized_required_tag_keys,
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
            "The EKS cluster does not satisfy the configured "
            "required tagging policy."
        ),
        evidence={
            "cluster_arn": result.resource_arn,
            "tags": result.tags,
            "required_tag_keys": list(
                result.required_tag_keys
            ),
        },
        remediation=(
            "Add the required non-system tag keys to "
            "the EKS cluster."
        ),
        compliance=[
            "AWS Security Hub EKS.6",
        ],
    )
