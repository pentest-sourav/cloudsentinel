from dataclasses import dataclass

from engine.findings.model import Finding, Severity

from engine.rules.aws.eks.common import has_non_system_tags


@dataclass(frozen=True)
class EKSIdentityProviderTaggingResult:
    resource_id: str
    resource_arn: str
    cluster_name: str
    provider_name: str
    tags: dict


def check_eks_identity_provider_tagging(
    resource_id: str,
    resource_arn: str,
    cluster_name: str,
    provider_name: str,
    tags: dict,
) -> EKSIdentityProviderTaggingResult | None:
    if has_non_system_tags(tags):
        return None

    return EKSIdentityProviderTaggingResult(
        resource_id=resource_id,
        resource_arn=resource_arn,
        cluster_name=cluster_name,
        provider_name=provider_name,
        tags=tags,
    )


def build_eks_identity_provider_tagging_finding(
    result: EKSIdentityProviderTaggingResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-EKS-007",
        title="EKS Identity Provider Configuration Is Not Tagged",
        severity=Severity.LOW,
        provider="aws",
        resource_type="eks_identity_provider_config",
        resource_id=result.resource_id,
        description=(
            "The EKS identity provider configuration does not "
            "have a non-system tag."
        ),
        evidence={
            "identity_provider_arn": result.resource_arn,
            "cluster_name": result.cluster_name,
            "provider_name": result.provider_name,
            "tags": result.tags,
        },
        remediation=(
            "Add at least one meaningful non-system tag to "
            "the EKS identity provider configuration."
        ),
        compliance=[
            "AWS Security Hub EKS.7",
        ],
    )
