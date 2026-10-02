from dataclasses import dataclass

from engine.findings.model import Finding, Severity

from engine.rules.aws.eks.common import (
    has_required_tag_keys,
    normalize_required_tag_keys,
)


@dataclass(frozen=True)
class EKSIdentityProviderTaggingResult:
    resource_id: str
    resource_arn: str
    cluster_name: str
    provider_name: str
    tags: dict
    required_tag_keys: tuple[str, ...]


def check_eks_identity_provider_tagging(
    resource_id: str,
    resource_arn: str,
    cluster_name: str,
    provider_name: str,
    tags: dict,
    required_tag_keys: list[str] | tuple[str, ...] | None = None,
) -> EKSIdentityProviderTaggingResult | None:
    normalized_required_tag_keys = normalize_required_tag_keys(
        required_tag_keys,
    )

    if has_required_tag_keys(
        tags,
        normalized_required_tag_keys,
    ):
        return None

    return EKSIdentityProviderTaggingResult(
        resource_id=resource_id,
        resource_arn=resource_arn,
        cluster_name=cluster_name,
        provider_name=provider_name,
        tags=tags,
        required_tag_keys=normalized_required_tag_keys,
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
            "satisfy the configured required tagging policy."
        ),
        evidence={
            "identity_provider_arn": result.resource_arn,
            "cluster_name": result.cluster_name,
            "provider_name": result.provider_name,
            "tags": result.tags,
            "required_tag_keys": list(
                result.required_tag_keys
            ),
        },
        remediation=(
            "Add the required non-system tag keys to "
            "the EKS identity provider configuration."
        ),
        compliance=[
            "AWS Security Hub EKS.7",
        ],
    )
