from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class ECRTagImmutabilityResult:
    repository_name: str
    image_tag_mutability: str | None
    exclusion_filters: list[dict]


def check_ecr_tag_immutability(
    repository_name: str,
    image_tag_mutability: str | None,
    image_tag_mutability_exclusion_filters: list[dict] | None,
) -> ECRTagImmutabilityResult | None:
    if image_tag_mutability == "IMMUTABLE":
        return None

    return ECRTagImmutabilityResult(
        repository_name=repository_name,
        image_tag_mutability=image_tag_mutability,
        exclusion_filters=(
            image_tag_mutability_exclusion_filters or []
        ),
    )


def build_ecr_tag_immutability_finding(
    result: ECRTagImmutabilityResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ECR-002",
        title="ECR Repository Does Not Enforce Immutable Image Tags",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="ecr_repository",
        resource_id=result.repository_name,
        description=(
            "The ECR repository does not use fully immutable image tags. "
            "Mutable or exclusion-based tag mutability can allow an "
            "existing image tag to be changed."
        ),
        evidence={
            "repository_name": result.repository_name,
            "image_tag_mutability": result.image_tag_mutability,
            "image_tag_mutability_exclusion_filters": (
                result.exclusion_filters
            ),
        },
        remediation=(
            "Configure the ECR repository with image tag mutability "
            "set to IMMUTABLE."
        ),
        compliance=[
            "AWS Security Hub ECR.2",
        ],
    )
