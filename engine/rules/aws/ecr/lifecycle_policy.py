from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class ECRLifecyclePolicyResult:
    repository_name: str


def check_ecr_lifecycle_policy(
    repository_name: str,
    lifecycle_policy: dict | None,
) -> ECRLifecyclePolicyResult | None:
    if lifecycle_policy:
        policy_text = lifecycle_policy.get(
            "lifecycle_policy_text"
        )

        if policy_text:
            return None

    return ECRLifecyclePolicyResult(
        repository_name=repository_name,
    )


def build_ecr_lifecycle_policy_finding(
    result: ECRLifecyclePolicyResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ECR-003",
        title="ECR Repository Does Not Have a Lifecycle Policy",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="ecr_repository",
        resource_id=result.repository_name,
        description=(
            "The ECR repository does not have a lifecycle policy "
            "configured to manage image retention."
        ),
        evidence={
            "repository_name": result.repository_name,
            "lifecycle_policy_configured": False,
        },
        remediation=(
            "Configure at least one ECR lifecycle policy rule to "
            "automatically expire unused or outdated images."
        ),
        compliance=[
            "AWS Security Hub ECR.3",
        ],
    )
