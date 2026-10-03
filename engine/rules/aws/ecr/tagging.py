from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class ECRTaggingResult:
    repository_name: str
    repository_arn: str
    tags: list[dict[str, str]]
    required_tag_keys: list[str]
    missing_tag_keys: list[str]


def _normalize_required_tag_keys(
    required_tag_keys: list[str] | None,
) -> list[str]:
    if not isinstance(required_tag_keys, list):
        return []

    result = []

    for key in required_tag_keys:
        if not isinstance(key, str):
            continue
        key = key.strip()
        if not key or key.lower().startswith("aws:"):
            continue
        if key not in result:
            result.append(key)

    return result


def check_ecr_tagging(
    repository_name: str,
    repository_arn: str,
    tags: list[dict[str, str]],
    required_tag_keys: list[str] | None = None,
) -> ECRTaggingResult | None:
    required = _normalize_required_tag_keys(required_tag_keys)

    present = {
        tag.get("Key")
        for tag in tags
        if isinstance(tag, dict)
        and isinstance(tag.get("Key"), str)
        and not tag["Key"].lower().startswith("aws:")
    }

    missing = [key for key in required if key not in present]

    if required and not missing:
        return None

    if not required and present:
        return None

    return ECRTaggingResult(
        repository_name=repository_name,
        repository_arn=repository_arn,
        tags=tags,
        required_tag_keys=required,
        missing_tag_keys=missing,
    )


def build_ecr_tagging_finding(
    result: ECRTaggingResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ECR-005",
        title="ECR Repository Is Not Tagged",
        severity=Severity.LOW,
        provider="aws",
        resource_type="ecr_repository",
        resource_id=result.repository_arn,
        description=(
            "The ECR repository does not satisfy the configured "
            "tagging requirements."
        ),
        evidence={
            "repository_name": result.repository_name,
            "repository_arn": result.repository_arn,
            "tags": result.tags,
            "required_tag_keys": result.required_tag_keys,
            "missing_tag_keys": result.missing_tag_keys,
        },
        remediation=(
            "Add the missing required tag keys using "
            "case-sensitive matching."
            if result.required_tag_keys
            else
            "Add at least one appropriate non-system tag."
        ),
        compliance=["AWS Security Hub ECR.4"],
    )
