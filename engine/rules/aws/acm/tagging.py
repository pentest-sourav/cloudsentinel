from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity

from engine.rules.aws.acm.common import (
    has_non_system_tags,
)


@dataclass(frozen=True)
class ACMTaggingResult:
    resource_id: str
    resource_arn: str
    tags: list[dict[str, Any]]


def check_acm_tagging(
    resource_id: str,
    resource_arn: str,
    tags: list[dict[str, Any]],
) -> ACMTaggingResult | None:
    if has_non_system_tags(tags):
        return None

    return ACMTaggingResult(
        resource_id=resource_id,
        resource_arn=resource_arn,
        tags=tags,
    )


def build_acm_tagging_finding(
    result: ACMTaggingResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ACM-003",
        title="ACM Certificate Is Not Tagged",
        severity=Severity.LOW,
        provider="aws",
        resource_type="acm_certificate",
        resource_id=result.resource_id,
        description=(
            "The ACM certificate does not have "
            "a non-system tag."
        ),
        evidence={
            "certificate_arn": result.resource_arn,
            "tags": result.tags,
        },
        remediation=(
            "Add at least one meaningful non-system "
            "tag to the ACM certificate."
        ),
        compliance=[
            "AWS Security Hub ACM.3",
        ],
    )
