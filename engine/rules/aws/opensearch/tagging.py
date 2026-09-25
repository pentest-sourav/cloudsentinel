from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class OpenSearchTaggingResult:
    domain_arn: str
    tagged: bool
    tags: list[dict[str, Any]]


def check_opensearch_tagging(
    domain_arn: str,
    tags: list[dict[str, Any]],
) -> OpenSearchTaggingResult:
    valid_tags = [
        tag
        for tag in tags
        if isinstance(tag, dict)
        and isinstance(tag.get("Key"), str)
        and bool(tag.get("Key"))
        and not tag["Key"].startswith("aws:")
    ]

    return OpenSearchTaggingResult(
        domain_arn=domain_arn,
        tagged=bool(valid_tags),
        tags=valid_tags,
    )


def build_opensearch_tagging_finding(
    result: OpenSearchTaggingResult,
) -> Finding | None:
    if result.tagged:
        return None

    return Finding(
        rule_id="CS-AWS-OPENSEARCH-009",
        title="OpenSearch Domain Has No Non-System Tags",
        severity=Severity.LOW,
        provider="aws",
        resource_type="opensearch_domain",
        resource_id=result.domain_arn,
        description=(
            "The OpenSearch domain does not have any non-system "
            "tags configured."
        ),
        evidence={
            "tagged": result.tagged,
            "tags": result.tags,
        },
        remediation=(
            "Add appropriate ownership, environment, application, "
            "or governance tags to the OpenSearch domain."
        ),
        compliance=[
            "AWS Security Hub Opensearch.9",
        ],
    )
