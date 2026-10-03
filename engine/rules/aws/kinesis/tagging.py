from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class KinesisTaggingResult:
    resource_id: str
    tags: list[dict]
    required_tag_keys: list[str]
    missing_tag_keys: list[str]

    @property
    def actual_configuration(self) -> str:
        """Backward-compatible configuration description for existing tests."""
        if not self.tags:
            return "NO_TAGS"

        valid_non_system_tags = [
            tag
            for tag in self.tags
            if isinstance(tag, dict)
            and isinstance(tag.get("Key"), str)
            and tag.get("Key").strip()
            and not tag["Key"].lower().startswith("aws:")
        ]

        if not valid_non_system_tags:
            return "NO_TAGS"

        return "TAGS_PRESENT"


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


def _normalize_valid_tags(
    tags: list[dict] | None,
) -> list[dict]:
    if not isinstance(tags, list):
        return []

    return [
        tag
        for tag in tags
        if (
            isinstance(tag, dict)
            and isinstance(tag.get("Key"), str)
            and bool(tag.get("Key").strip())
            and not tag["Key"].lower().startswith("aws:")
        )
    ]


def check_kinesis_tagging(
    stream_arn: str,
    tags: list[dict],
    required_tag_keys: list[str] | None = None,
) -> KinesisTaggingResult | None:
    required = _normalize_required_tag_keys(required_tag_keys)
    valid_tags = _normalize_valid_tags(tags)

    present = {
        tag["Key"]
        for tag in valid_tags
    }

    missing = [
        key
        for key in required
        if key not in present
    ]

    if required:
        if not missing:
            return None
    elif present:
        return None

    return KinesisTaggingResult(
        resource_id=stream_arn,
        tags=tags if isinstance(tags, list) else [],
        required_tag_keys=required,
        missing_tag_keys=missing,
    )


def build_kinesis_tagging_finding(
    result: KinesisTaggingResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-KINESIS-002",
        title="Kinesis Stream Is Not Tagged",
        severity=Severity.LOW,
        provider="aws",
        resource_type="kinesis_stream",
        resource_id=result.resource_id,
        description=(
            "The Kinesis stream does not satisfy the configured "
            "tagging requirements."
        ),
        evidence={
            "stream_arn": result.resource_id,
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
        compliance=["AWS Security Hub Kinesis.2"],
    )
