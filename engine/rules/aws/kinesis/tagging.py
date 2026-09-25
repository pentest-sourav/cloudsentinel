from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class KinesisTaggingResult:
    resource_id: str
    expected_configuration: str
    actual_configuration: str


def check_kinesis_tagging(
    stream_arn: str,
    tags: list[dict],
) -> KinesisTaggingResult | None:
    valid_tags = [
        tag
        for tag in tags
        if isinstance(tag, dict)
        and isinstance(tag.get("Key"), str)
        and tag.get("Key")
    ]

    if valid_tags:
        return None

    return KinesisTaggingResult(
        resource_id=stream_arn,
        expected_configuration="At least one tag",
        actual_configuration="NO_TAGS",
    )


def build_kinesis_tagging_finding(
    result: KinesisTaggingResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-KINESIS-002",
        title="Kinesis streams should be tagged",
        severity=Severity.LOW,
        provider="aws",
        resource_type="kinesis_stream",
        resource_id=result.resource_id,
        description=(
            "The Kinesis stream does not have any "
            "user-defined tags."
        ),
        evidence={
            "stream_arn": result.resource_id,
            "expected_configuration": (
                result.expected_configuration
            ),
            "actual_configuration": (
                result.actual_configuration
            ),
        },
        remediation=(
            "Add at least one user-defined tag to the "
            "Kinesis stream. If your environment uses "
            "required tag keys, ensure the configured "
            "keys are present."
        ),
        compliance=[
            "AWS Security Hub Kinesis.2",
        ],
    )
