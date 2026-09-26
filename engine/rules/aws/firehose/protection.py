from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class FirehoseRuleResult:
    delivery_stream_name: str
    evidence: dict[str, object]


def _result(
    delivery_stream_name: str,
    evidence: dict[str, object],
) -> FirehoseRuleResult | None:
    if not delivery_stream_name:
        return None

    return FirehoseRuleResult(
        delivery_stream_name=delivery_stream_name,
        evidence=evidence,
    )


def check_firehose_encryption(
    delivery_stream_name: str,
    encryption_status: str | None,
) -> FirehoseRuleResult | None:
    if not delivery_stream_name or encryption_status is None:
        return None

    if encryption_status == "ENABLED":
        return None

    return _result(
        delivery_stream_name,
        {
            "delivery_stream_name": delivery_stream_name,
            "encryption_status": encryption_status,
        },
    )


def build_firehose_encryption_finding(
    result: FirehoseRuleResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-FIREHOSE-001",
        title="Firehose Delivery Stream Is Not Encrypted at Rest",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="firehose_delivery_stream",
        resource_id=result.delivery_stream_name,
        description=(
            f"The Firehose delivery stream "
            f"{result.delivery_stream_name} "
            "does not have active server-side encryption enabled."
        ),
        evidence=result.evidence,
        remediation=(
            "Enable server-side encryption for the Firehose "
            "delivery stream using an AWS-owned or "
            "customer-managed KMS key."
        ),
        compliance=[
            "AWS Foundational Security Best Practices",
            "NIST SP 800-53 Rev. 5",
        ],
    )
