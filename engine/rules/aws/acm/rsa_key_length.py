from dataclasses import dataclass

from engine.findings.model import Finding, Severity

from engine.rules.aws.acm.common import (
    MIN_RSA_KEY_LENGTH,
)


@dataclass(frozen=True)
class ACMRSAKeyLengthResult:
    resource_id: str
    resource_arn: str
    key_algorithm: str
    key_length: int


def _extract_rsa_key_length(
    key_algorithm: str,
) -> int | None:
    if not isinstance(key_algorithm, str):
        return None

    if not key_algorithm.startswith("RSA_"):
        return None

    try:
        return int(
            key_algorithm.removeprefix("RSA_")
        )
    except ValueError:
        return None


def check_acm_rsa_key_length(
    resource_id: str,
    resource_arn: str,
    key_algorithm: str | None,
) -> ACMRSAKeyLengthResult | None:
    key_length = _extract_rsa_key_length(
        key_algorithm
    )

    if key_length is None:
        return None

    if key_length >= MIN_RSA_KEY_LENGTH:
        return None

    return ACMRSAKeyLengthResult(
        resource_id=resource_id,
        resource_arn=resource_arn,
        key_algorithm=key_algorithm,
        key_length=key_length,
    )


def build_acm_rsa_key_length_finding(
    result: ACMRSAKeyLengthResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ACM-002",
        title=(
            "ACM RSA Certificate Uses "
            "an Insufficient Key Length"
        ),
        severity=Severity.HIGH,
        provider="aws",
        resource_type="acm_certificate",
        resource_id=result.resource_id,
        description=(
            "The ACM-managed RSA certificate uses "
            "an RSA key length below 2048 bits."
        ),
        evidence={
            "certificate_arn": result.resource_arn,
            "key_algorithm": result.key_algorithm,
            "key_length": result.key_length,
            "minimum_key_length": (
                MIN_RSA_KEY_LENGTH
            ),
        },
        remediation=(
            "Replace the certificate with an RSA "
            "certificate using a key length of at "
            "least 2048 bits."
        ),
        compliance=[
            "AWS Security Hub ACM.2",
        ],
    )
