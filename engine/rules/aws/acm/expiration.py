from dataclasses import dataclass
from datetime import datetime

from engine.findings.model import Finding, Severity

from engine.rules.aws.acm.common import (
    DEFAULT_DAYS_TO_EXPIRATION,
    days_until,
    format_datetime,
)


@dataclass(frozen=True)
class ACMExpirationResult:
    resource_id: str
    resource_arn: str
    not_after: datetime
    days_to_expiration: float
    threshold_days: int


def check_acm_expiration(
    resource_id: str,
    resource_arn: str,
    not_after: datetime | None,
    days_to_expiration: int = (
        DEFAULT_DAYS_TO_EXPIRATION
    ),
) -> ACMExpirationResult | None:
    if not_after is None:
        return None

    remaining_days = days_until(not_after)

    if remaining_days > days_to_expiration:
        return None

    return ACMExpirationResult(
        resource_id=resource_id,
        resource_arn=resource_arn,
        not_after=not_after,
        days_to_expiration=remaining_days,
        threshold_days=days_to_expiration,
    )


def build_acm_expiration_finding(
    result: ACMExpirationResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ACM-001",
        title=(
            "ACM Certificate Is Within "
            "the Renewal Window"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="acm_certificate",
        resource_id=result.resource_id,
        description=(
            "The ACM certificate expires within "
            "the configured renewal window."
        ),
        evidence={
            "certificate_arn": result.resource_arn,
            "not_after": format_datetime(
                result.not_after
            ),
            "days_to_expiration": (
                result.days_to_expiration
            ),
            "threshold_days": (
                result.threshold_days
            ),
        },
        remediation=(
            "Renew the certificate before expiration. "
            "For ACM-issued certificates, verify that "
            "automatic renewal requirements are satisfied. "
            "Imported certificates must be renewed and "
            "re-imported manually."
        ),
        compliance=[
            "AWS Security Hub ACM.1",
        ],
    )
