from dataclasses import dataclass
from datetime import datetime

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class ExpiredServerCertificateResult:
    certificate_name: str | None
    certificate_arn: str | None
    certificate_id: str | None
    expiration: datetime


def check_expired_server_certificate(
    certificate_name: str | None,
    certificate_arn: str | None,
    certificate_id: str | None,
    expiration: datetime,
) -> ExpiredServerCertificateResult:
    return ExpiredServerCertificateResult(
        certificate_name=certificate_name,
        certificate_arn=certificate_arn,
        certificate_id=certificate_id,
        expiration=expiration,
    )


def build_expired_server_certificate_finding(
    result: ExpiredServerCertificateResult,
) -> Finding:
    resource_id = (
        result.certificate_arn
        or result.certificate_id
        or result.certificate_name
        or "unknown"
    )

    return Finding(
        rule_id="CS-AWS-IAM-043",
        title="Expired IAM Server Certificate",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="iam_server_certificate",
        resource_id=resource_id,
        description=(
            f"IAM-managed SSL/TLS server certificate "
            f"'{result.certificate_name or resource_id}' "
            f"expired on {result.expiration.isoformat()}."
        ),
        evidence={
            "certificate_name": result.certificate_name,
            "certificate_arn": result.certificate_arn,
            "certificate_id": result.certificate_id,
            "expiration": result.expiration.isoformat(),
        },
        remediation=(
            "Remove the expired IAM-managed server certificate "
            "if it is no longer required."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
