from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class S3LoggingResult:
    bucket_name: str
    logging_enabled: bool
    configuration: dict


def check_s3_logging(
    bucket_name: str,
    logging_configuration: dict,
) -> S3LoggingResult:
    logging_enabled = bool(logging_configuration)

    return S3LoggingResult(
        bucket_name=bucket_name,
        logging_enabled=logging_enabled,
        configuration=logging_configuration,
    )


def build_s3_logging_finding(
    result: S3LoggingResult,
) -> Finding | None:
    if result.logging_enabled:
        return None

    return Finding(
        rule_id="CS-AWS-S3-006",
        title="S3 Server Access Logging Not Enabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="s3_bucket",
        resource_id=result.bucket_name,
        description=(
            "Server access logging is not enabled for the S3 bucket. "
            "Without access logging, requests made to the bucket may "
            "be harder to investigate and audit."
        ),
        evidence={
            "logging_enabled": result.logging_enabled,
            "configuration": result.configuration,
        },
        remediation=(
            "Enable S3 server access logging and configure an appropriate "
            "destination bucket for storing access logs."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
