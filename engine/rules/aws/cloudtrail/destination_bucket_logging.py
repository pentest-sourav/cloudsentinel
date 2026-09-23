from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class CloudTrailDestinationBucketLoggingResult:
    bucket_name: str
    logging_configuration: dict

    @property
    def access_logging_enabled(self) -> bool:
        return bool(self.logging_configuration)


def check_cloudtrail_destination_bucket_logging(
    bucket_name: str,
    logging_configuration: dict,
) -> CloudTrailDestinationBucketLoggingResult:
    if not isinstance(logging_configuration, dict):
        logging_configuration = {}

    return CloudTrailDestinationBucketLoggingResult(
        bucket_name=bucket_name,
        logging_configuration=logging_configuration,
    )


def build_cloudtrail_destination_bucket_logging_finding(
    result: CloudTrailDestinationBucketLoggingResult,
) -> Finding | None:
    if result.access_logging_enabled:
        return None

    return Finding(
        rule_id="CS-AWS-CT-018",
        title=(
            "CloudTrail destination S3 bucket does not have "
            "S3 server access logging enabled"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="s3_bucket",
        resource_id=result.bucket_name,
        description=(
            "The S3 bucket used as a CloudTrail trail destination "
            "does not have S3 server access logging configured."
        ),
        evidence={
            "bucket_name": result.bucket_name,
            "logging_configuration": result.logging_configuration,
            "access_logging_enabled": (
                result.access_logging_enabled
            ),
        },
        remediation=(
            "Configure S3 server access logging for the CloudTrail "
            "destination bucket and send the access logs to an "
            "appropriate dedicated logging destination."
        ),
        compliance=[
            "NIST SP 800-53 Rev. 5",
        ],
    )
