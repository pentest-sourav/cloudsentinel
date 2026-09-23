from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class CloudTrailDestinationBucketPublicAccessResult:
    bucket_name: str
    public_access_block: dict[str, bool]

    @property
    def public_access_block_enabled(self) -> bool:
        required_settings = (
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        )

        return all(
            self.public_access_block.get(setting) is True
            for setting in required_settings
        )


def check_cloudtrail_destination_bucket_public_access(
    bucket_name: str,
    public_access_block: dict[str, bool],
) -> CloudTrailDestinationBucketPublicAccessResult:
    if not isinstance(public_access_block, dict):
        public_access_block = {}

    return CloudTrailDestinationBucketPublicAccessResult(
        bucket_name=bucket_name,
        public_access_block=public_access_block,
    )


def build_cloudtrail_destination_bucket_public_access_finding(
    result: CloudTrailDestinationBucketPublicAccessResult,
) -> Finding | None:
    if result.public_access_block_enabled:
        return None

    return Finding(
        rule_id="CS-AWS-CT-017",
        title=(
            "CloudTrail destination S3 bucket does not have "
            "complete bucket-level public access protection"
        ),
        severity=Severity.HIGH,
        provider="aws",
        resource_type="s3_bucket",
        resource_id=result.bucket_name,
        description=(
            "The S3 bucket used as a CloudTrail trail destination "
            "does not have all four bucket-level S3 Block Public "
            "Access settings enabled."
        ),
        evidence={
            "bucket_name": result.bucket_name,
            "public_access_block": result.public_access_block,
            "block_public_acls": result.public_access_block.get(
                "BlockPublicAcls"
            ),
            "ignore_public_acls": result.public_access_block.get(
                "IgnorePublicAcls"
            ),
            "block_public_policy": result.public_access_block.get(
                "BlockPublicPolicy"
            ),
            "restrict_public_buckets": result.public_access_block.get(
                "RestrictPublicBuckets"
            ),
        },
        remediation=(
            "Enable BlockPublicAcls, IgnorePublicAcls, "
            "BlockPublicPolicy, and RestrictPublicBuckets on the "
            "CloudTrail destination S3 bucket. Also verify account "
            "and organization-level S3 Block Public Access settings "
            "when assessing effective public access."
        ),
        compliance=[
            "NIST SP 800-53 Rev. 5",
        ],
    )
