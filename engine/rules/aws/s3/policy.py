from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class S3BucketPolicyResult:
    bucket_name: str
    policy_is_public: bool
    policy_status: dict


def check_s3_bucket_policy(
    bucket_name: str,
    policy_status: dict,
) -> S3BucketPolicyResult:
    policy_is_public = policy_status.get(
        "IsPublic",
        False,
    )

    return S3BucketPolicyResult(
        bucket_name=bucket_name,
        policy_is_public=policy_is_public,
        policy_status=policy_status,
    )


def build_s3_bucket_policy_finding(
    result: S3BucketPolicyResult,
) -> Finding | None:
    if not result.policy_is_public:
        return None

    return Finding(
        rule_id="CS-AWS-S3-003",
        title="S3 Bucket Policy Allows Public Access",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="s3_bucket",
        resource_id=result.bucket_name,
        description=(
            "The S3 bucket policy is classified by AWS as public. "
            "This indicates that the bucket policy contains a public "
            "access path and should be reviewed."
        ),
        evidence={
            "policy_is_public": result.policy_is_public,
            "policy_status": result.policy_status,
        },
        remediation=(
            "Review the S3 bucket policy and remove unintended public "
            "access. Restrict access to explicitly required AWS "
            "principals, accounts, or services."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
