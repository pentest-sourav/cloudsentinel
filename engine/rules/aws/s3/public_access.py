from dataclasses import dataclass

from engine.findings.model import Finding, Severity


REQUIRED_PUBLIC_ACCESS_BLOCK_SETTINGS = [
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
]


@dataclass(frozen=True)
class S3PublicAccessResult:
    bucket_name: str
    is_public: bool
    reason: str
    configuration: dict[str, bool]

    @property
    def public_access_signal(self) -> bool:
        return self.is_public


def check_s3_public_access(
    bucket_name: str,
    public_access_block: dict,
) -> S3PublicAccessResult:
    configuration = {
        setting: public_access_block.get(setting, False)
        for setting in REQUIRED_PUBLIC_ACCESS_BLOCK_SETTINGS
    }

    disabled_settings = [
        setting
        for setting in REQUIRED_PUBLIC_ACCESS_BLOCK_SETTINGS
        if not configuration[setting]
    ]

    if disabled_settings:
        return S3PublicAccessResult(
            bucket_name=bucket_name,
            is_public=True,
            reason=(
                "S3 Public Access Block is not fully enabled. "
                f"Disabled settings: {', '.join(disabled_settings)}"
            ),
            configuration=configuration,
        )

    return S3PublicAccessResult(
        bucket_name=bucket_name,
        is_public=False,
        reason="All S3 Public Access Block settings are enabled.",
        configuration=configuration,
    )


def build_s3_public_access_finding(
    result: S3PublicAccessResult,
) -> Finding | None:
    if not result.public_access_signal:
        return None

    return Finding(
        rule_id="CS-AWS-S3-001",
        title="S3 Public Access Block Not Fully Enabled",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="s3_bucket",
        resource_id=result.bucket_name,
        description=(
            "The S3 bucket does not have all Public Access Block "
            "settings enabled. This is an exposure signal and does "
            "not by itself prove that the bucket is publicly accessible."
        ),
        evidence={
            "configuration": result.configuration,
            "reason": result.reason,
            "public_access_signal": result.public_access_signal,
        },
        remediation=(
            "Review and enable the required S3 Public Access Block "
            "settings unless public access is explicitly required."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
