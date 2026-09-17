from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class S3OwnershipResult:
    bucket_name: str
    ownership_mode: str | None
    acl_disabled: bool
    configuration: dict


def check_s3_ownership(
    bucket_name: str,
    ownership_configuration: dict,
) -> S3OwnershipResult:
    if "OwnershipControls" in ownership_configuration:
        ownership_controls = ownership_configuration.get(
            "OwnershipControls",
            {},
        )
        rules = ownership_controls.get(
            "Rules",
            [],
        )
    else:
        rules = ownership_configuration.get(
            "Rules",
            [],
        )

    ownership_mode = None

    if rules:
        ownership_mode = rules[0].get(
            "ObjectOwnership"
        )

    acl_disabled = ownership_mode == "BucketOwnerEnforced"

    return S3OwnershipResult(
        bucket_name=bucket_name,
        ownership_mode=ownership_mode,
        acl_disabled=acl_disabled,
        configuration=ownership_configuration,
    )

def build_s3_ownership_finding(
    result: S3OwnershipResult,
) -> Finding | None:
    if result.acl_disabled:
        return None

    return Finding(
        rule_id="CS-AWS-S3-008",
        title="S3 Bucket Ownership Does Not Enforce Bucket Owner",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="s3_bucket",
        resource_id=result.bucket_name,
        description=(
            "The S3 bucket does not use the BucketOwnerEnforced "
            "object ownership setting. ACL-based ownership or access "
            "behavior may therefore still be applicable."
        ),
        evidence={
            "ownership_mode": result.ownership_mode,
            "acl_disabled": result.acl_disabled,
            "configuration": result.configuration,
        },
        remediation=(
            "Use BucketOwnerEnforced object ownership where ACL-based "
            "access is not required. Review existing ACL dependencies "
            "before changing the ownership configuration."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
