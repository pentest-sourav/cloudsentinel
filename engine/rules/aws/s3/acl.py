from dataclasses import dataclass

from engine.findings.model import Finding, Severity


PUBLIC_GROUP_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


@dataclass(frozen=True)
class S3AclResult:
    bucket_name: str
    broad_access: bool
    public_grants: list[dict]


def check_s3_acl(
    bucket_name: str,
    acl: dict,
) -> S3AclResult:
    grants = acl.get("Grants", [])

    public_grants = []

    for grant in grants:
        grantee = grant.get("Grantee", {})

        uri = grantee.get("URI")

        if uri in PUBLIC_GROUP_URIS:
            public_grants.append(grant)

    return S3AclResult(
        bucket_name=bucket_name,
        broad_access=bool(public_grants),
        public_grants=public_grants,
    )


def build_s3_acl_finding(
    result: S3AclResult,
) -> Finding | None:
    if not result.broad_access:
        return None

    return Finding(
        rule_id="CS-AWS-S3-004",
        title="S3 Bucket ACL Grants Broad Access",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="s3_bucket",
        resource_id=result.bucket_name,
        description=(
            "The S3 bucket ACL contains a grant to a broad AWS S3 "
            "group such as AllUsers or AuthenticatedUsers. This is "
            "an exposure signal and should be reviewed."
        ),
        evidence={
            "broad_access": result.broad_access,
            "public_grants": result.public_grants,
        },
        remediation=(
            "Remove unintended grants to AllUsers or "
            "AuthenticatedUsers and restrict bucket access to "
            "explicitly required principals."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
