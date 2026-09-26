from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class CloudFrontResult:
    resource_id: str
    resource_type: str
    details: dict


def check_cloudfront_default_root_object(
    resource_id: str,
    resource_type: str,
    s3_origins: list[dict],
    default_root_object: str | None,
) -> CloudFrontResult | None:
    if not resource_id:
        return None

    if not s3_origins:
        return None

    if (
        isinstance(default_root_object, str)
        and default_root_object.strip()
    ):
        return None

    return CloudFrontResult(
        resource_id=resource_id,
        resource_type=resource_type,
        details={
            "s3_origin_count": len(s3_origins),
            "default_root_object": (
                default_root_object
            ),
        },
    )


def build_cloudfront_default_root_object_finding(
    result: CloudFrontResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-CLOUDFRONT-001",
        title=(
            "CloudFront S3 distribution has no "
            "default root object"
        ),
        severity=Severity.HIGH,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The CloudFront distribution "
            f"{result.resource_id} uses an S3 origin "
            "but does not configure a default root "
            "object."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Configure a default root object such as "
            "index.html for the CloudFront distribution."
        ),
        compliance=[
            "AWS Security Hub CloudFront.1",
            "NIST SP 800-53 Rev. 5 SC-7(11)",
            "PCI DSS v4.0.1/2.2.6",
        ],
    )


def check_cloudfront_viewer_https(
    resource_id: str,
    resource_type: str,
    viewer_protocol_policies: list[str],
) -> CloudFrontResult | None:
    if not resource_id:
        return None

    insecure_policies = [
        policy
        for policy in viewer_protocol_policies
        if policy == "allow-all"
    ]

    if not insecure_policies:
        return None

    return CloudFrontResult(
        resource_id=resource_id,
        resource_type=resource_type,
        details={
            "viewer_protocol_policies": (
                viewer_protocol_policies
            ),
            "insecure_policies": insecure_policies,
        },
    )


def build_cloudfront_viewer_https_finding(
    result: CloudFrontResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-CLOUDFRONT-002",
        title=(
            "CloudFront distribution allows "
            "unencrypted viewer traffic"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The CloudFront distribution "
            f"{result.resource_id} has one or more "
            "cache behaviors configured with "
            "ViewerProtocolPolicy=allow-all."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Configure CloudFront cache behaviors to "
            "use redirect-to-https or https-only."
        ),
        compliance=[
            "AWS Security Hub CloudFront.3",
            "NIST SP 800-53 Rev. 5 SC-8",
            "PCI DSS v4.0.1/4.2.1",
        ],
    )


def check_cloudfront_logging(
    resource_id: str,
    resource_type: str,
    logging_enabled: bool,
) -> CloudFrontResult | None:
    if not resource_id:
        return None

    if logging_enabled:
        return None

    return CloudFrontResult(
        resource_id=resource_id,
        resource_type=resource_type,
        details={
            "logging_enabled": logging_enabled,
        },
    )


def build_cloudfront_logging_finding(
    result: CloudFrontResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-CLOUDFRONT-003",
        title=(
            "CloudFront distribution does not have "
            "standard access logging enabled"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The CloudFront distribution "
            f"{result.resource_id} does not have "
            "standard access logging enabled."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Enable CloudFront standard access logging "
            "and configure an appropriate destination."
        ),
        compliance=[
            "AWS Security Hub CloudFront.5",
            "NIST SP 800-53 Rev. 5 AU-12",
            "PCI DSS v4.0.1/10.4.2",
        ],
    )


def check_cloudfront_waf(
    resource_id: str,
    resource_type: str,
    waf_enabled: bool,
    waf_web_acl_id: str | None,
) -> CloudFrontResult | None:
    if not resource_id:
        return None

    if waf_enabled and waf_web_acl_id:
        return None

    return CloudFrontResult(
        resource_id=resource_id,
        resource_type=resource_type,
        details={
            "waf_enabled": waf_enabled,
            "waf_web_acl_id": waf_web_acl_id,
        },
    )


def build_cloudfront_waf_finding(
    result: CloudFrontResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-CLOUDFRONT-004",
        title=(
            "CloudFront distribution is not associated "
            "with AWS WAF"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The CloudFront distribution "
            f"{result.resource_id} is not associated "
            "with an AWS WAF web ACL."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Associate the CloudFront distribution with "
            "an appropriate AWS WAF web ACL."
        ),
        compliance=[
            "AWS Security Hub CloudFront.6",
            "NIST SP 800-53 Rev. 5 AC-4(21)",
            "PCI DSS v4.0.1/6.4.2",
        ],
    )


def check_cloudfront_s3_oac(
    resource_id: str,
    resource_type: str,
    s3_origins: list[dict],
) -> CloudFrontResult | None:
    if not resource_id:
        return None

    if not s3_origins:
        return None

    origins_without_oac = [
        {
            "origin_id": origin.get("origin_id"),
            "domain_name": origin.get("domain_name"),
            "origin_access_control_id": (
                origin.get("origin_access_control_id")
            ),
            "origin_access_identity": (
                origin.get("origin_access_identity")
            ),
        }
        for origin in s3_origins
        if not origin.get(
            "origin_access_control_id"
        )
    ]

    if not origins_without_oac:
        return None

    return CloudFrontResult(
        resource_id=resource_id,
        resource_type=resource_type,
        details={
            "s3_origin_count": len(s3_origins),
            "origins_without_oac": origins_without_oac,
        },
    )


def build_cloudfront_s3_oac_finding(
    result: CloudFrontResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-CLOUDFRONT-005",
        title=(
            "CloudFront S3 origin does not use "
            "Origin Access Control"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The CloudFront distribution "
            f"{result.resource_id} has an S3 origin "
            "without Origin Access Control."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Configure Origin Access Control for each "
            "S3 origin and update the S3 bucket policy "
            "to allow access through CloudFront."
        ),
        compliance=[
            "AWS Security Hub CloudFront.13",
        ],
    )
