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


def check_cloudfront_custom_origin_https(
    resource_id: str,
    resource_type: str,
    origins: list[dict],
    cache_behaviors: list[dict],
) -> CloudFrontResult | None:
    if not resource_id:
        return None

    behaviors_by_origin: dict[str, list[str]] = {}

    for behavior in cache_behaviors:
        viewer_protocol_policy = behavior.get(
            "viewer_protocol_policy"
        )

        if not viewer_protocol_policy:
            continue

        target_origin_ids = behavior.get(
            "target_origin_ids"
        )

        if not target_origin_ids:
            target_origin_id = behavior.get(
                "target_origin_id"
            )
            target_origin_ids = (
                [target_origin_id]
                if target_origin_id
                else []
            )

        for target_origin_id in target_origin_ids:
            behaviors_by_origin.setdefault(
                target_origin_id,
                [],
            ).append(viewer_protocol_policy)

    insecure_origins = []

    for origin in origins:
        if origin.get("is_s3_origin"):
            continue

        origin_id = origin.get("origin_id")
        origin_protocol_policy = origin.get(
            "origin_protocol_policy"
        )

        if not origin_id or not origin_protocol_policy:
            continue

        viewer_policies = behaviors_by_origin.get(
            origin_id,
            [],
        )

        # AWS Security Hub CloudFront.9:
        # - http-only always fails.
        # - match-viewer fails when the relevant viewer
        #   protocol policy allows HTTP.
        if origin_protocol_policy == "http-only":
            insecure_origins.append(
                {
                    "origin_id": origin_id,
                    "domain_name": origin.get(
                        "domain_name"
                    ),
                    "origin_protocol_policy": (
                        origin_protocol_policy
                    ),
                    "viewer_protocol_policies": (
                        viewer_policies
                    ),
                }
            )
            continue

        if (
            origin_protocol_policy == "match-viewer"
            and "allow-all" in viewer_policies
        ):
            insecure_origins.append(
                {
                    "origin_id": origin_id,
                    "domain_name": origin.get(
                        "domain_name"
                    ),
                    "origin_protocol_policy": (
                        origin_protocol_policy
                    ),
                    "viewer_protocol_policies": (
                        viewer_policies
                    ),
                }
            )

    if not insecure_origins:
        return None

    return CloudFrontResult(
        resource_id=resource_id,
        resource_type=resource_type,
        details={
            "insecure_origins": insecure_origins,
        },
    )


def build_cloudfront_custom_origin_https_finding(
    result: CloudFrontResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-CLOUDFRONT-006",
        title=(
            "CloudFront distribution does not encrypt "
            "traffic to custom origins"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The CloudFront distribution "
            f"{result.resource_id} has one or more "
            "custom origins that can receive "
            "unencrypted HTTP traffic."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Configure custom origins to use "
            "OriginProtocolPolicy=https-only. If "
            "using match-viewer, ensure every cache "
            "behavior targeting that origin uses "
            "redirect-to-https or https-only."
        ),
        compliance=[
            "AWS Security Hub CloudFront.9",
            "NIST SP 800-53 Rev. 5 SC-8",
            "PCI DSS v4.0.1/4.2.1",
        ],
    )


def check_cloudfront_deprecated_ssl_protocols(
    resource_id: str,
    resource_type: str,
    origins: list[dict],
) -> CloudFrontResult | None:
    if not resource_id:
        return None

    insecure_origins = []

    for origin in origins:
        if origin.get("is_s3_origin"):
            continue

        origin_id = origin.get("origin_id")
        origin_protocol_policy = origin.get(
            "origin_protocol_policy"
        )

        if not origin_id:
            continue

        if origin_protocol_policy == "http-only":
            continue

        ssl_protocols = origin.get(
            "origin_ssl_protocols",
            [],
        )

        if "SSLv3" not in ssl_protocols:
            continue

        insecure_origins.append(
            {
                "origin_id": origin_id,
                "domain_name": origin.get(
                    "domain_name"
                ),
                "origin_protocol_policy": (
                    origin_protocol_policy
                ),
                "origin_ssl_protocols": ssl_protocols,
            }
        )

    if not insecure_origins:
        return None

    return CloudFrontResult(
        resource_id=resource_id,
        resource_type=resource_type,
        details={
            "insecure_origins": insecure_origins,
        },
    )


def build_cloudfront_deprecated_ssl_protocols_finding(
    result: CloudFrontResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-CLOUDFRONT-007",
        title=(
            "CloudFront custom origin uses "
            "deprecated SSL protocol"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The CloudFront distribution "
            f"{result.resource_id} has one or more "
            "custom origins that allow the deprecated "
            "SSLv3 protocol."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Remove SSLv3 from OriginSslProtocols for "
            "all custom origins. Prefer TLSv1.2 or later "
            "for HTTPS communication with custom origins."
        ),
        compliance=[
            "AWS Security Hub CloudFront.10",
            "NIST SP 800-53 Rev. 5 SC-8",
            "NIST SP 800-171 Rev. 2 3.13.15",
            "PCI DSS v4.0.1/4.2.1",
        ],
    )


def check_cloudfront_tls_security_policy(
    resource_id: str,
    resource_type: str,
    viewer_security_policy: str | None,
) -> CloudFrontResult | None:
    if not resource_id:
        return None

    recommended_policies = {
        "TLSv1.2_2021",
        "TLSv1.2_2025",
        "TLSv1.3_2025",
    }

    if viewer_security_policy in recommended_policies:
        return None

    return CloudFrontResult(
        resource_id=resource_id,
        resource_type=resource_type,
        details={
            "viewer_security_policy": viewer_security_policy,
            "recommended_policies": sorted(
                recommended_policies
            ),
        },
    )


def build_cloudfront_tls_security_policy_finding(
    result: CloudFrontResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-CLOUDFRONT-008",
        title=(
            "CloudFront distribution does not use "
            "a recommended TLS security policy"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The CloudFront distribution "
            f"{result.resource_id} is not configured "
            "with a recommended viewer TLS security policy."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Configure the CloudFront distribution to use "
            "one of the recommended TLS security policies: "
            "TLSv1.2_2021, TLSv1.2_2025, or TLSv1.3_2025."
        ),
        compliance=[
            "AWS Security Hub CloudFront.15",
        ],
    )
