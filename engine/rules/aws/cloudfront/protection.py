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
            "default_root_object": default_root_object,
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
            "origin_id": origin.get(
                "origin_id"
            ),
            "domain_name": origin.get(
                "domain_name"
            ),
            "origin_access_control_id": (
                origin.get(
                    "origin_access_control_id"
                )
            ),
            "origin_access_identity": (
                origin.get(
                    "origin_access_identity"
                )
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

        origin_id = origin.get(
            "origin_id"
        )

        origin_protocol_policy = origin.get(
            "origin_protocol_policy"
        )

        if (
            not origin_id
            or not origin_protocol_policy
        ):
            continue

        viewer_policies = behaviors_by_origin.get(
            origin_id,
            [],
        )

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
            origin_protocol_policy
            == "match-viewer"
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

        origin_id = origin.get(
            "origin_id"
        )

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
                "origin_ssl_protocols": (
                    ssl_protocols
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
            "viewer_security_policy": (
                viewer_security_policy
            ),
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


# ============================================================
# CLOUDFRONT.4
# ============================================================

def check_cloudfront_origin_failover(
    resource_id: str,
    resource_type: str,
    origin_groups: dict[str, list[str]],
) -> CloudFrontResult | None:
    if not resource_id:
        return None

    valid_groups = {
        group_id: origin_ids
        for group_id, origin_ids in origin_groups.items()
        if len(origin_ids) >= 2
    }

    if valid_groups:
        return None

    return CloudFrontResult(
        resource_id=resource_id,
        resource_type=resource_type,
        details={
            "origin_groups": origin_groups,
        },
    )


def build_cloudfront_origin_failover_finding(
    result: CloudFrontResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-CLOUDFRONT-009",
        title=(
            "CloudFront distribution has no origin failover"
        ),
        severity=Severity.LOW,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The CloudFront distribution "
            f"{result.resource_id} does not have an "
            "origin group containing at least two origins."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Configure a CloudFront origin group with a "
            "primary and secondary origin and configure "
            "appropriate failover criteria."
        ),
        compliance=[
            "AWS Security Hub CloudFront.4",
            "NIST SP 800-53 Rev. 5 CP-10",
            "NIST SP 800-53 Rev. 5 SC-36",
            "NIST SP 800-53 Rev. 5 SC-5(2)",
            "NIST SP 800-53 Rev. 5 SI-13(5)",
        ],
    )


# ============================================================
# CLOUDFRONT.7
# ============================================================

def check_cloudfront_custom_certificate(
    resource_id: str,
    resource_type: str,
    cloudfront_default_certificate: bool,
    acm_certificate_arn: str | None,
    iam_certificate_id: str | None,
) -> CloudFrontResult | None:
    if not resource_id:
        return None

    if (
        not cloudfront_default_certificate
        and (
            acm_certificate_arn
            or iam_certificate_id
        )
    ):
        return None

    return CloudFrontResult(
        resource_id=resource_id,
        resource_type=resource_type,
        details={
            "cloudfront_default_certificate": (
                cloudfront_default_certificate
            ),
            "acm_certificate_arn": (
                acm_certificate_arn
            ),
            "iam_certificate_id": (
                iam_certificate_id
            ),
        },
    )


def build_cloudfront_custom_certificate_finding(
    result: CloudFrontResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-CLOUDFRONT-010",
        title=(
            "CloudFront distribution does not use "
            "a custom SSL/TLS certificate"
        ),
        severity=Severity.LOW,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The CloudFront distribution "
            f"{result.resource_id} is using the default "
            "CloudFront SSL/TLS certificate instead of "
            "a custom certificate."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Associate an appropriate ACM or IAM SSL/TLS "
            "certificate with the CloudFront distribution."
        ),
        compliance=[
            "AWS Security Hub CloudFront.7",
            "NIST SP 800-53 Rev. 5 CA-9(1)",
            "NIST SP 800-53 Rev. 5 SC-13",
        ],
    )


# ============================================================
# CLOUDFRONT.8
# ============================================================

def check_cloudfront_sni(
    resource_id: str,
    resource_type: str,
    cloudfront_default_certificate: bool,
    ssl_support_method: str | None,
) -> CloudFrontResult | None:
    if not resource_id:
        return None

    if cloudfront_default_certificate:
        return CloudFrontResult(
            resource_id=resource_id,
            resource_type=resource_type,
            details={
                "cloudfront_default_certificate": True,
                "ssl_support_method": ssl_support_method,
            },
        )

    if ssl_support_method == "sni-only":
        return None

    return CloudFrontResult(
        resource_id=resource_id,
        resource_type=resource_type,
        details={
            "cloudfront_default_certificate": (
                cloudfront_default_certificate
            ),
            "ssl_support_method": ssl_support_method,
        },
    )


def build_cloudfront_sni_finding(
    result: CloudFrontResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-CLOUDFRONT-011",
        title=(
            "CloudFront distribution does not use SNI"
        ),
        severity=Severity.LOW,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The CloudFront distribution "
            f"{result.resource_id} does not use a custom "
            "certificate with SNI-only HTTPS support."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Associate a custom SSL/TLS certificate and "
            "configure SSLSupportMethod=sni-only."
        ),
        compliance=[
            "AWS Security Hub CloudFront.8",
            "NIST SP 800-53 Rev. 5 CA-9(1)",
            "NIST SP 800-53 Rev. 5 CM-2",
        ],
    )


# ============================================================
# CLOUDFRONT.16
# ============================================================

def check_cloudfront_lambda_function_url_oac(
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

        domain_name = origin.get(
            "domain_name"
        )

        if not isinstance(
            domain_name,
            str,
        ):
            continue

        normalized_domain = domain_name.lower()

        is_lambda_url = (
            ".lambda-url."
            in normalized_domain
            and normalized_domain.endswith(
                ".on.aws"
            )
        )

        if not is_lambda_url:
            continue

        if origin.get(
            "origin_access_control_id"
        ):
            continue

        insecure_origins.append(
            {
                "origin_id": origin.get(
                    "origin_id"
                ),
                "domain_name": domain_name,
                "origin_access_control_id": (
                    origin.get(
                        "origin_access_control_id"
                    )
                ),
            }
        )

    if not insecure_origins:
        return None

    return CloudFrontResult(
        resource_id=resource_id,
        resource_type=resource_type,
        details={
            "insecure_lambda_function_url_origins": (
                insecure_origins
            ),
        },
    )


def build_cloudfront_lambda_function_url_oac_finding(
    result: CloudFrontResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-CLOUDFRONT-012",
        title=(
            "CloudFront Lambda function URL origin "
            "does not use Origin Access Control"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The CloudFront distribution "
            f"{result.resource_id} has one or more "
            "Lambda function URL origins without "
            "Origin Access Control."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Configure Origin Access Control for the "
            "Lambda function URL origin and require "
            "AWS_IAM authentication on the function URL."
        ),
        compliance=[
            "AWS Security Hub CloudFront.16",
        ],
    )


# ============================================================
# CLOUDFRONT.17
# ============================================================

def check_cloudfront_trusted_key_groups(
    resource_id: str,
    resource_type: str,
    cache_behaviors: list[dict],
) -> CloudFrontResult | None:
    if not resource_id:
        return None

    insecure_behaviors = []

    for behavior in cache_behaviors:
        key_groups_enabled = bool(
            behavior.get(
                "trusted_key_groups_enabled",
                False,
            )
        )

        signers_enabled = bool(
            behavior.get(
                "trusted_signers_enabled",
                False,
            )
        )

        key_group_ids = behavior.get(
            "trusted_key_group_ids",
            [],
        )

        signer_ids = behavior.get(
            "trusted_signer_ids",
            [],
        )

        if (
            signers_enabled
            or not key_groups_enabled
            or not key_group_ids
        ):
            insecure_behaviors.append(
                {
                    "behavior_type": behavior.get(
                        "behavior_type"
                    ),
                    "target_origin_id": behavior.get(
                        "target_origin_id"
                    ),
                    "trusted_key_groups_enabled": (
                        key_groups_enabled
                    ),
                    "trusted_key_group_ids": (
                        key_group_ids
                    ),
                    "trusted_signers_enabled": (
                        signers_enabled
                    ),
                    "trusted_signer_ids": signer_ids,
                }
            )

    if not insecure_behaviors:
        return None

    return CloudFrontResult(
        resource_id=resource_id,
        resource_type=resource_type,
        details={
            "insecure_behaviors": insecure_behaviors,
        },
    )


def build_cloudfront_trusted_key_groups_finding(
    result: CloudFrontResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-CLOUDFRONT-013",
        title=(
            "CloudFront distribution does not use "
            "trusted key groups for signed URLs or cookies"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The CloudFront distribution "
            f"{result.resource_id} has a cache behavior "
            "without trusted key group authentication, "
            "or it uses legacy trusted signers."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Configure trusted key groups for cache "
            "behaviors that require signed URLs or "
            "signed cookies, and migrate away from "
            "legacy trusted signers."
        ),
        compliance=[
            "AWS Security Hub CloudFront.17",
        ],
    )


# ============================================================
# CLOUDFRONT.12
# ============================================================

def check_cloudfront_nonexistent_s3_origins(
    resource_id: str,
    resource_type: str,
    s3_origins: list[dict],
) -> CloudFrontResult | None:
    if not resource_id or not s3_origins:
        return None

    nonexistent_origins = [
        {
            "origin_id": origin.get("origin_id"),
            "domain_name": origin.get("domain_name"),
            "s3_bucket_name": origin.get("s3_bucket_name"),
        }
        for origin in s3_origins
        if origin.get("s3_bucket_exists") is False
    ]

    if not nonexistent_origins:
        return None

    return CloudFrontResult(
        resource_id=resource_id,
        resource_type=resource_type,
        details={
            "nonexistent_s3_origins": nonexistent_origins,
        },
    )


def build_cloudfront_nonexistent_s3_origins_finding(
    result: CloudFrontResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-CLOUDFRONT-015",
        title=(
            "CloudFront distribution points to a "
            "non-existent S3 origin"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The CloudFront distribution "
            f"{result.resource_id} references one or more "
            "S3 origins whose buckets do not exist."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Remove the invalid S3 origin, correct the "
            "origin configuration, or recreate the "
            "referenced S3 bucket as appropriate."
        ),
        compliance=[
            "AWS Security Hub CloudFront.12",
        ],
    )
