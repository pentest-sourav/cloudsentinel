from engine.findings.model import Severity
from engine.rules.aws.cloudfront.protection import (
    build_cloudfront_custom_origin_https_finding,
    build_cloudfront_default_root_object_finding,
    build_cloudfront_deprecated_ssl_protocols_finding,
    build_cloudfront_logging_finding,
    build_cloudfront_s3_oac_finding,
    build_cloudfront_viewer_https_finding,
    build_cloudfront_waf_finding,
    check_cloudfront_custom_origin_https,
    check_cloudfront_default_root_object,
    check_cloudfront_deprecated_ssl_protocols,
    check_cloudfront_logging,
    check_cloudfront_s3_oac,
    check_cloudfront_viewer_https,
    check_cloudfront_waf,
)



S3_ORIGIN = {
    "origin_id": "S3-origin",
    "domain_name": "bucket.s3.amazonaws.com",
    "is_s3_origin": True,
    "origin_access_control_id": None,
}


def test_s3_distribution_without_default_root_fails():
    result = check_cloudfront_default_root_object(
        "E1",
        "cloudfront_distribution",
        [S3_ORIGIN],
        None,
    )

    finding = (
        build_cloudfront_default_root_object_finding(
            result
        )
    )

    assert finding.rule_id == "CS-AWS-CLOUDFRONT-001"
    assert finding.severity == Severity.HIGH


def test_custom_origin_does_not_require_default_root():
    assert (
        check_cloudfront_default_root_object(
            "E1",
            "cloudfront_distribution",
            [],
            None,
        )
        is None
    )


def test_https_viewer_policy_passes():
    assert (
        check_cloudfront_viewer_https(
            "E1",
            "cloudfront_distribution",
            [
                "redirect-to-https",
                "https-only",
            ],
        )
        is None
    )


def test_allow_all_viewer_policy_fails():
    result = check_cloudfront_viewer_https(
        "E1",
        "cloudfront_distribution",
        ["allow-all"],
    )

    finding = build_cloudfront_viewer_https_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-CLOUDFRONT-002"
    assert finding.severity == Severity.MEDIUM


def test_logging_enabled_passes():
    assert (
        check_cloudfront_logging(
            "E1",
            "cloudfront_distribution",
            True,
        )
        is None
    )


def test_logging_disabled_fails():
    result = check_cloudfront_logging(
        "E1",
        "cloudfront_distribution",
        False,
    )

    finding = build_cloudfront_logging_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-CLOUDFRONT-003"


def test_waf_enabled_passes():
    assert (
        check_cloudfront_waf(
            "E1",
            "cloudfront_distribution",
            True,
            "waf-123",
        )
        is None
    )


def test_waf_missing_fails():
    result = check_cloudfront_waf(
        "E1",
        "cloudfront_distribution",
        False,
        None,
    )

    finding = build_cloudfront_waf_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-CLOUDFRONT-004"


def test_s3_oac_enabled_passes():
    assert (
        check_cloudfront_s3_oac(
            "E1",
            "cloudfront_distribution",
            [
                {
                    **S3_ORIGIN,
                    "origin_access_control_id": "oac-123",
                }
            ],
        )
        is None
    )


def test_s3_oac_missing_fails():
    result = check_cloudfront_s3_oac(
        "E1",
        "cloudfront_distribution",
        [S3_ORIGIN],
    )

    finding = build_cloudfront_s3_oac_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-CLOUDFRONT-005"


CUSTOM_ORIGIN = {
    "origin_id": "custom-origin",
    "domain_name": "origin.example.com",
    "is_s3_origin": False,
    "origin_protocol_policy": "https-only",
}


def test_custom_origin_http_only_fails_cloudfront_006():
    result = check_cloudfront_custom_origin_https(
        "E1",
        "cloudfront_distribution",
        [
            {
                **CUSTOM_ORIGIN,
                "origin_protocol_policy": "http-only",
            }
        ],
        [
            {
                "target_origin_id": "custom-origin",
                "target_origin_ids": ["custom-origin"],
                "viewer_protocol_policy": "https-only",
            }
        ],
    )

    finding = build_cloudfront_custom_origin_https_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-CLOUDFRONT-006"
    assert finding.severity == Severity.MEDIUM


def test_custom_origin_https_only_passes_cloudfront_006():
    assert (
        check_cloudfront_custom_origin_https(
            "E1",
            "cloudfront_distribution",
            [CUSTOM_ORIGIN],
            [
                {
                    "target_origin_id": "custom-origin",
                    "target_origin_ids": ["custom-origin"],
                    "viewer_protocol_policy": "https-only",
                }
            ],
        )
        is None
    )


def test_match_viewer_with_allow_all_fails_cloudfront_006():
    result = check_cloudfront_custom_origin_https(
        "E1",
        "cloudfront_distribution",
        [
            {
                **CUSTOM_ORIGIN,
                "origin_protocol_policy": "match-viewer",
            }
        ],
        [
            {
                "target_origin_id": "custom-origin",
                "target_origin_ids": ["custom-origin"],
                "viewer_protocol_policy": "allow-all",
            }
        ],
    )

    finding = build_cloudfront_custom_origin_https_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-CLOUDFRONT-006"


def test_match_viewer_with_redirect_to_https_passes():
    assert (
        check_cloudfront_custom_origin_https(
            "E1",
            "cloudfront_distribution",
            [
                {
                    **CUSTOM_ORIGIN,
                    "origin_protocol_policy": "match-viewer",
                }
            ],
            [
                {
                    "target_origin_id": "custom-origin",
                    "target_origin_ids": ["custom-origin"],
                    "viewer_protocol_policy": (
                        "redirect-to-https"
                    ),
                }
            ],
        )
        is None
    )


def test_match_viewer_with_https_only_passes():
    assert (
        check_cloudfront_custom_origin_https(
            "E1",
            "cloudfront_distribution",
            [
                {
                    **CUSTOM_ORIGIN,
                    "origin_protocol_policy": "match-viewer",
                }
            ],
            [
                {
                    "target_origin_id": "custom-origin",
                    "target_origin_ids": ["custom-origin"],
                    "viewer_protocol_policy": "https-only",
                }
            ],
        )
        is None
    )


def test_s3_origin_is_ignored_by_cloudfront_006():
    assert (
        check_cloudfront_custom_origin_https(
            "E1",
            "cloudfront_distribution",
            [
                {
                    **S3_ORIGIN,
                    "origin_protocol_policy": None,
                }
            ],
            [
                {
                    "target_origin_id": "S3-origin",
                    "target_origin_ids": ["S3-origin"],
                    "viewer_protocol_policy": "allow-all",
                }
            ],
        )
        is None
    )


def test_allow_all_on_different_origin_does_not_fail():
    assert (
        check_cloudfront_custom_origin_https(
            "E1",
            "cloudfront_distribution",
            [
                {
                    **CUSTOM_ORIGIN,
                    "origin_id": "secure-origin",
                    "origin_protocol_policy": (
                        "match-viewer"
                    ),
                },
                {
                    **CUSTOM_ORIGIN,
                    "origin_id": "other-origin",
                    "origin_protocol_policy": (
                        "https-only"
                    ),
                },
            ],
            [
                {
                    "target_origin_id": "secure-origin",
                    "target_origin_ids": ["secure-origin"],
                    "viewer_protocol_policy": "https-only",
                },
                {
                    "target_origin_id": "other-origin",
                    "target_origin_ids": ["other-origin"],
                    "viewer_protocol_policy": "allow-all",
                },
            ],
        )
        is None
    )


def test_custom_origin_ssl_v3_fails_cloudfront_007():
    result = check_cloudfront_deprecated_ssl_protocols(
        "E1",
        "cloudfront_distribution",
        [
            {
                **CUSTOM_ORIGIN,
                "origin_protocol_policy": "https-only",
                "origin_ssl_protocols": [
                    "SSLv3",
                    "TLSv1.2",
                ],
            }
        ],
    )

    finding = (
        build_cloudfront_deprecated_ssl_protocols_finding(
            result
        )
    )

    assert finding.rule_id == "CS-AWS-CLOUDFRONT-007"
    assert finding.severity == Severity.MEDIUM


def test_custom_origin_tls12_only_passes_cloudfront_007():
    assert (
        check_cloudfront_deprecated_ssl_protocols(
            "E1",
            "cloudfront_distribution",
            [
                {
                    **CUSTOM_ORIGIN,
                    "origin_protocol_policy": "https-only",
                    "origin_ssl_protocols": [
                        "TLSv1.2",
                    ],
                }
            ],
        )
        is None
    )


def test_http_only_origin_is_ignored_by_cloudfront_007():
    assert (
        check_cloudfront_deprecated_ssl_protocols(
            "E1",
            "cloudfront_distribution",
            [
                {
                    **CUSTOM_ORIGIN,
                    "origin_protocol_policy": "http-only",
                    "origin_ssl_protocols": [],
                }
            ],
        )
        is None
    )


def test_s3_origin_is_ignored_by_cloudfront_007():
    assert (
        check_cloudfront_deprecated_ssl_protocols(
            "E1",
            "cloudfront_distribution",
            [
                {
                    **S3_ORIGIN,
                    "origin_protocol_policy": None,
                    "origin_ssl_protocols": [
                        "SSLv3",
                    ],
                }
            ],
        )
        is None
    )


def test_multiple_custom_origins_only_insecure_origins_fail():
    result = check_cloudfront_deprecated_ssl_protocols(
        "E1",
        "cloudfront_distribution",
        [
            {
                **CUSTOM_ORIGIN,
                "origin_id": "secure-origin",
                "origin_ssl_protocols": [
                    "TLSv1.2",
                ],
            },
            {
                **CUSTOM_ORIGIN,
                "origin_id": "legacy-origin",
                "origin_ssl_protocols": [
                    "SSLv3",
                    "TLSv1.2",
                ],
            },
        ],
    )

    assert result is not None
    assert result.details["insecure_origins"] == [
        {
            "origin_id": "legacy-origin",
            "domain_name": "origin.example.com",
            "origin_protocol_policy": "https-only",
            "origin_ssl_protocols": [
                "SSLv3",
                "TLSv1.2",
            ],
        }
    ]
