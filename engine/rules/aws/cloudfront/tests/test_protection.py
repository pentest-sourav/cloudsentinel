from engine.findings.model import Severity
from engine.rules.aws.cloudfront.protection import (
    build_cloudfront_default_root_object_finding,
    build_cloudfront_logging_finding,
    build_cloudfront_s3_oac_finding,
    build_cloudfront_viewer_https_finding,
    build_cloudfront_waf_finding,
    check_cloudfront_default_root_object,
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
