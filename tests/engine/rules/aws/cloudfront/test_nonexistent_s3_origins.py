from engine.findings.model import Severity
from engine.rules.aws.cloudfront.protection import (
    build_cloudfront_nonexistent_s3_origins_finding,
    check_cloudfront_nonexistent_s3_origins,
)


def test_nonexistent_s3_origin_is_detected():
    result = check_cloudfront_nonexistent_s3_origins(
        resource_id="DIST1",
        resource_type="cloudfront_distribution",
        s3_origins=[
            {
                "origin_id": "origin-1",
                "domain_name": (
                    "missing-bucket.s3.amazonaws.com"
                ),
                "s3_bucket_name": "missing-bucket",
                "s3_bucket_exists": False,
            }
        ],
    )

    assert result is not None
    assert result.details["nonexistent_s3_origins"] == [
        {
            "origin_id": "origin-1",
            "domain_name": (
                "missing-bucket.s3.amazonaws.com"
            ),
            "s3_bucket_name": "missing-bucket",
        }
    ]


def test_existing_or_unknown_s3_origin_is_not_reported():
    assert (
        check_cloudfront_nonexistent_s3_origins(
            resource_id="DIST1",
            resource_type="cloudfront_distribution",
            s3_origins=[
                {
                    "s3_bucket_exists": True,
                },
                {},
            ],
        )
        is None
    )


def test_nonexistent_s3_origin_finding():
    result = check_cloudfront_nonexistent_s3_origins(
        resource_id="DIST1",
        resource_type="cloudfront_distribution",
        s3_origins=[
            {
                "origin_id": "origin-1",
                "domain_name": (
                    "missing-bucket.s3.amazonaws.com"
                ),
                "s3_bucket_name": "missing-bucket",
                "s3_bucket_exists": False,
            }
        ],
    )

    finding = build_cloudfront_nonexistent_s3_origins_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-CLOUDFRONT-015"
    assert finding.severity == Severity.HIGH
    assert (
        "AWS Security Hub CloudFront.12"
        in finding.compliance
    )
