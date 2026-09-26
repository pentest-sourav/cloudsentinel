from unittest.mock import Mock

from scanner.aws.scanners.cloudfront import (
    CloudFrontScanner,
)


def test_cloudfront_scanner_executes_registered_rules():
    service = Mock()

    service.list_distributions.return_value = [
        {
            "Id": "E-insecure",
            "DistributionConfig": {
                "DefaultCacheBehavior": {
                    "ViewerProtocolPolicy": (
                        "allow-all"
                    ),
                },
                "Logging": {
                    "Enabled": False,
                },
                "Origins": {
                    "Items": [
                        {
                            "Id": "S3-origin",
                            "DomainName": (
                                "bucket.s3.amazonaws.com"
                            ),
                            "S3OriginConfig": {},
                        },
                    ],
                },
            },
        },
    ]

    findings = CloudFrontScanner(
        service
    ).scan()

    rule_ids = {
        finding.rule_id
        for finding in findings
    }

    assert rule_ids == {
        "CS-AWS-CLOUDFRONT-001",
        "CS-AWS-CLOUDFRONT-002",
        "CS-AWS-CLOUDFRONT-003",
        "CS-AWS-CLOUDFRONT-004",
        "CS-AWS-CLOUDFRONT-005",
    }
