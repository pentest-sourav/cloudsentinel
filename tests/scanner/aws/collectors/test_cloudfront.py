from unittest.mock import Mock

from scanner.aws.collectors.cloudfront import (
    CloudFrontDataCollector,
)


def test_normalize_s3_origin_extracts_bucket_name():
    distribution = {
        "Id": "DIST1",
        "DistributionConfig": {
            "Origins": {
                "Items": [
                    {
                        "Id": "origin-1",
                        "DomainName": (
                            "my-bucket.s3.us-east-1.amazonaws.com"
                        ),
                        "S3OriginConfig": {},
                    },
                ],
            },
        },
    }

    item = CloudFrontDataCollector._normalize_distribution(
        distribution
    )

    assert item["s3_origins"][0]["s3_bucket_name"] == (
        "my-bucket"
    )


def test_collect_distributions_records_bucket_existence():
    service = Mock()
    service.list_distributions.return_value = [
        {
            "Id": "DIST1",
            "ARN": "arn:aws:cloudfront::123:distribution/DIST1",
            "DistributionConfig": {
                "Origins": {
                    "Items": [
                        {
                            "Id": "origin-1",
                            "DomainName": (
                                "missing-bucket.s3.amazonaws.com"
                            ),
                            "S3OriginConfig": {},
                        },
                    ],
                },
            },
        }
    ]
    service.check_s3_bucket_exists.return_value = False
    service.list_tags_for_resource.return_value = []

    collector = CloudFrontDataCollector(service)
    items = collector.collect_distributions()

    origin = items[0]["s3_origins"][0]

    assert origin["s3_bucket_name"] == "missing-bucket"
    assert origin["s3_bucket_exists"] is False
    service.check_s3_bucket_exists.assert_called_once_with(
        "missing-bucket"
    )
