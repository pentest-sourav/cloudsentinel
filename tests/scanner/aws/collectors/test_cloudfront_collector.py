from unittest.mock import Mock

from scanner.aws.collectors.cloudfront import (
    CloudFrontDataCollector,
)


def test_collect_distributions_normalizes_security_fields():
    service = Mock()

    service.list_distributions.return_value = [
        {
            "Id": "E123",
            "DomainName": "d123.cloudfront.net",
            "DistributionConfig": {
                "Enabled": True,
                "DefaultRootObject": "index.html",
                "DefaultCacheBehavior": {
                    "ViewerProtocolPolicy": (
                        "redirect-to-https"
                    ),
                },
                "CacheBehaviors": {
                    "Items": [
                        {
                            "ViewerProtocolPolicy": (
                                "https-only"
                            ),
                        },
                    ],
                },
                "Logging": {
                    "Enabled": True,
                    "Bucket": "logs.example.com",
                },
                "WebACLId": "waf-example",
                "Origins": {
                    "Items": [
                        {
                            "Id": "S3-origin",
                            "DomainName": (
                                "bucket.s3.amazonaws.com"
                            ),
                            "S3OriginConfig": {
                                "OriginAccessIdentity": "",
                            },
                            "OriginAccessControlId": (
                                "oac-example"
                            ),
                        },
                    ],
                },
            },
        },
    ]

    collector = CloudFrontDataCollector(service)

    result = collector.collect_distributions()

    assert result == [
        {
            "resource_id": "E123",
            "resource_type": (
                "cloudfront_distribution"
            ),
            "domain_name": "d123.cloudfront.net",
            "enabled": True,
            "default_root_object": "index.html",
            "viewer_protocol_policies": [
                "redirect-to-https",
                "https-only",
            ],
            "logging_enabled": True,
            "waf_web_acl_id": "waf-example",
            "waf_enabled": True,
            "origins": [
                {
                    "origin_id": "S3-origin",
                    "domain_name": (
                        "bucket.s3.amazonaws.com"
                    ),
                    "is_s3_origin": True,
                    "origin_access_control_id": (
                        "oac-example"
                    ),
                    "origin_access_identity": "",
                    "origin_protocol_policy": None,
                    "origin_ssl_protocols": [],
                },
            ],
            "s3_origins": [
                {
                    "origin_id": "S3-origin",
                    "domain_name": (
                        "bucket.s3.amazonaws.com"
                    ),
                    "is_s3_origin": True,
                    "origin_access_control_id": (
                        "oac-example"
                    ),
                    "origin_access_identity": "",
                    "origin_protocol_policy": None,
                    "origin_ssl_protocols": [],
                },
            ],
            "origin_groups_count": 0,
        },
    ]


def test_collector_caches_distributions():
    service = Mock()

    service.list_distributions.return_value = [
        {
            "Id": "E123",
            "DistributionConfig": {},
        },
    ]

    collector = CloudFrontDataCollector(service)

    collector.collect_distributions()
    collector.collect_distributions()

    service.list_distributions.assert_called_once()
