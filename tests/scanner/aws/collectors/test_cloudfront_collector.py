from unittest.mock import Mock

from scanner.aws.collectors.cloudfront import CloudFrontDataCollector


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
                    "TargetOriginId": "S3-origin",
                    "ViewerProtocolPolicy": "redirect-to-https",
                },
                "CacheBehaviors": {
                    "Items": [
                        {
                            "TargetOriginId": "S3-origin",
                            "ViewerProtocolPolicy": "https-only",
                        },
                    ],
                },
                "Logging": {
                    "Enabled": True,
                    "Bucket": "logs.example.com",
                },
                "ViewerCertificate": {
                    "CloudFrontDefaultCertificate": False,
                    "MinimumProtocolVersion": "TLSv1.2_2021",
                    "SSLSupportMethod": "sni-only",
                },
                "WebACLId": "waf-example",
                "Origins": {
                    "Items": [
                        {
                            "Id": "S3-origin",
                            "DomainName": "bucket.s3.amazonaws.com",
                            "S3OriginConfig": {
                                "OriginAccessIdentity": "",
                            },
                            "OriginAccessControlId": "oac-example",
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
            "resource_type": "cloudfront_distribution",
            "domain_name": "d123.cloudfront.net",
            "enabled": True,
            "default_root_object": "index.html",
            "viewer_protocol_policies": [
                "redirect-to-https",
                "https-only",
            ],
            "logging_enabled": True,
            "viewer_security_policy": "TLSv1.2_2021",
            "waf_web_acl_id": "waf-example",
            "waf_enabled": True,
            "origins": [
                {
                    "origin_id": "S3-origin",
                    "domain_name": "bucket.s3.amazonaws.com",
                    "is_s3_origin": True,
                    "origin_access_control_id": "oac-example",
                    "origin_access_identity": "",
                    "origin_protocol_policy": None,
                    "origin_ssl_protocols": [],
                },
            ],
            "s3_origins": [
                {
                    "origin_id": "S3-origin",
                    "domain_name": "bucket.s3.amazonaws.com",
                    "is_s3_origin": True,
                    "origin_access_control_id": "oac-example",
                    "origin_access_identity": "",
                    "origin_protocol_policy": None,
                    "origin_ssl_protocols": [],
                },
            ],
            "origin_groups_count": 0,
            "cache_behaviors": [
                {
                    "behavior_type": "default",
                    "target_origin_id": "S3-origin",
                    "target_origin_ids": ["S3-origin"],
                    "viewer_protocol_policy": "redirect-to-https",
                },
                {
                    "behavior_type": "ordered",
                    "target_origin_id": "S3-origin",
                    "target_origin_ids": ["S3-origin"],
                    "viewer_protocol_policy": "https-only",
                },
            ],
        },
    ]


def test_collect_distributions_normalizes_cache_behavior_origin_groups():
    service = Mock()

    service.list_distributions.return_value = [
        {
            "Id": "E456",
            "DomainName": "d456.cloudfront.net",
            "DistributionConfig": {
                "Enabled": True,
                "DefaultCacheBehavior": {
                    "TargetOriginId": "origin-group",
                    "ViewerProtocolPolicy": "redirect-to-https",
                },
                "CacheBehaviors": {
                    "Items": [
                        {
                            "TargetOriginId": "origin-group",
                            "ViewerProtocolPolicy": "https-only",
                        },
                    ],
                },
                "Origins": {
                    "Items": [
                        {
                            "Id": "origin-a",
                            "DomainName": "api-a.example.com",
                            "CustomOriginConfig": {
                                "OriginProtocolPolicy": "https-only",
                                "OriginSslProtocols": {
                                    "Items": ["TLSv1.2"],
                                },
                            },
                        },
                        {
                            "Id": "origin-b",
                            "DomainName": "api-b.example.com",
                            "CustomOriginConfig": {
                                "OriginProtocolPolicy": "https-only",
                                "OriginSslProtocols": {
                                    "Items": ["TLSv1.2"],
                                },
                            },
                        },
                    ],
                },
                "OriginGroups": {
                    "Items": [
                        {
                            "Id": "origin-group",
                            "Members": {
                                "Items": [
                                    {"OriginId": "origin-a"},
                                    {"OriginId": "origin-b"},
                                ],
                            },
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
            "resource_id": "E456",
            "resource_type": "cloudfront_distribution",
            "domain_name": "d456.cloudfront.net",
            "enabled": True,
            "default_root_object": None,
            "viewer_protocol_policies": [
                "redirect-to-https",
                "https-only",
            ],
            "logging_enabled": False,
            "viewer_security_policy": None,
            "waf_web_acl_id": None,
            "waf_enabled": False,
            "origins": [
                {
                    "origin_id": "origin-a",
                    "domain_name": "api-a.example.com",
                    "is_s3_origin": False,
                    "origin_access_control_id": None,
                    "origin_access_identity": None,
                    "origin_protocol_policy": "https-only",
                    "origin_ssl_protocols": ["TLSv1.2"],
                },
                {
                    "origin_id": "origin-b",
                    "domain_name": "api-b.example.com",
                    "is_s3_origin": False,
                    "origin_access_control_id": None,
                    "origin_access_identity": None,
                    "origin_protocol_policy": "https-only",
                    "origin_ssl_protocols": ["TLSv1.2"],
                },
            ],
            "s3_origins": [],
            "origin_groups_count": 1,
            "cache_behaviors": [
                {
                    "behavior_type": "default",
                    "target_origin_id": "origin-group",
                    "target_origin_ids": [
                        "origin-a",
                        "origin-b",
                    ],
                    "viewer_protocol_policy": "redirect-to-https",
                },
                {
                    "behavior_type": "ordered",
                    "target_origin_id": "origin-group",
                    "target_origin_ids": [
                        "origin-a",
                        "origin-b",
                    ],
                    "viewer_protocol_policy": "https-only",
                },
            ],
        },
    ]
