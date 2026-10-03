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
                    "TargetOriginId": "S3-origin",
                    "ViewerProtocolPolicy": (
                        "redirect-to-https"
                    ),
                    "TrustedKeyGroups": {
                        "Enabled": True,
                        "Items": ["kg-default"],
                    },
                    "TrustedSigners": {
                        "Enabled": False,
                        "Items": [],
                    },
                },
                "CacheBehaviors": {
                    "Items": [
                        {
                            "TargetOriginId": "S3-origin",
                            "ViewerProtocolPolicy": (
                                "https-only"
                            ),
                            "TrustedKeyGroups": {
                                "Enabled": True,
                                "Items": ["kg-ordered"],
                            },
                            "TrustedSigners": {
                                "Enabled": False,
                                "Items": [],
                            },
                        },
                    ],
                },
                "Logging": {
                    "Enabled": True,
                    "Bucket": "logs.example.com",
                },
                "ViewerCertificate": {
                    "CloudFrontDefaultCertificate": False,
                    "MinimumProtocolVersion": (
                        "TLSv1.2_2021"
                    ),
                    "SSLSupportMethod": "sni-only",
                    "ACMCertificateArn": (
                        "arn:aws:acm:us-east-1:123:"
                        "certificate/example"
                    ),
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

    service.list_tags_for_resource.return_value = []
    service.check_s3_bucket_exists.return_value = True
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
            "viewer_security_policy": (
                "TLSv1.2_2021"
            ),
            "cloudfront_default_certificate": False,
            "ssl_support_method": "sni-only",
            "acm_certificate_arn": (
                "arn:aws:acm:us-east-1:123:"
                "certificate/example"
            ),
            "iam_certificate_id": None,
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
                    "s3_bucket_name": "bucket",
                    "s3_bucket_exists": True,
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
            "cache_behaviors": [
                {
                    "behavior_type": "default",
                    "target_origin_id": "S3-origin",
                    "target_origin_ids": [
                        "S3-origin"
                    ],
                    "viewer_protocol_policy": (
                        "redirect-to-https"
                    ),
                    "trusted_key_groups_enabled": True,
                    "trusted_key_group_ids": [
                        "kg-default"
                    ],
                    "trusted_signers_enabled": False,
                    "trusted_signer_ids": [],
                },
                {
                    "behavior_type": "ordered",
                    "target_origin_id": "S3-origin",
                    "target_origin_ids": [
                        "S3-origin"
                    ],
                    "viewer_protocol_policy": (
                        "https-only"
                    ),
                    "trusted_key_groups_enabled": True,
                    "trusted_key_group_ids": [
                        "kg-ordered"
                    ],
                    "trusted_signers_enabled": False,
                    "trusted_signer_ids": [],
                },
            ],
            "origin_groups": {},
            "origin_groups_count": 0,
            "tags": [],
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
                    "ViewerProtocolPolicy": (
                        "redirect-to-https"
                    ),
                    "TrustedKeyGroups": {
                        "Enabled": True,
                        "Items": ["kg-1"],
                    },
                    "TrustedSigners": {
                        "Enabled": False,
                        "Items": [],
                    },
                },
                "CacheBehaviors": {
                    "Items": [
                        {
                            "TargetOriginId": "origin-group",
                            "ViewerProtocolPolicy": (
                                "https-only"
                            ),
                        },
                    ],
                },
                "Origins": {
                    "Items": [
                        {
                            "Id": "origin-a",
                            "DomainName": (
                                "api-a.example.com"
                            ),
                            "CustomOriginConfig": {
                                "OriginProtocolPolicy": (
                                    "https-only"
                                ),
                                "OriginSslProtocols": {
                                    "Items": ["TLSv1.2"],
                                },
                            },
                        },
                        {
                            "Id": "origin-b",
                            "DomainName": (
                                "api-b.example.com"
                            ),
                            "CustomOriginConfig": {
                                "OriginProtocolPolicy": (
                                    "https-only"
                                ),
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
                                    {
                                        "OriginId": "origin-a"
                                    },
                                    {
                                        "OriginId": "origin-b"
                                    },
                                ],
                            },
                        },
                    ],
                },
            },
        },
    ]

    service.list_tags_for_resource.return_value = []
    collector = CloudFrontDataCollector(service)

    result = collector.collect_distributions()

    assert result[0]["origin_groups"] == {
        "origin-group": [
            "origin-a",
            "origin-b",
        ]
    }

    assert result[0]["origin_groups_count"] == 1

    assert result[0]["cache_behaviors"][0][
        "trusted_key_groups_enabled"
    ] is True

    assert result[0]["cache_behaviors"][0][
        "trusted_key_group_ids"
    ] == ["kg-1"]
