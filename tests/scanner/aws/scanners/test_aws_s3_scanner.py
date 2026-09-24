from unittest.mock import Mock

from scanner.aws.scanners.s3 import S3Scanner


def test_s3_scanner_returns_findings_for_public_buckets():
    fake_service = Mock()

    fake_service.list_buckets.return_value = [
        {
            "name": "private-bucket",
            "creation_date": "2026-09-16T10:00:00Z",
        },
        {
            "name": "public-bucket",
            "creation_date": "2026-09-16T11:00:00Z",
        },
        {
            "name": "another-public-bucket",
            "creation_date": "2026-09-16T12:00:00Z",
        },
    ]

    fake_service.get_public_access_block.side_effect = [
        {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
        {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
        {},
    ]

    # Secure configuration for all other S3 rules.
    fake_service.get_bucket_encryption.return_value = {
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256",
                }
            }
        ]
    }

    fake_service.get_bucket_policy_status.return_value = {
        "PolicyStatus": {
            "IsPublic": False,
        }
    }

    fake_service.get_bucket_policy.return_value = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyInsecureTransport",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [
                    "arn:aws:s3:::example-bucket",
                    "arn:aws:s3:::example-bucket/*",
                ],
                "Condition": {
                    "Bool": {
                        "aws:SecureTransport": "false",
                    }
                },
            }
        ],
    }

    fake_service.get_bucket_acl.return_value = {
        "Owner": {
            "ID": "owner-id",
        },
        "Grants": [
            {
                "Grantee": {
                    "Type": "CanonicalUser",
                    "ID": "owner-id",
                },
                "Permission": "FULL_CONTROL",
            }
        ],
    }

    fake_service.get_bucket_versioning.return_value = {
        "Status": "Enabled",
    }

    fake_service.get_bucket_logging.return_value = {
        "LoggingEnabled": {
            "TargetBucket": "log-bucket",
        }
    }

    fake_service.get_object_lock_configuration.return_value = {
        "ObjectLockEnabled": "Enabled",
    }

    fake_service.get_bucket_ownership_controls.return_value = {
        "OwnershipControls": {
            "Rules": [
                {
                    "ObjectOwnership": "BucketOwnerEnforced",
                }
            ]
        }
    }

    scanner = S3Scanner(fake_service)

    findings = scanner.scan()

    assert len(findings) == 2

    assert findings[0].rule_id == "CS-AWS-S3-001"
    assert findings[0].resource_id == "public-bucket"

    assert findings[1].rule_id == "CS-AWS-S3-001"
    assert findings[1].resource_id == "another-public-bucket"

    assert fake_service.list_buckets.call_count == 1
    assert fake_service.get_public_access_block.call_count == 3
