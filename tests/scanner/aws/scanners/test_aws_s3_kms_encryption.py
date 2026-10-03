from unittest.mock import Mock

from engine.findings.model import Severity
from scanner.aws.scanners.s3 import S3Scanner


def test_s3_scanner_detects_kms_encryption_gap_only():
    fake_service = Mock()

    fake_service.list_buckets.return_value = [
        {"name": "kms-gap-bucket"},
    ]
    fake_service.get_public_access_block.return_value = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }
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
        "IsPublic": False,
    }
    fake_service.get_bucket_policy.return_value = {
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Condition": {
                    "Bool": {
                        "aws:SecureTransport": "false",
                    }
                },
            }
        ]
    }
    fake_service.get_bucket_acl.return_value = {
        "Grants": [],
    }
    fake_service.get_bucket_versioning.return_value = {
        "Status": "Enabled",
        "MFADelete": "Enabled",
    }
    fake_service.get_bucket_mfa_delete.return_value = {
        "Status": "Enabled",
        "MFADelete": "Enabled",
    }
    fake_service.get_bucket_logging.return_value = {
        "TargetBucket": "logs",
    }
    fake_service.get_object_lock_configuration.return_value = {
        "ObjectLockEnabled": "Enabled",
    }
    fake_service.get_bucket_ownership_controls.return_value = {
        "Rules": [
            {
                "ObjectOwnership": "BucketOwnerEnforced",
            }
        ]
    }
    fake_service.get_bucket_lifecycle_configuration.return_value = {
        "Rules": [
            {
                "ID": "retention",
                "Status": "Enabled",
            }
        ]
    }

    findings = S3Scanner(fake_service).scan()

    assert len(findings) == 1
    assert findings[0].rule_id == "CS-AWS-S3-017"
    assert findings[0].severity == Severity.MEDIUM
