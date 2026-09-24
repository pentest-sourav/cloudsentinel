from scanner.aws.scanners.s3 import S3Scanner


ALL_USERS_URI = (
    "http://acs.amazonaws.com/groups/global/AllUsers"
)


class FakeS3Service:
    def list_buckets(self):
        return [
            {"name": "secure-bucket"},
            {"name": "insecure-bucket"},
        ]

    def get_public_access_block(self, bucket_name):
        if bucket_name == "secure-bucket":
            return {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }

        return {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        }

    def get_bucket_encryption(self, bucket_name):
        if bucket_name == "secure-bucket":
            return {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        }
                    }
                ]
            }

        return {}

    def get_bucket_policy_status(self, bucket_name):
        if bucket_name == "secure-bucket":
            return {
                "IsPublic": False,
            }

        return {
            "IsPublic": True,
        }

    def get_bucket_policy(self, bucket_name):
        if bucket_name == "secure-bucket":
            return {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "DenyInsecureTransport",
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:*",
                        "Resource": [
                            "arn:aws:s3:::secure-bucket",
                            "arn:aws:s3:::secure-bucket/*",
                        ],
                        "Condition": {
                            "Bool": {
                                "aws:SecureTransport": "false",
                            }
                        },
                    }
                ],
            }

        return {}

    def get_bucket_acl(self, bucket_name):
        if bucket_name == "secure-bucket":
            return {
                "Owner": {
                    "ID": "owner-id",
                },
                "Grants": [
                    {
                        "Grantee": {
                            "ID": "owner-id",
                            "Type": "CanonicalUser",
                        },
                        "Permission": "FULL_CONTROL",
                    }
                ],
            }

        return {
            "Owner": {
                "ID": "owner-id",
            },
            "Grants": [
                {
                    "Grantee": {
                        "URI": ALL_USERS_URI,
                        "Type": "Group",
                    },
                    "Permission": "READ",
                }
            ],
        }

    def get_bucket_versioning(self, bucket_name):
        if bucket_name == "secure-bucket":
            return {
                "Status": "Enabled",
                "MFADelete": "Disabled",
            }

        return {
            "Status": None,
            "MFADelete": None,
        }

    def get_bucket_logging(self, bucket_name):
        if bucket_name == "secure-bucket":
            return {
                "TargetBucket": "secure-logging-bucket",
                "TargetPrefix": "s3-access/",
            }

        return {}

    def get_object_lock_configuration(self, bucket_name):
        if bucket_name == "secure-bucket":
            return {
                "ObjectLockEnabled": "Enabled",
                "Rule": {
                    "DefaultRetention": {
                        "Mode": "GOVERNANCE",
                        "Days": 30,
                    }
                },
            }

        return {}

    def get_bucket_ownership_controls(self, bucket_name):
        if bucket_name == "secure-bucket":
            return {
                "Rules": [
                    {
                        "ObjectOwnership": "BucketOwnerEnforced",
                    }
                ]
            }

        return {}


def test_s3_scanner_detects_all_insecure_bucket_checks():
    scanner = S3Scanner(FakeS3Service())

    findings = scanner.scan()

    assert len(findings) == 9

    rule_ids = {
        finding.rule_id
        for finding in findings
    }

    assert "CS-AWS-S3-001" in rule_ids
    assert "CS-AWS-S3-002" in rule_ids
    assert "CS-AWS-S3-003" in rule_ids
    assert "CS-AWS-S3-004" in rule_ids
    assert "CS-AWS-S3-005" in rule_ids
    assert "CS-AWS-S3-006" in rule_ids
    assert "CS-AWS-S3-007" in rule_ids
    assert "CS-AWS-S3-008" in rule_ids
    assert "CS-AWS-S3-009" in rule_ids

    for finding in findings:
        assert finding.resource_id == "insecure-bucket"


def test_s3_scanner_does_not_generate_findings_for_secure_bucket():
    class SecureOnlyFakeS3Service(FakeS3Service):
        def list_buckets(self):
            return [
                {"name": "secure-bucket"},
            ]

    scanner = S3Scanner(SecureOnlyFakeS3Service())

    findings = scanner.scan()

    assert findings == []
