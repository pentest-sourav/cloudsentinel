from engine.findings.model import Severity
from engine.rules.aws.s3.kms_encryption import (
    build_s3_kms_encryption_finding,
    check_s3_kms_encryption,
)


def test_kms_encryption_passes_for_aws_kms():
    result = check_s3_kms_encryption(
        bucket_name="kms-bucket",
        encryption_configuration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                        "KMSMasterKeyID": "arn:aws:kms:ap-south-1:123456789012:key/example",
                    }
                }
            ]
        },
    )

    assert result.encrypted_with_kms is True
    assert build_s3_kms_encryption_finding(result) is None


def test_kms_encryption_fails_for_aes256():
    result = check_s3_kms_encryption(
        bucket_name="aes-bucket",
        encryption_configuration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256",
                    }
                }
            ]
        },
    )

    finding = build_s3_kms_encryption_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-S3-017"
    assert finding.severity == Severity.MEDIUM


def test_kms_encryption_fails_without_default_encryption():
    result = check_s3_kms_encryption(
        bucket_name="unencrypted-bucket",
        encryption_configuration={},
    )

    assert result.encrypted_with_kms is False
    assert build_s3_kms_encryption_finding(result) is not None
