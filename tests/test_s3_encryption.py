from engine.findings.model import Severity
from engine.rules.aws.s3.encryption import (
    build_s3_encryption_finding,
    check_s3_encryption,
)


def test_s3_encryption_disabled_generates_medium_finding():
    result = check_s3_encryption(
        bucket_name="unencrypted-bucket",
        encryption_configuration={},
    )

    finding = build_s3_encryption_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-S3-002"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_id == "unencrypted-bucket"


def test_s3_encryption_enabled_has_no_finding():
    configuration = {
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256",
                }
            }
        ]
    }

    result = check_s3_encryption(
        bucket_name="secure-bucket",
        encryption_configuration=configuration,
    )

    finding = build_s3_encryption_finding(result)

    assert finding is None
    assert result.encryption_enabled is True
    assert result.algorithm == "AES256"
