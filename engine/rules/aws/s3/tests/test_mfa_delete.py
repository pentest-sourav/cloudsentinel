from engine.findings.model import Severity
from engine.rules.aws.s3.mfa_delete import (
    build_s3_mfa_delete_finding,
    check_s3_mfa_delete,
)


def test_versioned_bucket_without_mfa_delete_fails():
    result = check_s3_mfa_delete(
        bucket_name="bucket-a",
        versioning_status={
            "Status": "Enabled",
            "MFADelete": "Disabled",
        },
    )

    finding = build_s3_mfa_delete_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-S3-020"
    assert finding.severity == Severity.LOW


def test_unversioned_bucket_does_not_require_mfa_delete():
    result = check_s3_mfa_delete(
        bucket_name="bucket-a",
        versioning_status={
            "Status": None,
            "MFADelete": None,
        },
    )

    assert build_s3_mfa_delete_finding(result) is None


def test_versioned_bucket_with_mfa_delete_passes():
    result = check_s3_mfa_delete(
        bucket_name="bucket-a",
        versioning_status={
            "Status": "Enabled",
            "MFADelete": "Enabled",
        },
    )

    assert build_s3_mfa_delete_finding(result) is None
