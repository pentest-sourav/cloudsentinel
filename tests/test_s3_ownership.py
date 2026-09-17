from engine.findings.model import Severity

from engine.rules.aws.s3.ownership import (
    build_s3_ownership_finding,
    check_s3_ownership,
)


def test_s3_bucket_owner_enforced_has_no_finding():
    configuration = {
        "Rules": [
            {
                "ObjectOwnership": "BucketOwnerEnforced",
            }
        ]
    }

    result = check_s3_ownership(
        bucket_name="secure-bucket",
        ownership_configuration=configuration,
    )

    assert result.ownership_mode == "BucketOwnerEnforced"
    assert result.acl_disabled is True

    finding = build_s3_ownership_finding(result)

    assert finding is None


def test_s3_bucket_owner_not_enforced_generates_finding():
    configuration = {
        "Rules": [
            {
                "ObjectOwnership": "BucketOwnerPreferred",
            }
        ]
    }

    result = check_s3_ownership(
        bucket_name="test-bucket",
        ownership_configuration=configuration,
    )

    assert result.ownership_mode == "BucketOwnerPreferred"
    assert result.acl_disabled is False

    finding = build_s3_ownership_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-S3-008"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_id == "test-bucket"
