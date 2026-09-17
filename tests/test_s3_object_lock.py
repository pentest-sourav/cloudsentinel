from engine.findings.model import Severity

from engine.rules.aws.s3.object_lock import (
    build_s3_object_lock_finding,
    check_s3_object_lock,
)


def test_s3_object_lock_disabled_generates_finding():
    result = check_s3_object_lock(
        bucket_name="test-bucket",
        object_lock_configuration={},
    )

    assert result.object_lock_enabled is False

    finding = build_s3_object_lock_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-S3-007"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_id == "test-bucket"
    assert finding.evidence["object_lock_enabled"] is False


def test_s3_object_lock_enabled_has_no_finding():
    configuration = {
        "ObjectLockEnabled": "Enabled",
        "Rule": {
            "DefaultRetention": {
                "Mode": "GOVERNANCE",
                "Days": 30,
            }
        },
    }

    result = check_s3_object_lock(
        bucket_name="secure-bucket",
        object_lock_configuration=configuration,
    )

    assert result.object_lock_enabled is True

    finding = build_s3_object_lock_finding(result)

    assert finding is None
