from engine.findings.model import Severity

from engine.rules.aws.dynamodb.autoscaling import (
    build_dynamodb_autoscaling_finding,
    check_dynamodb_autoscaling,
)
from engine.rules.aws.dynamodb.backup_plan import (
    build_dynamodb_backup_plan_finding,
    check_dynamodb_backup_plan,
)
from engine.rules.aws.dynamodb.dax_encryption import (
    build_dax_encryption_finding,
    check_dax_encryption,
)
from engine.rules.aws.dynamodb.dax_tls import (
    build_dax_tls_finding,
    check_dax_tls,
)
from engine.rules.aws.dynamodb.deletion_protection import (
    build_dynamodb_deletion_protection_finding,
    check_dynamodb_deletion_protection,
)
from engine.rules.aws.dynamodb.pitr import (
    build_dynamodb_pitr_finding,
    check_dynamodb_pitr,
)
from engine.rules.aws.dynamodb.tagging import (
    build_dynamodb_tagging_finding,
    check_dynamodb_tagging,
)


TABLE_ARN = (
    "arn:aws:dynamodb:ap-south-1:"
    "123456789012:table/cloudsentinel"
)

DAX_ARN = (
    "arn:aws:dax:ap-south-1:"
    "123456789012:cache/cloudsentinel-dax"
)


# ---------------------------------------------------------------------------
# DynamoDB.1 - Auto Scaling
# ---------------------------------------------------------------------------


def test_dynamodb_autoscaling_passes_for_on_demand_table():
    result = check_dynamodb_autoscaling(
        TABLE_ARN,
        "cloudsentinel",
        "PAY_PER_REQUEST",
        True,
        {},
        {},
    )

    assert result.autoscaling_enabled is True
    assert build_dynamodb_autoscaling_finding(result) is None


def test_dynamodb_autoscaling_passes_for_provisioned_table():
    result = check_dynamodb_autoscaling(
        TABLE_ARN,
        "cloudsentinel",
        "PROVISIONED",
        True,
        {
            "dynamodb:table:ReadCapacityUnits": [
                {"ResourceId": "table/cloudsentinel"}
            ],
            "dynamodb:table:WriteCapacityUnits": [
                {"ResourceId": "table/cloudsentinel"}
            ],
        },
        {
            "dynamodb:table:ReadCapacityUnits": [
                {"PolicyName": "read-target-tracking"}
            ],
            "dynamodb:table:WriteCapacityUnits": [
                {"PolicyName": "write-target-tracking"}
            ],
        },
    )

    assert result.autoscaling_enabled is True
    assert build_dynamodb_autoscaling_finding(result) is None


def test_dynamodb_autoscaling_fails_when_disabled():
    result = check_dynamodb_autoscaling(
        TABLE_ARN,
        "cloudsentinel",
        "PROVISIONED",
        False,
        {},
        {},
    )

    finding = build_dynamodb_autoscaling_finding(result)

    assert result.autoscaling_enabled is False
    assert finding is not None
    assert finding.rule_id == "CS-AWS-DYNAMODB-001"
    assert finding.severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# DynamoDB.2 - Point-in-time recovery
# ---------------------------------------------------------------------------


def test_dynamodb_pitr_passes_when_enabled():
    result = check_dynamodb_pitr(
        TABLE_ARN,
        "cloudsentinel",
        {
            "PointInTimeRecoveryDescription": {
                "PointInTimeRecoveryStatus": "ENABLED",
            }
        },
    )

    assert result.point_in_time_recovery_enabled is True
    assert build_dynamodb_pitr_finding(result) is None


def test_dynamodb_pitr_fails_when_disabled():
    result = check_dynamodb_pitr(
        TABLE_ARN,
        "cloudsentinel",
        {
            "PointInTimeRecoveryDescription": {
                "PointInTimeRecoveryStatus": "DISABLED",
            }
        },
    )

    finding = build_dynamodb_pitr_finding(result)

    assert result.point_in_time_recovery_enabled is False
    assert finding is not None
    assert finding.rule_id == "CS-AWS-DYNAMODB-002"
    assert finding.severity == Severity.MEDIUM


def test_dynamodb_pitr_fails_when_description_is_missing():
    result = check_dynamodb_pitr(
        TABLE_ARN,
        "cloudsentinel",
        {},
    )

    finding = build_dynamodb_pitr_finding(result)

    assert result.point_in_time_recovery_enabled is False
    assert finding is not None


# ---------------------------------------------------------------------------
# DynamoDB.3 - DAX encryption at rest
# ---------------------------------------------------------------------------


def test_dax_encryption_passes_when_enabled():
    result = check_dax_encryption(
        DAX_ARN,
        "cloudsentinel-dax",
        {
            "Status": "ENABLED",
        },
    )

    assert result.encryption_at_rest_enabled is True
    assert build_dax_encryption_finding(result) is None


def test_dax_encryption_fails_when_disabled():
    result = check_dax_encryption(
        DAX_ARN,
        "cloudsentinel-dax",
        {
            "Status": "DISABLED",
        },
    )

    finding = build_dax_encryption_finding(result)

    assert result.encryption_at_rest_enabled is False
    assert finding is not None
    assert finding.rule_id == "CS-AWS-DYNAMODB-003"
    assert finding.severity == Severity.MEDIUM


def test_dax_encryption_fails_when_description_is_missing():
    result = check_dax_encryption(
        DAX_ARN,
        "cloudsentinel-dax",
        {},
    )

    finding = build_dax_encryption_finding(result)

    assert result.encryption_at_rest_enabled is False
    assert finding is not None


# ---------------------------------------------------------------------------
# DynamoDB.4 - AWS Backup plan
# ---------------------------------------------------------------------------


def test_dynamodb_backup_plan_passes_when_table_is_protected():
    result = check_dynamodb_backup_plan(
        TABLE_ARN,
        "cloudsentinel",
        "ACTIVE",
        [
            {
                "ResourceArn": TABLE_ARN,
                "ResourceType": "DynamoDB",
            }
        ],
    )

    assert result.protected_by_backup_plan is True
    assert result.protected_resource is not None
    assert build_dynamodb_backup_plan_finding(result) is None


def test_dynamodb_backup_plan_fails_when_table_is_not_protected():
    result = check_dynamodb_backup_plan(
        TABLE_ARN,
        "cloudsentinel",
        "ACTIVE",
        [],
    )

    finding = build_dynamodb_backup_plan_finding(result)

    assert result.protected_by_backup_plan is False
    assert result.protected_resource is None
    assert finding is not None
    assert finding.rule_id == "CS-AWS-DYNAMODB-004"
    assert finding.severity == Severity.MEDIUM


def test_dynamodb_backup_plan_fails_for_inactive_table():
    result = check_dynamodb_backup_plan(
        TABLE_ARN,
        "cloudsentinel",
        "CREATING",
        [
            {
                "ResourceArn": TABLE_ARN,
                "ResourceType": "DynamoDB",
            }
        ],
    )

    finding = build_dynamodb_backup_plan_finding(result)

    assert result.protected_by_backup_plan is False
    assert result.protected_resource is not None
    assert finding is not None


# ---------------------------------------------------------------------------
# DynamoDB.5 - Tagging
# ---------------------------------------------------------------------------


def test_dynamodb_tagging_passes_with_non_system_tag():
    result = check_dynamodb_tagging(
        TABLE_ARN,
        [
            {
                "Key": "Environment",
                "Value": "prod",
            }
        ],
    )

    assert result.tagged is True
    assert build_dynamodb_tagging_finding(result) is None


def test_dynamodb_tagging_ignores_system_tags():
    result = check_dynamodb_tagging(
        TABLE_ARN,
        [
            {
                "Key": "aws:cloudformation:stack-id",
                "Value": "stack",
            }
        ],
    )

    finding = build_dynamodb_tagging_finding(result)

    assert result.tagged is False
    assert finding is not None
    assert finding.rule_id == "CS-AWS-DYNAMODB-005"
    assert finding.severity == Severity.LOW


def test_dynamodb_tagging_fails_without_tags():
    result = check_dynamodb_tagging(
        TABLE_ARN,
        [],
    )

    finding = build_dynamodb_tagging_finding(result)

    assert result.tagged is False
    assert finding is not None
    assert finding.severity == Severity.LOW


def test_dynamodb_tagging_ignores_invalid_tags():
    result = check_dynamodb_tagging(
        TABLE_ARN,
        [
            {},
            {
                "Key": "",
                "Value": "invalid",
            },
            {
                "Key": "aws:createdBy",
                "Value": "system",
            },
        ],
    )

    finding = build_dynamodb_tagging_finding(result)

    assert result.tagged is False
    assert result.tags == []
    assert finding is not None


# ---------------------------------------------------------------------------
# DynamoDB.6 - Deletion protection
# ---------------------------------------------------------------------------


def test_dynamodb_deletion_protection_passes_when_enabled():
    result = check_dynamodb_deletion_protection(
        TABLE_ARN,
        "cloudsentinel",
        True,
    )

    assert result.deletion_protection_enabled is True
    assert build_dynamodb_deletion_protection_finding(result) is None


def test_dynamodb_deletion_protection_fails_when_disabled():
    result = check_dynamodb_deletion_protection(
        TABLE_ARN,
        "cloudsentinel",
        False,
    )

    finding = build_dynamodb_deletion_protection_finding(result)

    assert result.deletion_protection_enabled is False
    assert finding is not None
    assert finding.rule_id == "CS-AWS-DYNAMODB-006"
    assert finding.severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# DynamoDB.7 - DAX TLS
# ---------------------------------------------------------------------------


def test_dax_tls_passes_when_tls_is_enabled():
    result = check_dax_tls(
        DAX_ARN,
        "cloudsentinel-dax",
        "TLS",
    )

    assert result.endpoint_encryption_type == "TLS"
    assert result.tls_enabled is True
    assert build_dax_tls_finding(result) is None


def test_dax_tls_normalizes_lowercase_tls():
    result = check_dax_tls(
        DAX_ARN,
        "cloudsentinel-dax",
        "tls",
    )

    assert result.endpoint_encryption_type == "TLS"
    assert result.tls_enabled is True
    assert build_dax_tls_finding(result) is None


def test_dax_tls_fails_when_tls_is_not_enabled():
    result = check_dax_tls(
        DAX_ARN,
        "cloudsentinel-dax",
        "NONE",
    )

    finding = build_dax_tls_finding(result)

    assert result.endpoint_encryption_type == "NONE"
    assert result.tls_enabled is False
    assert finding is not None
    assert finding.rule_id == "CS-AWS-DYNAMODB-007"
    assert finding.severity == Severity.MEDIUM


def test_dax_tls_fails_when_encryption_type_is_missing():
    result = check_dax_tls(
        DAX_ARN,
        "cloudsentinel-dax",
        None,
    )

    finding = build_dax_tls_finding(result)

    assert result.endpoint_encryption_type is None
    assert result.tls_enabled is False
    assert finding is not None
