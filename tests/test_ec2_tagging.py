from engine.findings.model import Severity
from engine.rules.aws.ec2.tagging import (
    build_ec2_tagging_finding,
    check_ec2_tagging,
)


def test_tagging_compliant_with_user_tag():
    result = check_ec2_tagging(
        "CS-AWS-EC2-038",
        "ec2_instance",
        "i-123",
        "Instance tagging",
        [
            {
                "Key": "Environment",
                "Value": "prod",
            }
        ],
    )

    assert result is None


def test_tagging_noncompliant_without_tags():
    result = check_ec2_tagging(
        "CS-AWS-EC2-038",
        "ec2_instance",
        "i-123",
        "Instance tagging",
        [],
    )

    assert result is not None
    assert result.rule_id == "CS-AWS-EC2-038"
    assert result.resource_id == "i-123"


def test_system_tags_do_not_count():
    result = check_ec2_tagging(
        "CS-AWS-EC2-038",
        "ec2_instance",
        "i-123",
        "Instance tagging",
        [
            {
                "Key": "aws:cloudformation:stack-id",
                "Value": "stack",
            }
        ],
    )

    assert result is not None


def test_mixed_system_and_user_tags_are_compliant():
    result = check_ec2_tagging(
        "CS-AWS-EC2-038",
        "ec2_instance",
        "i-123",
        "Instance tagging",
        [
            {
                "Key": "aws:cloudformation:stack-id",
                "Value": "stack",
            },
            {
                "Key": "Owner",
                "Value": "CloudSentinel",
            },
        ],
    )

    assert result is None


def test_dict_tags_are_supported():
    result = check_ec2_tagging(
        "CS-AWS-EC2-038",
        "ec2_instance",
        "i-123",
        "Instance tagging",
        {
            "Environment": "prod",
        },
    )

    assert result is None


def test_finding_is_low_severity():
    result = check_ec2_tagging(
        "CS-AWS-EC2-038",
        "ec2_instance",
        "i-123",
        "Instance tagging",
        [],
    )

    finding = build_ec2_tagging_finding(result)

    assert finding.severity == Severity.LOW
    assert finding.rule_id == "CS-AWS-EC2-038"
    assert finding.resource_id == "i-123"


def test_required_tag_keys_are_compliant_when_all_keys_are_present():
    result = check_ec2_tagging(
        "CS-AWS-EC2-038",
        "ec2_instance",
        "i-123",
        "Instance tagging",
        [
            {"Key": "Environment", "Value": "prod"},
            {"Key": "Owner", "Value": "CloudSentinel"},
        ],
        required_tag_keys=["Environment", "Owner"],
    )

    assert result is None


def test_required_tag_keys_report_missing_keys():
    result = check_ec2_tagging(
        "CS-AWS-EC2-038",
        "ec2_instance",
        "i-123",
        "Instance tagging",
        [
            {"Key": "Environment", "Value": "prod"},
        ],
        required_tag_keys=["Environment", "Owner"],
    )

    assert result is not None
    assert result.required_tag_keys == ["Environment", "Owner"]
    assert result.missing_tag_keys == ["Owner"]


def test_required_tag_keys_are_case_sensitive():
    result = check_ec2_tagging(
        "CS-AWS-EC2-038",
        "ec2_instance",
        "i-123",
        "Instance tagging",
        [
            {"Key": "environment", "Value": "prod"},
        ],
        required_tag_keys=["Environment"],
    )

    assert result is not None
    assert result.missing_tag_keys == ["Environment"]


def test_required_tag_keys_ignore_system_tags():
    result = check_ec2_tagging(
        "CS-AWS-EC2-038",
        "ec2_instance",
        "i-123",
        "Instance tagging",
        [
            {
                "Key": "aws:cloudformation:stack-id",
                "Value": "stack",
            },
        ],
        required_tag_keys=["Environment"],
    )

    assert result is not None
    assert result.missing_tag_keys == ["Environment"]


def test_empty_required_tag_keys_preserve_legacy_behavior():
    result = check_ec2_tagging(
        "CS-AWS-EC2-038",
        "ec2_instance",
        "i-123",
        "Instance tagging",
        [],
        required_tag_keys=[],
    )

    assert result is not None
    assert result.required_tag_keys == []
    assert result.missing_tag_keys == []


def test_parameterized_finding_contains_missing_keys():
    result = check_ec2_tagging(
        "CS-AWS-EC2-038",
        "ec2_instance",
        "i-123",
        "Instance tagging",
        [
            {"Key": "Environment", "Value": "prod"},
        ],
        required_tag_keys=["Environment", "Owner"],
    )

    finding = build_ec2_tagging_finding(result)

    assert finding.evidence["required_tag_keys"] == [
        "Environment",
        "Owner",
    ]
    assert finding.evidence["missing_tag_keys"] == ["Owner"]
