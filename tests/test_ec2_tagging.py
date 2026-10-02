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
