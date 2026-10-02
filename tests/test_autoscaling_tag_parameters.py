from engine.rules.aws.autoscaling.controls import (
    check_autoscaling_tags,
)


def test_autoscaling_tags_without_parameter_preserves_existing_behavior():
    result = check_autoscaling_tags(
        group_name="asg-prod",
        group_arn="arn:aws:autoscaling:region:123456789012:autoScalingGroup:example",
        has_non_system_tags=True,
        tags={"Environment": "prod"},
    )

    assert result is None


def test_autoscaling_tags_required_key_present():
    result = check_autoscaling_tags(
        group_name="asg-prod",
        group_arn=None,
        has_non_system_tags=True,
        tags={
            "Environment": "prod",
            "Owner": "security",
        },
        required_tag_keys=["Owner"],
    )

    assert result is None


def test_autoscaling_tags_required_key_missing():
    result = check_autoscaling_tags(
        group_name="asg-prod",
        group_arn=None,
        has_non_system_tags=True,
        tags={
            "Environment": "prod",
        },
        required_tag_keys=["Owner"],
    )

    assert result is not None
    assert result.reason == "missing_required_tag_keys"
    assert result.evidence["required_tag_keys"] == ["Owner"]
    assert result.evidence["missing_tag_keys"] == ["Owner"]


def test_autoscaling_tags_requires_all_configured_keys():
    result = check_autoscaling_tags(
        group_name="asg-prod",
        group_arn=None,
        has_non_system_tags=True,
        tags={
            "Environment": "prod",
            "Owner": "security",
        },
        required_tag_keys=[
            "Environment",
            "Owner",
            "Application",
        ],
    )

    assert result is not None
    assert result.reason == "missing_required_tag_keys"
    assert result.evidence["missing_tag_keys"] == ["Application"]


def test_autoscaling_tags_empty_required_keys_uses_baseline_behavior():
    result = check_autoscaling_tags(
        group_name="asg-prod",
        group_arn=None,
        has_non_system_tags=False,
        tags={},
        required_tag_keys=[],
    )

    assert result is not None
    assert result.reason == "missing_non_system_tags"


def test_autoscaling_tags_ignores_system_required_keys():
    result = check_autoscaling_tags(
        group_name="asg-prod",
        group_arn=None,
        has_non_system_tags=False,
        tags={
            "aws:createdBy": "system",
        },
        required_tag_keys=["aws:createdBy"],
    )

    assert result is not None
    assert result.reason == "missing_non_system_tags"
    assert result.evidence["required_tag_keys"] == []


def test_autoscaling_tags_required_keys_are_case_sensitive():
    result = check_autoscaling_tags(
        group_name="asg-prod",
        group_arn=None,
        has_non_system_tags=True,
        tags={
            "Environment": "prod",
        },
        required_tag_keys=["environment"],
    )

    assert result is not None
    assert result.evidence["missing_tag_keys"] == ["environment"]
