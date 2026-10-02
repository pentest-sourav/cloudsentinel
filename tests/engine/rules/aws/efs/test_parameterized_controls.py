from engine.rules.aws.efs.protection import (
    check_efs_access_point_tags,
)


def test_efs_tags_default_accepts_any_non_system_tag():
    assert check_efs_access_point_tags(
        resource_id="fsap-123",
        tags=[{"Key": "Environment", "Value": "prod"}],
        has_non_system_tags=True,
    ) is None


def test_efs_tags_default_rejects_untagged_access_point():
    assert check_efs_access_point_tags(
        resource_id="fsap-123",
        tags=[],
        has_non_system_tags=False,
    ) is not None


def test_efs_tags_parameter_accepts_all_required_keys():
    assert check_efs_access_point_tags(
        resource_id="fsap-123",
        tags=[
            {"Key": "Environment", "Value": "prod"},
            {"Key": "Owner", "Value": "security"},
        ],
        has_non_system_tags=True,
        required_tag_keys=["Environment", "Owner"],
    ) is None


def test_efs_tags_parameter_rejects_missing_required_key():
    result = check_efs_access_point_tags(
        resource_id="fsap-123",
        tags=[
            {"Key": "Environment", "Value": "prod"},
        ],
        has_non_system_tags=True,
        required_tag_keys=["Environment", "Owner"],
    )

    assert result is not None
    assert result.details["missing_tag_keys"] == ["Owner"]


def test_efs_tags_parameter_is_case_sensitive():
    result = check_efs_access_point_tags(
        resource_id="fsap-123",
        tags=[
            {"Key": "environment", "Value": "prod"},
        ],
        has_non_system_tags=True,
        required_tag_keys=["Environment"],
    )

    assert result is not None
    assert result.details["missing_tag_keys"] == ["Environment"]


def test_efs_tags_empty_parameter_preserves_default_behavior():
    assert check_efs_access_point_tags(
        resource_id="fsap-123",
        tags=[{"Key": "Team", "Value": "security"}],
        has_non_system_tags=True,
        required_tag_keys=[],
    ) is None
