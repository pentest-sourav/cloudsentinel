from engine.rules.aws.batch.controls import (
    check_batch_job_queue_tags,
    check_batch_scheduling_policy_tags,
    check_batch_compute_environment_tags,
    check_batch_compute_resource_tags,
)


def _common():
    return {
        "resource_name": "resource-1",
        "resource_arn": "arn:aws:batch:region:123:resource/resource-1",
        "resource_type": "batch_resource",
        "tag_data_available": True,
        "has_non_system_tags": True,
        "tags": {"Environment": "prod"},
        "required_tag_keys": ["Environment", "Owner"],
    }


def test_batch_job_queue_required_tags():
    result = check_batch_job_queue_tags(**_common())
    assert result is not None
    assert result.evidence["missing_tag_keys"] == ["Owner"]


def test_batch_scheduling_policy_required_tags():
    result = check_batch_scheduling_policy_tags(**_common())
    assert result is not None
    assert result.evidence["missing_tag_keys"] == ["Owner"]


def test_batch_compute_environment_required_tags():
    result = check_batch_compute_environment_tags(**_common())
    assert result is not None
    assert result.evidence["missing_tag_keys"] == ["Owner"]


def test_batch_compute_resource_required_tags():
    result = check_batch_compute_resource_tags(
        **_common(),
        compute_resource_type="EC2",
    )
    assert result is not None
    assert result.evidence["missing_tag_keys"] == ["Owner"]


def test_batch_required_tags_all_present():
    data = _common()
    data["tags"] = {"Environment": "prod", "Owner": "security"}

    assert check_batch_job_queue_tags(**data) is None
    assert check_batch_scheduling_policy_tags(**data) is None
    assert check_batch_compute_environment_tags(**data) is None
    assert check_batch_compute_resource_tags(
        **data,
        compute_resource_type="EC2",
    ) is None
