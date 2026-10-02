from engine.rules.aws.ecs.cluster_tagging import (
    check_ecs_cluster_tagging,
)
from engine.rules.aws.ecs.service_tagging import (
    check_ecs_service_tagging,
)
from engine.rules.aws.ecs.task_definition_tagging import (
    check_ecs_task_definition_tagging,
)


def test_ecs_service_tagging_without_parameter_preserves_existing_behavior():
    result = check_ecs_service_tagging(
        resource_arn="arn:aws:ecs:region:123456789012:service/example",
        resource_id="example-service",
        tags=[{"key": "Environment", "value": "prod"}],
        resource={},
    )

    assert result.tagged is True
    assert result.required_tag_keys == ()


def test_ecs_service_tagging_required_key_present():
    result = check_ecs_service_tagging(
        resource_arn="arn:aws:ecs:region:123456789012:service/example",
        resource_id="example-service",
        tags=[
            {"key": "Environment", "value": "prod"},
            {"key": "Owner", "value": "security"},
        ],
        resource={},
        required_tag_keys=["Owner"],
    )

    assert result.tagged is True
    assert result.required_tag_keys == ("Owner",)


def test_ecs_service_tagging_required_key_missing():
    result = check_ecs_service_tagging(
        resource_arn="arn:aws:ecs:region:123456789012:service/example",
        resource_id="example-service",
        tags=[{"key": "Environment", "value": "prod"}],
        resource={},
        required_tag_keys=["Owner"],
    )

    assert result.tagged is False
    assert result.required_tag_keys == ("Owner",)


def test_ecs_service_tagging_requires_all_keys():
    result = check_ecs_service_tagging(
        resource_arn="arn:aws:ecs:region:123456789012:service/example",
        resource_id="example-service",
        tags=[
            {"key": "Environment", "value": "prod"},
            {"key": "Owner", "value": "security"},
        ],
        resource={},
        required_tag_keys=["Environment", "Owner", "Application"],
    )

    assert result.tagged is False
    assert result.required_tag_keys == (
        "Environment",
        "Owner",
        "Application",
    )


def test_ecs_service_tagging_ignores_system_tags():
    result = check_ecs_service_tagging(
        resource_arn="arn:aws:ecs:region:123456789012:service/example",
        resource_id="example-service",
        tags=[
            {"key": "aws:createdBy", "value": "system"},
        ],
        resource={},
        required_tag_keys=["aws:createdBy"],
    )

    assert result.tagged is False
    assert result.required_tag_keys == ()


def test_ecs_cluster_tagging_required_key_present():
    result = check_ecs_cluster_tagging(
        resource_arn="arn:aws:ecs:region:123456789012:cluster/example",
        resource_id="example-cluster",
        tags=[{"key": "Environment", "value": "prod"}],
        resource={},
        required_tag_keys=["Environment"],
    )

    assert result.tagged is True
    assert result.required_tag_keys == ("Environment",)


def test_ecs_cluster_tagging_required_key_missing():
    result = check_ecs_cluster_tagging(
        resource_arn="arn:aws:ecs:region:123456789012:cluster/example",
        resource_id="example-cluster",
        tags=[{"key": "Environment", "value": "prod"}],
        resource={},
        required_tag_keys=["Owner"],
    )

    assert result.tagged is False
    assert result.required_tag_keys == ("Owner",)


def test_ecs_cluster_tagging_multiple_required_keys():
    result = check_ecs_cluster_tagging(
        resource_arn="arn:aws:ecs:region:123456789012:cluster/example",
        resource_id="example-cluster",
        tags=[
            {"key": "Environment", "value": "prod"},
            {"key": "Owner", "value": "security"},
        ],
        resource={},
        required_tag_keys=["Environment", "Owner"],
    )

    assert result.tagged is True
    assert result.required_tag_keys == (
        "Environment",
        "Owner",
    )


def test_ecs_task_definition_tagging_required_key_present():
    result = check_ecs_task_definition_tagging(
        resource_arn="arn:aws:ecs:region:123456789012:task-definition/example:1",
        resource_id="example:1",
        tags=[{"key": "Application", "value": "web"}],
        resource={},
        required_tag_keys=["Application"],
    )

    assert result.tagged is True
    assert result.required_tag_keys == ("Application",)


def test_ecs_task_definition_tagging_required_key_missing():
    result = check_ecs_task_definition_tagging(
        resource_arn="arn:aws:ecs:region:123456789012:task-definition/example:1",
        resource_id="example:1",
        tags=[{"key": "Application", "value": "web"}],
        resource={},
        required_tag_keys=["Owner"],
    )

    assert result.tagged is False
    assert result.required_tag_keys == ("Owner",)


def test_ecs_task_definition_tagging_empty_tags_with_parameter():
    result = check_ecs_task_definition_tagging(
        resource_arn="arn:aws:ecs:region:123456789012:task-definition/example:1",
        resource_id="example:1",
        tags=[],
        resource={},
        required_tag_keys=["Application"],
    )

    assert result.tagged is False
    assert result.required_tag_keys == ("Application",)


def test_ecs_task_definition_tagging_empty_parameter_preserves_behavior():
    result = check_ecs_task_definition_tagging(
        resource_arn="arn:aws:ecs:region:123456789012:task-definition/example:1",
        resource_id="example:1",
        tags=[],
        resource={},
        required_tag_keys=[],
    )

    assert result.tagged is False
    assert result.required_tag_keys == ()
