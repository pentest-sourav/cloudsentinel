from unittest.mock import Mock

from scanner.aws.collectors.batch import (
    BatchDataCollector,
)


def test_collect_job_queues_normalizes_tags():
    service = Mock()

    service.describe_job_queues.return_value = [
        {
            "jobQueueArn": "arn:queue",
            "jobQueueName": "queue",
        }
    ]

    service.list_tags_for_resource.return_value = {
        "Environment": "prod",
        "aws:createdBy": "system",
    }

    collector = BatchDataCollector(service)

    result = collector.collect_job_queues()

    assert result[0]["tags"] == {
        "Environment": "prod",
    }

    assert (
        result[0]["has_non_system_tags"]
        is True
    )


def test_system_only_tags_are_not_counted():
    service = Mock()

    service.describe_job_queues.return_value = [
        {
            "jobQueueArn": "arn:queue",
            "jobQueueName": "queue",
        }
    ]

    service.list_tags_for_resource.return_value = {
        "aws:createdBy": "system",
    }

    result = BatchDataCollector(
        service
    ).collect_job_queues()

    assert result[0]["tags"] == {}

    assert (
        result[0]["has_non_system_tags"]
        is False
    )


def test_collect_scheduling_policies():
    service = Mock()

    service.list_scheduling_policies.return_value = [
        {
            "arn": "arn:policy",
        }
    ]

    service.describe_scheduling_policies.return_value = [
        {
            "arn": "arn:policy",
            "name": "policy",
        }
    ]

    service.list_tags_for_resource.return_value = {
        "Owner": "security",
    }

    result = BatchDataCollector(
        service
    ).collect_scheduling_policies()

    assert result[0]["resource_name"] == "policy"

    assert (
        result[0]["has_non_system_tags"]
        is True
    )


def test_collect_compute_environments():
    service = Mock()

    service.describe_compute_environments.return_value = [
        {
            "computeEnvironmentArn": "arn:env",
            "computeEnvironmentName": "env",
            "type": "MANAGED",
            "computeResources": {
                "type": "EC2",
            },
        }
    ]

    service.list_tags_for_resource.return_value = {
        "Environment": "prod",
    }

    result = BatchDataCollector(
        service
    ).collect_compute_environments()

    assert result[0]["resource_name"] == "env"

    assert (
        result[0]["has_non_system_tags"]
        is True
    )


def test_batch4_collects_managed_non_fargate_compute_resources():
    service = Mock()

    service.describe_compute_environments.return_value = [
        {
            "computeEnvironmentArn": "arn:ec2-env",
            "computeEnvironmentName": "ec2-env",
            "type": "MANAGED",
            "computeResources": {
                "type": "EC2",
                "tags": {
                    "Environment": "prod",
                    "aws:system": "ignored",
                },
            },
        },
        {
            "computeEnvironmentArn": "arn:fargate-env",
            "computeEnvironmentName": "fargate-env",
            "type": "MANAGED",
            "computeResources": {
                "type": "FARGATE",
                "tags": {},
            },
        },
    ]

    result = BatchDataCollector(
        service
    ).collect_managed_compute_resource_tags()

    assert len(result) == 1

    assert (
        result[0]["resource_name"]
        == "ec2-env"
    )

    assert result[0]["tags"] == {
        "Environment": "prod",
    }


def test_collector_caches_compute_environments():
    service = Mock()

    service.describe_compute_environments.return_value = []

    collector = BatchDataCollector(service)

    collector.collect_compute_environments()
    collector.collect_managed_compute_resource_tags()

    service.describe_compute_environments.assert_called_once()
