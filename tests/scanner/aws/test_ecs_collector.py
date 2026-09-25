from unittest.mock import Mock

from scanner.aws.collectors.ecs import ECSDataCollector


def test_collect_clusters_normalizes_settings_and_tags():
    service = Mock()

    service.list_clusters.return_value = [
        "arn:aws:ecs:ap-south-1:123456789012:cluster/test"
    ]

    service.describe_clusters.return_value = [
        {
            "clusterArn": (
                "arn:aws:ecs:ap-south-1:"
                "123456789012:cluster/test"
            ),
            "clusterName": "test",
            "status": "ACTIVE",
            "settings": [
                {
                    "name": "containerInsights",
                    "value": "enabled",
                }
            ],
            "tags": [
                {
                    "key": "Environment",
                    "value": "prod",
                }
            ],
        }
    ]

    collector = ECSDataCollector(service)

    result = collector.collect_clusters()

    assert result[0]["resource_id"] == "test"
    assert result[0]["settings"][0]["value"] == "enabled"
    assert result[0]["tags"][0]["key"] == "Environment"


def test_collect_services_normalizes_network_configuration():
    service = Mock()

    service.list_clusters.return_value = [
        "arn:cluster:test"
    ]

    service.describe_clusters.return_value = [
        {
            "clusterArn": "arn:cluster:test",
            "clusterName": "test",
            "settings": [],
            "tags": [],
        }
    ]

    service.list_services.return_value = [
        "arn:service:test"
    ]

    service.describe_services.return_value = [
        {
            "serviceArn": "arn:service:test",
            "serviceName": "test-service",
            "clusterArn": "arn:cluster:test",
            "launchType": "FARGATE",
            "platformVersion": "1.4.0",
            "networkConfiguration": {
                "awsvpcConfiguration": {
                    "assignPublicIp": "DISABLED"
                }
            },
            "tags": [],
        }
    ]

    collector = ECSDataCollector(service)

    result = collector.collect_services()

    assert result[0]["launch_type"] == "FARGATE"
    assert (
        result[0]["network_configuration"]
        ["awsvpcConfiguration"]["assignPublicIp"]
        == "DISABLED"
    )


def test_collector_caches_clusters():
    service = Mock()

    service.list_clusters.return_value = []
    service.describe_clusters.return_value = []

    collector = ECSDataCollector(service)

    assert collector.collect_clusters() == []
    assert collector.collect_clusters() == []

    service.list_clusters.assert_called_once()
    service.describe_clusters.assert_called_once()
