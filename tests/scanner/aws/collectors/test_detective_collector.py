from unittest.mock import Mock

from scanner.aws.collectors.detective import (
    DetectiveDataCollector,
)


def _service():
    service = Mock()

    service.list_graphs.return_value = [
        {
            "Arn": "arn:aws:detective:region:account:graph:123",
            "CreatedTime": "2026-01-01T00:00:00Z",
        }
    ]

    service.list_tags_for_resource.return_value = {
        "Environment": "prod",
        "aws:createdBy": "system",
    }

    return service


def test_collect_graphs():
    service = _service()

    result = DetectiveDataCollector(
        service
    ).collect_graphs()

    assert result == [
        {
            "resource_name": "123",
            "resource_arn": (
                "arn:aws:detective:region:account:graph:123"
            ),
            "resource_type": "AWS::Detective::Graph",
            "created_time": "2026-01-01T00:00:00Z",
            "tags": {
                "Environment": "prod",
            },
            "tag_data_available": True,
            "has_non_system_tags": True,
        }
    ]


def test_system_tags_are_ignored():
    service = _service()

    service.list_tags_for_resource.return_value = {
        "aws:createdBy": "system",
    }

    result = DetectiveDataCollector(
        service
    ).collect_graphs()

    assert result[0]["tags"] == {}
    assert result[0]["tag_data_available"] is True
    assert result[0]["has_non_system_tags"] is False


def test_collector_caches_graphs_and_tags():
    service = _service()

    collector = DetectiveDataCollector(service)

    collector.collect_graphs()
    collector.collect_graphs()

    service.list_graphs.assert_called_once()
    service.list_tags_for_resource.assert_called_once_with(
        "arn:aws:detective:region:account:graph:123"
    )
