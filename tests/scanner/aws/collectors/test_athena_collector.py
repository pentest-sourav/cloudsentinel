from unittest.mock import Mock

from scanner.aws.collectors.athena import (
    AthenaDataCollector,
)


def make_service():
    service = Mock()

    service.build_resource_arn.side_effect = (
        lambda kind, name:
        f"arn:aws:athena:ap-south-1:123:{kind}/{name}"
    )

    return service


def test_collect_data_catalogs_normalizes_tags():
    service = make_service()

    service.list_data_catalogs.return_value = [
        {
            "CatalogName": "AwsDataCatalog",
        },
        {},
    ]

    service.list_tags_for_resource.return_value = [
        {
            "Key": "Environment",
            "Value": "prod",
        },
        {
            "Key": "aws:createdBy",
            "Value": "system",
        },
    ]

    result = AthenaDataCollector(
        service
    ).collect_data_catalogs()

    assert result == [
        {
            "catalog_name": "AwsDataCatalog",
            "catalog_arn": (
                "arn:aws:athena:ap-south-1:123:"
                "datacatalog/AwsDataCatalog"
            ),
            "tags": {
                "Environment": "prod",
            },
            "tag_data_available": True,
            "has_non_system_tags": True,
        },
    ]

    service.list_tags_for_resource.assert_called_once()


def test_collect_workgroups_caches_details_and_tags():
    service = make_service()

    service.list_workgroups.return_value = [
        {"Name": "primary"},
        {"Name": "primary"},
    ]

    service.get_workgroup.return_value = {
        "Name": "primary",
        "Configuration": {
            "PublishCloudWatchMetricsEnabled": False,
        },
    }

    service.list_tags_for_resource.return_value = []

    result = AthenaDataCollector(
        service
    ).collect_workgroups()

    assert len(result) == 2

    assert all(
        item[
            "publish_cloudwatch_metrics_enabled"
        ] is False
        for item in result
    )

    assert (
        service.get_workgroup.call_count
        == 1
    )

    assert (
        service.list_tags_for_resource.call_count
        == 1
    )
