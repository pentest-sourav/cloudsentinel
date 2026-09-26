from unittest.mock import Mock

from scanner.aws.collectors.appflow import (
    AppFlowDataCollector,
)


def test_collect_flows_normalizes_tags():
    service = Mock()

    service.list_flows.return_value = [
        {
            "flowName": "salesforce_to_s3",
            "flowArn": (
                "arn:aws:appflow:ap-south-1:"
                "123456789012:flow/salesforce_to_s3"
            ),
            "flowStatus": "Active",
            "sourceConnectorType": "Salesforce",
            "destinationConnectorType": "S3",
        }
    ]

    service.list_tags_for_resource.return_value = {
        "Environment": "prod",
        "Owner": "security",
        "aws:createdBy": "system",
    }

    result = AppFlowDataCollector(
        service
    ).collect_flows()

    assert result == [
        {
            "flow_name": "salesforce_to_s3",
            "flow_arn": (
                "arn:aws:appflow:ap-south-1:"
                "123456789012:flow/salesforce_to_s3"
            ),
            "flow_status": "Active",
            "source_connector_type": "Salesforce",
            "destination_connector_type": "S3",
            "tags": {
                "Environment": "prod",
                "Owner": "security",
            },
            "tag_data_available": True,
            "has_non_system_tags": True,
        }
    ]


def test_collect_flows_detects_system_only_tags():
    service = Mock()

    service.list_flows.return_value = [
        {
            "flowName": "flow_one",
            "flowArn": "arn:flow",
        }
    ]

    service.list_tags_for_resource.return_value = {
        "aws:createdBy": "system",
    }

    result = AppFlowDataCollector(
        service
    ).collect_flows()

    assert result[0]["tags"] == {}
    assert result[0]["tag_data_available"] is True
    assert result[0]["has_non_system_tags"] is False


def test_collect_flows_skips_invalid_resources():
    service = Mock()

    service.list_flows.return_value = [
        {
            "flowName": "valid",
            "flowArn": "arn:valid",
        },
        {
            "flowName": "",
            "flowArn": "arn:invalid",
        },
        None,
    ]

    service.list_tags_for_resource.return_value = {}

    result = AppFlowDataCollector(
        service
    ).collect_flows()

    assert len(result) == 1
    assert result[0]["flow_name"] == "valid"


def test_collect_flows_is_cached():
    service = Mock()

    service.list_flows.return_value = [
        {
            "flowName": "flow_one",
            "flowArn": "arn:flow",
        }
    ]
    service.list_tags_for_resource.return_value = {}

    collector = AppFlowDataCollector(service)

    collector.collect_flows()
    collector.collect_flows()

    service.list_flows.assert_called_once()
    service.list_tags_for_resource.assert_called_once_with(
        "arn:flow"
    )
