from unittest.mock import Mock

from scanner.aws.collectors.apprunner import (
    AppRunnerDataCollector,
)


def make_service():
    return Mock()


def test_collect_services_normalizes_tags_and_ignores_system_tags():
    service = make_service()

    service.list_services.return_value = [
        {
            "ServiceId": "1111",
            "ServiceArn": "arn:service:one",
            "ServiceName": "frontend",
            "Status": "RUNNING",
        }
    ]

    service.list_tags_for_resource.return_value = [
        {
            "Key": "Environment",
            "Value": "prod",
        },
        {
            "Key": "Owner",
            "Value": "security",
        },
        {
            "Key": "aws:createdBy",
            "Value": "system",
        },
    ]

    result = AppRunnerDataCollector(
        service
    ).collect_services()

    assert result == [
        {
            "service_id": "1111",
            "service_arn": "arn:service:one",
            "service_name": "frontend",
            "status": "RUNNING",
            "tags": {
                "Environment": "prod",
                "Owner": "security",
            },
            "tag_data_available": True,
            "has_non_system_tags": True,
        }
    ]


def test_collect_services_detects_untagged_service():
    service = make_service()

    service.list_services.return_value = [
        {
            "ServiceId": "1111",
            "ServiceArn": "arn:service:one",
            "ServiceName": "frontend",
            "Status": "RUNNING",
        }
    ]

    service.list_tags_for_resource.return_value = [
        {
            "Key": "aws:createdBy",
            "Value": "system",
        }
    ]

    result = AppRunnerDataCollector(
        service
    ).collect_services()

    assert result[0]["tags"] == {}
    assert result[0]["tag_data_available"] is True
    assert result[0]["has_non_system_tags"] is False


def test_collect_services_skips_invalid_services():
    service = make_service()

    service.list_services.return_value = [
        {
            "ServiceId": "1111",
            "ServiceArn": "arn:service:one",
            "ServiceName": "valid",
        },
        {
            "ServiceId": "2222",
            "ServiceArn": "",
            "ServiceName": "invalid",
        },
        None,
    ]

    service.list_tags_for_resource.return_value = []

    result = AppRunnerDataCollector(
        service
    ).collect_services()

    assert len(result) == 1
    assert result[0]["service_name"] == "valid"


def test_collect_services_uses_service_id_when_name_missing():
    service = make_service()

    service.list_services.return_value = [
        {
            "ServiceId": "1111",
            "ServiceArn": "arn:service:one",
        }
    ]

    service.list_tags_for_resource.return_value = []

    result = AppRunnerDataCollector(
        service
    ).collect_services()

    assert result[0]["service_name"] == "1111"


def test_collect_services_skips_when_tag_data_is_not_a_list():
    service = make_service()

    service.list_services.return_value = [
        {
            "ServiceId": "1111",
            "ServiceArn": "arn:service:one",
            "ServiceName": "frontend",
        }
    ]

    service.list_tags_for_resource.return_value = {}

    result = AppRunnerDataCollector(
        service
    ).collect_services()

    assert result[0]["tag_data_available"] is False
    assert result[0]["has_non_system_tags"] is False


def test_collect_vpc_connectors_normalizes_tags():
    service = make_service()

    service.list_vpc_connectors.return_value = [
        {
            "VpcConnectorArn": "arn:connector:one",
            "VpcConnectorName": "frontend",
            "VpcConnectorRevision": 1,
            "Status": "ACTIVE",
        }
    ]

    service.list_tags_for_resource.return_value = [
        {
            "Key": "Environment",
            "Value": "prod",
        }
    ]

    result = AppRunnerDataCollector(
        service
    ).collect_vpc_connectors()

    assert result == [
        {
            "vpc_connector_arn": "arn:connector:one",
            "vpc_connector_name": "frontend",
            "vpc_connector_revision": 1,
            "status": "ACTIVE",
            "tags": {
                "Environment": "prod",
            },
            "tag_data_available": True,
            "has_non_system_tags": True,
        }
    ]


def test_collect_vpc_connectors_detects_system_only_tags():
    service = make_service()

    service.list_vpc_connectors.return_value = [
        {
            "VpcConnectorArn": "arn:connector:one",
            "VpcConnectorName": "frontend",
            "VpcConnectorRevision": 1,
            "Status": "ACTIVE",
        }
    ]

    service.list_tags_for_resource.return_value = [
        {
            "Key": "aws:createdBy",
            "Value": "system",
        }
    ]

    result = AppRunnerDataCollector(
        service
    ).collect_vpc_connectors()

    assert result[0]["tags"] == {}
    assert result[0]["tag_data_available"] is True
    assert result[0]["has_non_system_tags"] is False


def test_collect_vpc_connectors_skips_invalid_connectors():
    service = make_service()

    service.list_vpc_connectors.return_value = [
        {
            "VpcConnectorArn": "arn:connector:one",
            "VpcConnectorName": "valid",
        },
        {
            "VpcConnectorArn": "",
            "VpcConnectorName": "invalid",
        },
        None,
    ]

    service.list_tags_for_resource.return_value = []

    result = AppRunnerDataCollector(
        service
    ).collect_vpc_connectors()

    assert len(result) == 1
    assert result[0]["vpc_connector_name"] == "valid"


def test_collector_caches_discovery():
    service = make_service()

    service.list_services.return_value = []
    service.list_vpc_connectors.return_value = []

    collector = AppRunnerDataCollector(service)

    assert collector.collect_services() == []
    assert collector.collect_services() == []

    assert collector.collect_vpc_connectors() == []
    assert collector.collect_vpc_connectors() == []

    service.list_services.assert_called_once()
    service.list_vpc_connectors.assert_called_once()
