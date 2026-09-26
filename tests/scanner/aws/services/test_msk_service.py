from unittest.mock import Mock

import pytest

from scanner.aws.services.msk import MSKService


def make_service():
    session = Mock()
    kafka_client = Mock()
    kafka_connect_client = Mock()

    def client(name, **kwargs):
        if name == "kafka":
            return kafka_client

        if name == "kafkaconnect":
            return kafka_connect_client

        raise AssertionError(name)

    session.client.side_effect = client

    service = MSKService(session)

    return (
        service,
        kafka_client,
        kafka_connect_client,
    )


def test_list_clusters_paginates():
    service, kafka_client, _ = make_service()

    kafka_client.list_clusters_v2.side_effect = [
        {
            "ClusterInfoList": [
                {"ClusterArn": "arn:cluster:1"},
            ],
            "NextToken": "next",
        },
        {
            "ClusterInfoList": [
                {"ClusterArn": "arn:cluster:2"},
            ],
        },
    ]

    assert service.list_clusters() == [
        {"ClusterArn": "arn:cluster:1"},
        {"ClusterArn": "arn:cluster:2"},
    ]

    assert kafka_client.list_clusters_v2.call_count == 2
    assert (
        kafka_client.list_clusters_v2.call_args_list[1]
        .kwargs["NextToken"]
        == "next"
    )


def test_describe_cluster():
    service, kafka_client, _ = make_service()

    kafka_client.describe_cluster_v2.return_value = {
        "ClusterInfo": {
            "ClusterArn": "arn:cluster:1",
            "ClusterType": "PROVISIONED",
        },
    }

    assert service.describe_cluster(
        "arn:cluster:1"
    ) == {
        "ClusterArn": "arn:cluster:1",
        "ClusterType": "PROVISIONED",
    }


def test_list_connectors_paginates():
    service, _, kafka_connect_client = make_service()

    kafka_connect_client.list_connectors.side_effect = [
        {
            "connectors": [
                {"connectorArn": "arn:connector:1"},
            ],
            "nextToken": "next",
        },
        {
            "connectors": [
                {"connectorArn": "arn:connector:2"},
            ],
        },
    ]

    assert service.list_connectors() == [
        {"connectorArn": "arn:connector:1"},
        {"connectorArn": "arn:connector:2"},
    ]

    assert kafka_connect_client.list_connectors.call_count == 2
    assert (
        kafka_connect_client.list_connectors.call_args_list[1]
        .kwargs["nextToken"]
        == "next"
    )


def test_service_wraps_client_error():
    service, kafka_client, _ = make_service()

    from botocore.exceptions import ClientError

    kafka_client.list_clusters_v2.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "Access denied",
            }
        },
        "ListClustersV2",
    )

    with pytest.raises(
        RuntimeError,
        match="AWS MSK cluster discovery failed",
    ):
        service.list_clusters()
