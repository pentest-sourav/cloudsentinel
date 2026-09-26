from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from scanner.aws.services.documentdb import DocumentDBService


def _service():
    session = Mock()
    service = DocumentDBService.__new__(DocumentDBService)
    service.session = session
    service.docdb_client = Mock()
    return service


def test_describe_db_clusters_uses_paginator():
    service = _service()

    paginator = Mock()
    paginator.paginate.return_value = [
        {"DBClusters": [{"DBClusterIdentifier": "cluster-1"}]},
        {"DBClusters": [{"DBClusterIdentifier": "cluster-2"}]},
    ]
    service.docdb_client.get_paginator.return_value = paginator

    result = service.describe_db_clusters()

    assert result == [
        {"DBClusterIdentifier": "cluster-1"},
        {"DBClusterIdentifier": "cluster-2"},
    ]
    service.docdb_client.get_paginator.assert_called_once_with(
        "describe_db_clusters"
    )


def test_describe_db_cluster_snapshots_uses_paginator():
    service = _service()

    paginator = Mock()
    paginator.paginate.return_value = [
        {"DBClusterSnapshots": [{"DBClusterSnapshotIdentifier": "s-1"}]},
        {"DBClusterSnapshots": [{"DBClusterSnapshotIdentifier": "s-2"}]},
    ]
    service.docdb_client.get_paginator.return_value = paginator

    result = service.describe_db_cluster_snapshots()

    assert result == [
        {"DBClusterSnapshotIdentifier": "s-1"},
        {"DBClusterSnapshotIdentifier": "s-2"},
    ]


def test_snapshot_attributes_returns_aws_response():
    service = _service()

    expected = {
        "DBClusterSnapshotAttributesResult": {
            "DBClusterSnapshotAttributes": []
        }
    }
    service.docdb_client.describe_db_cluster_snapshot_attributes.return_value = (
        expected
    )

    assert (
        service.describe_db_cluster_snapshot_attributes("snapshot-1")
        == expected
    )


def test_describe_cluster_parameters_handles_marker_pagination():
    service = _service()

    service.docdb_client.describe_db_cluster_parameters.side_effect = [
        {
            "Parameters": [
                {
                    "ParameterName": "tls",
                    "ParameterValue": "enabled",
                }
            ],
            "Marker": "next-token",
        },
        {
            "Parameters": [
                {
                    "ParameterName": "audit_logs",
                    "ParameterValue": "enabled",
                }
            ]
        },
    ]

    result = service.describe_db_cluster_parameters("custom-docdb")

    assert result == [
        {
            "ParameterName": "tls",
            "ParameterValue": "enabled",
        },
        {
            "ParameterName": "audit_logs",
            "ParameterValue": "enabled",
        },
    ]
    assert service.docdb_client.describe_db_cluster_parameters.call_count == 2

    first_call = (
        service.docdb_client.describe_db_cluster_parameters.call_args_list[0]
    )
    second_call = (
        service.docdb_client.describe_db_cluster_parameters.call_args_list[1]
    )

    assert first_call.kwargs["DBClusterParameterGroupName"] == "custom-docdb"
    assert "Marker" not in first_call.kwargs
    assert second_call.kwargs["Marker"] == "next-token"


def test_empty_parameter_group_returns_empty():
    service = _service()

    assert service.describe_db_cluster_parameters("") == []
    service.docdb_client.describe_db_cluster_parameters.assert_not_called()


def test_client_error_is_normalized():
    service = _service()

    error = ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "denied",
            }
        },
        "DescribeDBClusters",
    )

    paginator = Mock()
    paginator.paginate.side_effect = error
    service.docdb_client.get_paginator.return_value = paginator

    with pytest.raises(
        RuntimeError,
        match="DocumentDB DB cluster discovery failed: "
        "AccessDeniedException: denied",
    ):
        service.describe_db_clusters()
