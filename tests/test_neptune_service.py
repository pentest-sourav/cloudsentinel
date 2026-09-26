from unittest.mock import Mock

import pytest

from scanner.aws.services.neptune import NeptuneService


def test_describe_db_clusters_uses_pagination():
    session = Mock()
    client = Mock()
    paginator = Mock()

    paginator.paginate.return_value = [
        {"DBClusters": [{"DBClusterIdentifier": "cluster-1"}]},
        {"DBClusters": [{"DBClusterIdentifier": "cluster-2"}]},
    ]

    client.get_paginator.return_value = paginator
    session.client.return_value = client

    service = NeptuneService(session)

    assert service.describe_db_clusters() == [
        {"DBClusterIdentifier": "cluster-1"},
        {"DBClusterIdentifier": "cluster-2"},
    ]

    client.get_paginator.assert_called_once_with(
        "describe_db_clusters"
    )


def test_describe_db_instances_filters_for_neptune():
    session = Mock()
    client = Mock()
    paginator = Mock()

    paginator.paginate.return_value = [
        {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "instance-1",
                    "Engine": "neptune",
                }
            ]
        }
    ]

    client.get_paginator.return_value = paginator
    session.client.return_value = client

    service = NeptuneService(session)

    assert service.describe_db_instances()[0][
        "Engine"
    ] == "neptune"

    paginator.paginate.assert_called_once_with(
        Filters=[
            {
                "Name": "engine",
                "Values": ["neptune"],
            }
        ]
    )


def test_describe_db_cluster_snapshots_uses_pagination():
    session = Mock()
    client = Mock()
    paginator = Mock()

    paginator.paginate.return_value = [
        {
            "DBClusterSnapshots": [
                {
                    "DBClusterSnapshotIdentifier": "snapshot-1"
                }
            ]
        }
    ]

    client.get_paginator.return_value = paginator
    session.client.return_value = client

    service = NeptuneService(session)

    assert service.describe_db_cluster_snapshots() == [
        {
            "DBClusterSnapshotIdentifier": "snapshot-1"
        }
    ]


def test_describe_snapshot_attributes():
    session = Mock()
    client = Mock()

    client.describe_db_cluster_snapshot_attributes.return_value = {
        "DBClusterSnapshotAttributesResult": {
            "DBClusterSnapshotAttributes": [
                {
                    "AttributeName": "restore",
                    "AttributeValues": ["all"],
                }
            ]
        }
    }

    session.client.return_value = client

    service = NeptuneService(session)

    result = service.describe_db_cluster_snapshot_attributes(
        "snapshot-1"
    )

    assert result[
        "DBClusterSnapshotAttributesResult"
    ][
        "DBClusterSnapshotAttributes"
    ][0]["AttributeValues"] == ["all"]

    client.describe_db_cluster_snapshot_attributes.assert_called_once_with(
        DBClusterSnapshotIdentifier="snapshot-1"
    )
