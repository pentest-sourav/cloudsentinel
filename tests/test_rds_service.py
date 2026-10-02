from unittest.mock import MagicMock

from scanner.aws.services.rds import RDSService


def test_describe_db_instances_returns_instances():
    service = RDSService.__new__(RDSService)

    service.rds_client = MagicMock()

    paginator = MagicMock()

    paginator.paginate.return_value = [
        {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "cloudsentinel-db",
                    "PubliclyAccessible": False,
                    "StorageEncrypted": True,
                }
            ]
        }
    ]

    service.rds_client.get_paginator.return_value = paginator

    result = service.describe_db_instances()

    assert len(result) == 1
    assert result[0]["DBInstanceIdentifier"] == "cloudsentinel-db"
    assert result[0]["PubliclyAccessible"] is False
    assert result[0]["StorageEncrypted"] is True

    service.rds_client.get_paginator.assert_called_once_with(
        "describe_db_instances"
    )


def test_describe_db_instances_handles_empty_response():
    service = RDSService.__new__(RDSService)

    service.rds_client = MagicMock()

    paginator = MagicMock()
    paginator.paginate.return_value = [
        {"DBInstances": []}
    ]

    service.rds_client.get_paginator.return_value = paginator

    result = service.describe_db_instances()

    assert result == []


def test_describe_db_instances_handles_multiple_pages():
    service = RDSService.__new__(RDSService)

    service.rds_client = MagicMock()

    paginator = MagicMock()

    paginator.paginate.return_value = [
        {
            "DBInstances": [
                {"DBInstanceIdentifier": "db-1"}
            ]
        },
        {
            "DBInstances": [
                {"DBInstanceIdentifier": "db-2"}
            ]
        },
    ]

    service.rds_client.get_paginator.return_value = paginator

    result = service.describe_db_instances()

    assert len(result) == 2
    assert result[0]["DBInstanceIdentifier"] == "db-1"
    assert result[1]["DBInstanceIdentifier"] == "db-2"


def test_describe_global_clusters_collects_all_pages():
    session = MagicMock()
    rds_client = MagicMock()
    paginator = MagicMock()

    session.client.return_value = rds_client
    rds_client.get_paginator.return_value = paginator

    paginator.paginate.return_value = [
        {
            "GlobalClusters": [
                {
                    "GlobalClusterIdentifier": "global-001",
                    "GlobalClusterArn": (
                        "arn:aws:rds::123456789012:"
                        "global-cluster:global-001"
                    ),
                    "Engine": "aurora-mysql",
                    "EngineVersion": "8.0.mysql_aurora.3.08.0",
                }
            ]
        },
        {
            "GlobalClusters": [
                {
                    "GlobalClusterIdentifier": "global-002",
                    "Engine": "aurora-mysql",
                    "EngineVersion": "8.0.mysql_aurora.3.04.3",
                }
            ]
        },
    ]

    service = RDSService(session)

    result = service.describe_global_clusters()

    assert result == [
        {
            "GlobalClusterIdentifier": "global-001",
            "GlobalClusterArn": (
                "arn:aws:rds::123456789012:"
                "global-cluster:global-001"
            ),
            "Engine": "aurora-mysql",
            "EngineVersion": "8.0.mysql_aurora.3.08.0",
        },
        {
            "GlobalClusterIdentifier": "global-002",
            "Engine": "aurora-mysql",
            "EngineVersion": "8.0.mysql_aurora.3.04.3",
        },
    ]

    rds_client.get_paginator.assert_called_once_with(
        "describe_global_clusters"
    )
