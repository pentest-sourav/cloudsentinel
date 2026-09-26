from unittest.mock import MagicMock

from scanner.aws.services.redshift import RedshiftService


def test_describe_clusters_returns_all_pages():
    service = RedshiftService.__new__(RedshiftService)
    service.redshift_client = MagicMock()
    service.ec2_client = MagicMock()

    paginator = MagicMock()
    paginator.paginate.return_value = [
        {"Clusters": [{"ClusterIdentifier": "cluster-1"}]},
        {"Clusters": [{"ClusterIdentifier": "cluster-2"}]},
    ]

    service.redshift_client.get_paginator.return_value = paginator

    result = service.describe_clusters()

    assert result == [
        {"ClusterIdentifier": "cluster-1"},
        {"ClusterIdentifier": "cluster-2"},
    ]

    service.redshift_client.get_paginator.assert_called_once_with(
        "describe_clusters"
    )


def test_describe_cluster_parameters_handles_marker_pagination():
    service = RedshiftService.__new__(RedshiftService)
    service.redshift_client = MagicMock()
    service.ec2_client = MagicMock()

    service.redshift_client.describe_cluster_parameters.side_effect = [
        {
            "Parameters": [
                {
                    "ParameterName": "require_ssl",
                    "ParameterValue": "false",
                }
            ],
            "Marker": "next",
        },
        {
            "Parameters": [
                {
                    "ParameterName": "statement_timeout",
                    "ParameterValue": "0",
                }
            ]
        },
    ]

    result = service.describe_cluster_parameters("default.redshift")

    assert len(result) == 2
    assert result[0]["ParameterName"] == "require_ssl"
    assert result[1]["ParameterName"] == "statement_timeout"

    assert service.redshift_client.describe_cluster_parameters.call_count == 2


def test_describe_logging_status_returns_response():
    service = RedshiftService.__new__(RedshiftService)
    service.redshift_client = MagicMock()
    service.ec2_client = MagicMock()

    service.redshift_client.describe_logging_status.return_value = {
        "LoggingEnabled": True,
    }

    result = service.describe_logging_status("cluster-1")

    assert result["LoggingEnabled"] is True


def test_describe_security_groups_returns_all_pages():
    service = RedshiftService.__new__(RedshiftService)
    service.redshift_client = MagicMock()
    service.ec2_client = MagicMock()

    service.ec2_client.describe_security_groups.side_effect = [
        {
            "SecurityGroups": [
                {
                    "GroupId": "sg-1",
                    "IpPermissions": [],
                }
            ],
            "NextToken": "next",
        },
        {
            "SecurityGroups": [
                {
                    "GroupId": "sg-2",
                    "IpPermissions": [],
                }
            ]
        },
    ]

    result = service.describe_security_groups(["sg-1", "sg-2"])

    assert [item["GroupId"] for item in result] == [
        "sg-1",
        "sg-2",
    ]
