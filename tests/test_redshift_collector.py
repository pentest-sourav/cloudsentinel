from unittest.mock import MagicMock

from scanner.aws.collectors.redshift import RedshiftDataCollector


def test_collect_clusters_normalizes_redshift_security_data():
    service = MagicMock()

    service.describe_clusters.return_value = [
        {
            "ClusterIdentifier": "cloudsentinel-redshift",
            "PubliclyAccessible": False,
            "Encrypted": True,
            "AutomatedSnapshotRetentionPeriod": 7,
            "AllowVersionUpgrade": True,
            "EnhancedVpcRouting": True,
            "MasterUsername": "cloudadmin",
            "MultiAZ": True,
            "Endpoint": {"Port": 5439},
            "ClusterParameterGroups": [
                {"ParameterGroupName": "custom-redshift"},
            ],
            "VpcSecurityGroups": [
                {"VpcSecurityGroupId": "sg-redshift"},
            ],
        }
    ]

    service.describe_cluster_parameters.return_value = [
        {
            "ParameterName": "require_ssl",
            "ParameterValue": "true",
        }
    ]

    service.describe_logging_status.return_value = {
        "LoggingEnabled": True,
    }

    service.describe_security_groups.return_value = [
        {
            "GroupId": "sg-redshift",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 5439,
                    "ToPort": 5439,
                    "IpRanges": [
                        {"CidrIp": "10.0.0.0/16"},
                    ],
                    "Ipv6Ranges": [],
                }
            ],
        }
    ]

    collector = RedshiftDataCollector(service)

    result = collector.collect_clusters()

    assert result == [
        {
            "cluster_identifier": "cloudsentinel-redshift",
            "publicly_accessible": False,
            "encrypted": True,
            "automated_snapshot_retention_period": 7,
            "allow_version_upgrade": True,
            "enhanced_vpc_routing": True,
            "master_username": "cloudadmin",
            "multi_az": True,
            "cluster_port": 5439,
            "require_ssl": "true",
            "parameter_group_name": "custom-redshift",
            "audit_logging_enabled": True,
            "vpc_security_group_ids": ["sg-redshift"],
            "security_group_ingress": [
                {
                    "security_group_id": "sg-redshift",
                    "ip_protocol": "tcp",
                    "from_port": 5439,
                    "to_port": 5439,
                    "ipv4_ranges": ["10.0.0.0/16"],
                    "ipv6_ranges": [],
                }
            ],
        }
    ]


def test_collect_clusters_does_not_invent_security_data_when_optional_fields_missing():
    service = MagicMock()

    service.describe_clusters.return_value = [
        {
            "ClusterIdentifier": "cluster-1",
        }
    ]

    service.describe_cluster_parameters.return_value = []
    service.describe_logging_status.return_value = {}
    service.describe_security_groups.return_value = []

    collector = RedshiftDataCollector(service)

    result = collector.collect_clusters()

    assert result == [
        {
            "cluster_identifier": "cluster-1",
            "publicly_accessible": None,
            "encrypted": None,
            "automated_snapshot_retention_period": None,
            "allow_version_upgrade": None,
            "enhanced_vpc_routing": None,
            "master_username": None,
            "multi_az": None,
            "cluster_port": None,
            "require_ssl": None,
            "parameter_group_name": None,
            "audit_logging_enabled": None,
            "vpc_security_group_ids": [],
            "security_group_ingress": [],
        }
    ]


def test_collect_clusters_is_cached():
    service = MagicMock()

    service.describe_clusters.return_value = [
        {"ClusterIdentifier": "cluster-1"}
    ]
    service.describe_cluster_parameters.return_value = []
    service.describe_logging_status.return_value = {}
    service.describe_security_groups.return_value = []

    collector = RedshiftDataCollector(service)

    first = collector.collect_clusters()
    second = collector.collect_clusters()

    assert first == second
    service.describe_clusters.assert_called_once()
