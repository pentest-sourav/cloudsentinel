from unittest.mock import Mock


TABLE_ONE = (
    "arn:aws:dynamodb:ap-south-1:"
    "123456789012:table/cloudsentinel-one"
)

TABLE_TWO = (
    "arn:aws:dynamodb:ap-south-1:"
    "123456789012:table/cloudsentinel-two"
)

DAX_ONE = (
    "arn:aws:dax:ap-south-1:"
    "123456789012:cache/cloudsentinel-dax"
)


def test_collect_tables():
    from scanner.aws.collectors.dynamodb import DynamoDBDataCollector

    service = Mock()

    service.list_tables.return_value = [
        "cloudsentinel-one",
        "cloudsentinel-two",
    ]

    service.describe_table.side_effect = [
        {
            "TableArn": TABLE_ONE,
            "TableStatus": "ACTIVE",
            "BillingModeSummary": {
                "BillingMode": "PAY_PER_REQUEST",
            },
            "DeletionProtectionEnabled": True,
        },
        {
            "TableArn": TABLE_TWO,
            "TableStatus": "ACTIVE",
            "BillingModeSummary": {
                "BillingMode": "PROVISIONED",
            },
            "ProvisionedThroughput": {
                "ReadCapacityUnits": 5,
                "WriteCapacityUnits": 5,
            },
            "DeletionProtectionEnabled": False,
        },
    ]

    service.describe_continuous_backups.side_effect = [
        {
            "PointInTimeRecoveryDescription": {
                "PointInTimeRecoveryStatus": "ENABLED",
            }
        },
        {
            "PointInTimeRecoveryDescription": {
                "PointInTimeRecoveryStatus": "DISABLED",
            }
        },
    ]

    service.list_table_tags.side_effect = [
        [{"Key": "Environment", "Value": "test"}],
        [],
    ]

    service.describe_scalable_targets.return_value = {
        "dynamodb:table:ReadCapacityUnits": [
            {
                "ResourceId": "table/cloudsentinel-two",
            }
        ],
        "dynamodb:table:WriteCapacityUnits": [
            {
                "ResourceId": "table/cloudsentinel-two",
            }
        ],
    }

    service.describe_scaling_policies.return_value = {
        "dynamodb:table:ReadCapacityUnits": [
            {
                "PolicyName": "read-target-tracking",
            }
        ],
        "dynamodb:table:WriteCapacityUnits": [
            {
                "PolicyName": "write-target-tracking",
            }
        ],
    }

    service.list_backup_protected_resources.return_value = [
        {
            "ResourceArn": TABLE_ONE,
            "ResourceType": "DynamoDB",
        }
    ]

    from scanner.aws.collectors.dynamodb import DynamoDBDataCollector

    collector = DynamoDBDataCollector(service)

    result = collector.collect_tables()

    assert result == [
        {
            "table_name": "cloudsentinel-one",
            "table_arn": TABLE_ONE,
            "table_status": "ACTIVE",
            "billing_mode": "PAY_PER_REQUEST",
            "provisioned_throughput": {},
            "deletion_protection_enabled": True,
            "continuous_backups": {
                "PointInTimeRecoveryDescription": {
                    "PointInTimeRecoveryStatus": "ENABLED",
                }
            },
            "tags": [
                {"Key": "Environment", "Value": "test"},
            ],
            "scalable_targets": {},
            "scaling_policies": {},
            "autoscaling_enabled": True,
            "backup_resources": [
                {
                    "ResourceArn": TABLE_ONE,
                    "ResourceType": "DynamoDB",
                }
            ],
        },
        {
            "table_name": "cloudsentinel-two",
            "table_arn": TABLE_TWO,
            "table_status": "ACTIVE",
            "billing_mode": "PROVISIONED",
            "provisioned_throughput": {
                "ReadCapacityUnits": 5,
                "WriteCapacityUnits": 5,
            },
            "deletion_protection_enabled": False,
            "continuous_backups": {
                "PointInTimeRecoveryDescription": {
                    "PointInTimeRecoveryStatus": "DISABLED",
                }
            },
            "tags": [],
            "scalable_targets": {
                "dynamodb:table:ReadCapacityUnits": [
                    {
                        "ResourceId": "table/cloudsentinel-two",
                    }
                ],
                "dynamodb:table:WriteCapacityUnits": [
                    {
                        "ResourceId": "table/cloudsentinel-two",
                    }
                ],
            },
            "scaling_policies": {
                "dynamodb:table:ReadCapacityUnits": [
                    {
                        "PolicyName": "read-target-tracking",
                    }
                ],
                "dynamodb:table:WriteCapacityUnits": [
                    {
                        "PolicyName": "write-target-tracking",
                    }
                ],
            },
            "autoscaling_enabled": True,
            "backup_resources": [
                {
                    "ResourceArn": TABLE_ONE,
                    "ResourceType": "DynamoDB",
                }
            ],
        },
    ]

    service.describe_scalable_targets.assert_called_once_with(
        "cloudsentinel-two"
    )
    service.describe_scaling_policies.assert_called_once_with(
        "cloudsentinel-two"
    )


def test_collect_tables_skips_invalid_table_arns():
    from scanner.aws.collectors.dynamodb import DynamoDBDataCollector

    service = Mock()

    service.list_tables.return_value = [
        "valid-table",
        "invalid-table",
    ]

    service.describe_table.side_effect = [
        {
            "TableArn": TABLE_ONE,
            "TableStatus": "ACTIVE",
        },
        {},
    ]

    service.describe_continuous_backups.return_value = {}
    service.list_table_tags.return_value = []
    service.list_backup_protected_resources.return_value = []

    collector = DynamoDBDataCollector(service)

    result = collector.collect_tables()

    assert result == [
        {
            "table_name": "valid-table",
            "table_arn": TABLE_ONE,
            "table_status": "ACTIVE",
            "billing_mode": None,
            "provisioned_throughput": {},
            "deletion_protection_enabled": False,
            "continuous_backups": {},
            "tags": [],
            "scalable_targets": {},
            "scaling_policies": {},
            "autoscaling_enabled": False,
            "backup_resources": [],
        }
    ]

    service.describe_table.assert_any_call("valid-table")
    service.describe_table.assert_any_call("invalid-table")


def test_collect_tables_caches_table_data():
    from scanner.aws.collectors.dynamodb import DynamoDBDataCollector

    service = Mock()

    service.list_tables.return_value = [
        "cloudsentinel-one",
    ]

    service.describe_table.return_value = {
        "TableArn": TABLE_ONE,
        "TableStatus": "ACTIVE",
        "BillingModeSummary": {
            "BillingMode": "PAY_PER_REQUEST",
        },
    }

    service.describe_continuous_backups.return_value = {}
    service.list_table_tags.return_value = []
    service.list_backup_protected_resources.return_value = []

    collector = DynamoDBDataCollector(service)

    collector.collect_tables()
    collector.collect_tables()

    service.list_tables.assert_called_once_with()
    service.describe_table.assert_called_once_with(
        "cloudsentinel-one"
    )
    service.describe_continuous_backups.assert_called_once_with(
        "cloudsentinel-one"
    )
    service.list_table_tags.assert_called_once_with(TABLE_ONE)
    service.list_backup_protected_resources.assert_called_once_with()


def test_collect_tables_does_not_call_autoscaling_for_on_demand_table():
    from scanner.aws.collectors.dynamodb import DynamoDBDataCollector

    service = Mock()

    service.list_tables.return_value = [
        "cloudsentinel-one",
    ]

    service.describe_table.return_value = {
        "TableArn": TABLE_ONE,
        "TableStatus": "ACTIVE",
        "BillingModeSummary": {
            "BillingMode": "PAY_PER_REQUEST",
        },
    }

    service.describe_continuous_backups.return_value = {}
    service.list_table_tags.return_value = []
    service.list_backup_protected_resources.return_value = []

    collector = DynamoDBDataCollector(service)

    result = collector.collect_tables()

    assert result[0]["billing_mode"] == "PAY_PER_REQUEST"
    assert result[0]["autoscaling_enabled"] is True
    assert result[0]["scalable_targets"] == {}
    assert result[0]["scaling_policies"] == {}

    service.describe_scalable_targets.assert_not_called()
    service.describe_scaling_policies.assert_not_called()


def test_collect_tables_requires_both_read_and_write_autoscaling():
    from scanner.aws.collectors.dynamodb import DynamoDBDataCollector

    service = Mock()

    service.list_tables.return_value = [
        "cloudsentinel-one",
    ]

    service.describe_table.return_value = {
        "TableArn": TABLE_ONE,
        "TableStatus": "ACTIVE",
        "BillingModeSummary": {
            "BillingMode": "PROVISIONED",
        },
    }

    service.describe_continuous_backups.return_value = {}
    service.list_table_tags.return_value = []
    service.list_backup_protected_resources.return_value = []

    service.describe_scalable_targets.return_value = {
        "dynamodb:table:ReadCapacityUnits": [
            {"ResourceId": "table/cloudsentinel-one"}
        ],
        "dynamodb:table:WriteCapacityUnits": [],
    }

    service.describe_scaling_policies.return_value = {
        "dynamodb:table:ReadCapacityUnits": [
            {"PolicyName": "read-target-tracking"}
        ],
        "dynamodb:table:WriteCapacityUnits": [],
    }

    collector = DynamoDBDataCollector(service)

    result = collector.collect_tables()

    assert result[0]["autoscaling_enabled"] is False


def test_collect_dax_clusters():
    from scanner.aws.collectors.dynamodb import DynamoDBDataCollector

    service = Mock()

    service.list_dax_clusters.return_value = [
        {
            "ClusterName": "cloudsentinel-dax",
            "ClusterArn": DAX_ONE,
            "Status": "available",
            "SSEDescription": {
                "Status": "ENABLED",
            },
            "ClusterEndpointEncryptionType": "TLS",
        }
    ]

    collector = DynamoDBDataCollector(service)

    assert collector.collect_dax_clusters() == [
        {
            "cluster_name": "cloudsentinel-dax",
            "cluster_arn": DAX_ONE,
            "status": "available",
            "sse_description": {
                "Status": "ENABLED",
            },
            "cluster_endpoint_encryption_type": "TLS",
        }
    ]

    service.list_dax_clusters.assert_called_once_with()


def test_collect_dax_clusters_ignores_invalid_arns():
    from scanner.aws.collectors.dynamodb import DynamoDBDataCollector

    service = Mock()

    service.list_dax_clusters.return_value = [
        {
            "ClusterName": "valid",
            "ClusterArn": DAX_ONE,
        },
        {
            "ClusterName": "invalid",
        },
        {},
    ]

    collector = DynamoDBDataCollector(service)

    assert collector.collect_dax_clusters() == [
        {
            "cluster_name": "valid",
            "cluster_arn": DAX_ONE,
            "status": None,
            "sse_description": {},
            "cluster_endpoint_encryption_type": None,
        }
    ]


def test_collect_dax_clusters_caches_discovery():
    from scanner.aws.collectors.dynamodb import DynamoDBDataCollector

    service = Mock()

    service.list_dax_clusters.return_value = []

    collector = DynamoDBDataCollector(service)

    collector.collect_dax_clusters()
    collector.collect_dax_clusters()

    service.list_dax_clusters.assert_called_once_with()


def test_collect_backup_protected_resources():
    from scanner.aws.collectors.dynamodb import DynamoDBDataCollector

    service = Mock()

    resources = [
        {
            "ResourceArn": TABLE_ONE,
            "ResourceType": "DynamoDB",
        }
    ]

    service.list_backup_protected_resources.return_value = resources

    collector = DynamoDBDataCollector(service)

    assert collector.collect_backup_protected_resources() == resources
    assert collector.collect_backup_protected_resources() == resources

    service.list_backup_protected_resources.assert_called_once_with()
