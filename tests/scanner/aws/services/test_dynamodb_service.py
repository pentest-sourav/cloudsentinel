from unittest.mock import Mock, call

import boto3
from botocore.exceptions import ClientError

from scanner.aws.services.dynamodb import DynamoDBService
from scanner.aws.session import AWS_RETRY_CONFIG


TABLE_ARN = (
    "arn:aws:dynamodb:ap-south-1:"
    "123456789012:table/cloudsentinel"
)


def make_service():
    fake_session = Mock(spec=boto3.Session)

    fake_dynamodb = Mock()
    fake_dax = Mock()
    fake_autoscaling = Mock()
    fake_backup = Mock()

    def client(service_name, **kwargs):
        clients = {
            "dynamodb": fake_dynamodb,
            "dax": fake_dax,
            "application-autoscaling": fake_autoscaling,
            "backup": fake_backup,
        }
        return clients[service_name]

    fake_session.client.side_effect = client

    service = DynamoDBService(fake_session)

    return (
        service,
        fake_session,
        fake_dynamodb,
        fake_dax,
        fake_autoscaling,
        fake_backup,
    )


def test_service_uses_centralized_retry_config():
    fake_session = Mock(spec=boto3.Session)

    fake_dynamodb = Mock()
    fake_dax = Mock()
    fake_autoscaling = Mock()
    fake_backup = Mock()

    fake_session.client.side_effect = [
        fake_dynamodb,
        fake_dax,
        fake_autoscaling,
        fake_backup,
    ]

    service = DynamoDBService(fake_session)

    assert service.dynamodb_client is fake_dynamodb
    assert service.dax_client is fake_dax
    assert service.application_autoscaling_client is fake_autoscaling
    assert service.backup_client is fake_backup

    assert fake_session.client.call_args_list == [
        call(
            "dynamodb",
            config=AWS_RETRY_CONFIG,
        ),
        call(
            "dax",
            config=AWS_RETRY_CONFIG,
        ),
        call(
            "application-autoscaling",
            config=AWS_RETRY_CONFIG,
        ),
        call(
            "backup",
            config=AWS_RETRY_CONFIG,
        ),
    ]


def test_list_tables():
    (
        service,
        _,
        fake_dynamodb,
        _,
        _,
        _,
    ) = make_service()

    fake_dynamodb.list_tables.return_value = {
        "TableNames": [
            "cloudsentinel-one",
            "cloudsentinel-two",
        ],
    }

    assert service.list_tables() == [
        "cloudsentinel-one",
        "cloudsentinel-two",
    ]

    fake_dynamodb.list_tables.assert_called_once_with()


def test_list_tables_handles_pagination():
    (
        service,
        _,
        fake_dynamodb,
        _,
        _,
        _,
    ) = make_service()

    fake_dynamodb.list_tables.side_effect = [
        {
            "TableNames": ["cloudsentinel-one"],
            "LastEvaluatedTableName": "cloudsentinel-one",
        },
        {
            "TableNames": ["cloudsentinel-two"],
        },
    ]

    assert service.list_tables() == [
        "cloudsentinel-one",
        "cloudsentinel-two",
    ]

    assert fake_dynamodb.list_tables.call_count == 2
    assert fake_dynamodb.list_tables.call_args_list[0].kwargs == {}
    assert fake_dynamodb.list_tables.call_args_list[1].kwargs == {
        "ExclusiveStartTableName": "cloudsentinel-one",
    }


def test_list_tables_returns_empty_when_missing():
    (
        service,
        _,
        fake_dynamodb,
        _,
        _,
        _,
    ) = make_service()

    fake_dynamodb.list_tables.return_value = {}

    assert service.list_tables() == []


def test_list_tables_handles_client_error():
    (
        service,
        _,
        fake_dynamodb,
        _,
        _,
        _,
    ) = make_service()

    fake_dynamodb.list_tables.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "Access denied",
            }
        },
        "ListTables",
    )

    try:
        service.list_tables()
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        assert "DynamoDB table discovery failed" in str(exc)
        assert "AccessDenied" in str(exc)


def test_describe_table():
    (
        service,
        _,
        fake_dynamodb,
        _,
        _,
        _,
    ) = make_service()

    fake_dynamodb.describe_table.return_value = {
        "Table": {
            "TableName": "cloudsentinel",
            "TableArn": TABLE_ARN,
            "TableStatus": "ACTIVE",
            "DeletionProtectionEnabled": True,
        }
    }

    assert service.describe_table("cloudsentinel") == {
        "TableName": "cloudsentinel",
        "TableArn": TABLE_ARN,
        "TableStatus": "ACTIVE",
        "DeletionProtectionEnabled": True,
    }

    fake_dynamodb.describe_table.assert_called_once_with(
        TableName="cloudsentinel",
    )


def test_describe_continuous_backups():
    (
        service,
        _,
        fake_dynamodb,
        _,
        _,
        _,
    ) = make_service()

    fake_dynamodb.describe_continuous_backups.return_value = {
        "ContinuousBackupsDescription": {
            "PointInTimeRecoveryDescription": {
                "PointInTimeRecoveryStatus": "ENABLED",
            }
        }
    }

    assert service.describe_continuous_backups(
        "cloudsentinel"
    ) == {
        "PointInTimeRecoveryDescription": {
            "PointInTimeRecoveryStatus": "ENABLED",
        }
    }

    fake_dynamodb.describe_continuous_backups.assert_called_once_with(
        TableName="cloudsentinel",
    )


def test_list_table_tags():
    (
        service,
        _,
        fake_dynamodb,
        _,
        _,
        _,
    ) = make_service()

    fake_dynamodb.list_tags_of_resource.return_value = {
        "Tags": [
            {"Key": "Environment", "Value": "test"},
            {"Key": "Owner", "Value": "security"},
        ]
    }

    assert service.list_table_tags(TABLE_ARN) == [
        {"Key": "Environment", "Value": "test"},
        {"Key": "Owner", "Value": "security"},
    ]

    fake_dynamodb.list_tags_of_resource.assert_called_once_with(
        ResourceArn=TABLE_ARN,
    )


def test_describe_scalable_targets_returns_targets():
    (
        service,
        _,
        _,
        _,
        fake_autoscaling,
        _,
    ) = make_service()

    fake_autoscaling.describe_scalable_targets.side_effect = [
        {
            "ScalableTargets": [
                {
                    "ResourceId": "table/cloudsentinel",
                    "ScalableDimension": (
                        "dynamodb:table:ReadCapacityUnits"
                    ),
                }
            ]
        },
        {
            "ScalableTargets": [
                {
                    "ResourceId": "table/cloudsentinel",
                    "ScalableDimension": (
                        "dynamodb:table:WriteCapacityUnits"
                    ),
                }
            ]
        },
    ]

    result = service.describe_scalable_targets(
        "cloudsentinel"
    )

    assert result[
        "dynamodb:table:ReadCapacityUnits"
    ] == [
        {
            "ResourceId": "table/cloudsentinel",
            "ScalableDimension": (
                "dynamodb:table:ReadCapacityUnits"
            ),
        }
    ]

    assert result[
        "dynamodb:table:WriteCapacityUnits"
    ] == [
        {
            "ResourceId": "table/cloudsentinel",
            "ScalableDimension": (
                "dynamodb:table:WriteCapacityUnits"
            ),
        }
    ]

    assert fake_autoscaling.describe_scalable_targets.call_count == 2


def test_describe_scalable_targets_treats_missing_target_as_empty():
    (
        service,
        _,
        _,
        _,
        fake_autoscaling,
        _,
    ) = make_service()

    fake_autoscaling.describe_scalable_targets.side_effect = [
        ClientError(
            {
                "Error": {
                    "Code": "ResourceNotFoundException",
                    "Message": "No scalable target",
                }
            },
            "DescribeScalableTargets",
        ),
        {
            "ScalableTargets": [
                {
                    "ResourceId": "table/cloudsentinel",
                }
            ]
        },
    ]

    result = service.describe_scalable_targets(
        "cloudsentinel"
    )

    assert result[
        "dynamodb:table:ReadCapacityUnits"
    ] == []

    assert result[
        "dynamodb:table:WriteCapacityUnits"
    ] == [
        {
            "ResourceId": "table/cloudsentinel",
        }
    ]


def test_describe_scaling_policies_returns_policies():
    (
        service,
        _,
        _,
        _,
        fake_autoscaling,
        _,
    ) = make_service()

    fake_autoscaling.describe_scaling_policies.side_effect = [
        {
            "ScalingPolicies": [
                {
                    "PolicyName": "read-target-tracking",
                    "PolicyType": "TargetTrackingScaling",
                }
            ]
        },
        {
            "ScalingPolicies": [
                {
                    "PolicyName": "write-target-tracking",
                    "PolicyType": "TargetTrackingScaling",
                }
            ]
        },
    ]

    result = service.describe_scaling_policies(
        "cloudsentinel"
    )

    assert result[
        "dynamodb:table:ReadCapacityUnits"
    ] == [
        {
            "PolicyName": "read-target-tracking",
            "PolicyType": "TargetTrackingScaling",
        }
    ]

    assert result[
        "dynamodb:table:WriteCapacityUnits"
    ] == [
        {
            "PolicyName": "write-target-tracking",
            "PolicyType": "TargetTrackingScaling",
        }
    ]

    assert fake_autoscaling.describe_scaling_policies.call_count == 2


def test_describe_scaling_policies_treats_missing_policy_as_empty():
    (
        service,
        _,
        _,
        _,
        fake_autoscaling,
        _,
    ) = make_service()

    fake_autoscaling.describe_scaling_policies.side_effect = [
        ClientError(
            {
                "Error": {
                    "Code": "ResourceNotFoundException",
                    "Message": "No scaling policy",
                }
            },
            "DescribeScalingPolicies",
        ),
        {
            "ScalingPolicies": [
                {
                    "PolicyName": "target-tracking",
                }
            ]
        },
    ]

    result = service.describe_scaling_policies(
        "cloudsentinel"
    )

    assert result[
        "dynamodb:table:ReadCapacityUnits"
    ] == []

    assert result[
        "dynamodb:table:WriteCapacityUnits"
    ] == [
        {
            "PolicyName": "target-tracking",
        }
    ]


def test_list_dax_clusters_handles_pagination():
    (
        service,
        _,
        _,
        fake_dax,
        _,
        _,
    ) = make_service()

    fake_dax.describe_clusters.side_effect = [
        {
            "Clusters": [
                {
                    "ClusterName": "dax-one",
                    "ClusterArn": (
                        "arn:aws:dax:ap-south-1:"
                        "123456789012:cache/dax-one"
                    ),
                }
            ],
            "NextToken": "page-two",
        },
        {
            "Clusters": [
                {
                    "ClusterName": "dax-two",
                    "ClusterArn": (
                        "arn:aws:dax:ap-south-1:"
                        "123456789012:cache/dax-two"
                    ),
                }
            ]
        },
    ]

    assert service.list_dax_clusters() == [
        {
            "ClusterName": "dax-one",
            "ClusterArn": (
                "arn:aws:dax:ap-south-1:"
                "123456789012:cache/dax-one"
            ),
        },
        {
            "ClusterName": "dax-two",
            "ClusterArn": (
                "arn:aws:dax:ap-south-1:"
                "123456789012:cache/dax-two"
            ),
        },
    ]

    assert fake_dax.describe_clusters.call_count == 2
    assert fake_dax.describe_clusters.call_args_list[0].kwargs == {}
    assert fake_dax.describe_clusters.call_args_list[1].kwargs == {
        "NextToken": "page-two",
    }


def test_list_backup_protected_resources_handles_pagination():
    (
        service,
        _,
        _,
        _,
        _,
        fake_backup,
    ) = make_service()

    fake_backup.list_protected_resources.side_effect = [
        {
            "Results": [
                {
                    "ResourceArn": TABLE_ARN,
                    "ResourceType": "DynamoDB",
                }
            ],
            "NextToken": "page-two",
        },
        {
            "Results": [
                {
                    "ResourceArn": (
                        "arn:aws:dynamodb:ap-south-1:"
                        "123456789012:table/other"
                    ),
                    "ResourceType": "DynamoDB",
                }
            ]
        },
    ]

    assert service.list_backup_protected_resources() == [
        {
            "ResourceArn": TABLE_ARN,
            "ResourceType": "DynamoDB",
        },
        {
            "ResourceArn": (
                "arn:aws:dynamodb:ap-south-1:"
                "123456789012:table/other"
            ),
            "ResourceType": "DynamoDB",
        },
    ]

    assert fake_backup.list_protected_resources.call_count == 2
    assert (
        fake_backup.list_protected_resources.call_args_list[0].kwargs
        == {}
    )
    assert (
        fake_backup.list_protected_resources.call_args_list[1].kwargs
        == {"NextToken": "page-two"}
    )
