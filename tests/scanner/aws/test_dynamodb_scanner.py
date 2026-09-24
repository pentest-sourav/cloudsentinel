from unittest.mock import Mock

from scanner.aws.scanners.dynamodb import DynamoDBScanner


TABLE_ARN = (
    "arn:aws:dynamodb:ap-south-1:"
    "123456789012:table/cloudsentinel"
)

DAX_ARN = (
    "arn:aws:dax:ap-south-1:"
    "123456789012:cache/cloudsentinel-dax"
)


def test_dynamodb_scanner_executes_dynamodb_rules():
    service = Mock()

    service.list_tables.return_value = [
        "cloudsentinel",
    ]

    service.describe_table.return_value = {
        "TableArn": TABLE_ARN,
        "TableStatus": "ACTIVE",
        "BillingModeSummary": {
            "BillingMode": "PAY_PER_REQUEST",
        },
        "DeletionProtectionEnabled": True,
    }

    service.describe_continuous_backups.return_value = {
        "PointInTimeRecoveryDescription": {
            "PointInTimeRecoveryStatus": "ENABLED",
        }
    }

    service.list_table_tags.return_value = [
        {
            "Key": "Environment",
            "Value": "test",
        }
    ]

    service.list_backup_protected_resources.return_value = [
        {
            "ResourceArn": TABLE_ARN,
            "ResourceType": "DynamoDB",
        }
    ]

    service.list_dax_clusters.return_value = [
        {
            "ClusterName": "cloudsentinel-dax",
            "ClusterArn": DAX_ARN,
            "Status": "available",
            "SSEDescription": {
                "Status": "ENABLED",
            },
            "ClusterEndpointEncryptionType": "TLS",
        }
    ]

    scanner = DynamoDBScanner(service)

    findings = scanner.scan()

    assert findings == []
