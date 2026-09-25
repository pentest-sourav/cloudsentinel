from datetime import datetime, timezone
from unittest.mock import Mock

from scanner.aws.collectors.secretsmanager import (
    SecretsManagerDataCollector,
)


def make_service():
    service = Mock()

    service.list_secrets.return_value = [
        {
            "ARN": "arn:aws:secretsmanager:"
            "ap-south-1:123:secret:db",
            "Name": "db-secret",
        }
    ]

    service.describe_secret.return_value = {
        "ARN": "arn:aws:secretsmanager:"
        "ap-south-1:123:secret:db",
        "Name": "db-secret",
        "RotationEnabled": True,
        "RotationRules": {
            "AutomaticallyAfterDays": 30,
        },
        "LastRotatedDate": datetime(
            2026,
            9,
            1,
            tzinfo=timezone.utc,
        ),
        "LastAccessedDate": datetime(
            2026,
            9,
            20,
            tzinfo=timezone.utc,
        ),
        "NextRotationDate": datetime(
            2026,
            10,
            1,
            tzinfo=timezone.utc,
        ),
        "LastChangedDate": datetime(
            2026,
            9,
            1,
            tzinfo=timezone.utc,
        ),
        "Tags": [
            {
                "Key": "Environment",
                "Value": "prod",
            }
        ],
        "OwningService": "application",
    }

    return service


def test_collect_secrets_normalizes_security_fields():
    service = make_service()
    collector = SecretsManagerDataCollector(
        service
    )

    result = collector.collect_secrets()

    assert len(result) == 1

    secret = result[0]

    assert secret["resource_id"] == "db-secret"
    assert secret["rotation_enabled"] is True
    assert secret["rotation_rules"][
        "AutomaticallyAfterDays"
    ] == 30
    assert secret["last_rotated_date"] is not None
    assert secret["last_accessed_date"] is not None
    assert secret["tags"] == [
        {
            "Key": "Environment",
            "Value": "prod",
        }
    ]


def test_collector_caches_secret_collection():
    service = make_service()
    collector = SecretsManagerDataCollector(
        service
    )

    first = collector.collect_secrets()
    second = collector.collect_secrets()

    assert first is not second
    service.list_secrets.assert_called_once()
    service.describe_secret.assert_called_once()
