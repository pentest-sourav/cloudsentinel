from unittest.mock import Mock

import pytest

from scanner.aws.services.secretsmanager import (
    SecretsManagerService,
)


def make_service():
    session = Mock()
    client = Mock()
    session.client.return_value = client

    service = SecretsManagerService(session)

    return service, session, client


def test_init_creates_secretsmanager_client():
    service, session, client = make_service()

    assert service.client is client
    session.client.assert_called_once()


def test_list_secrets_paginates():
    service, _, client = make_service()

    client.list_secrets.side_effect = [
        {
            "SecretList": [
                {
                    "ARN": "arn:secret:a",
                    "Name": "secret-a",
                }
            ],
            "NextToken": "next",
        },
        {
            "SecretList": [
                {
                    "ARN": "arn:secret:b",
                    "Name": "secret-b",
                }
            ]
        },
    ]

    result = service.list_secrets()

    assert [
        item["Name"]
        for item in result
    ] == [
        "secret-a",
        "secret-b",
    ]

    assert client.list_secrets.call_count == 2


def test_describe_secret_returns_metadata():
    service, _, client = make_service()

    client.describe_secret.return_value = {
        "ARN": "arn:secret:a",
        "Name": "secret-a",
        "RotationEnabled": True,
        "Tags": [
            {
                "Key": "Environment",
                "Value": "prod",
            }
        ],
    }

    result = service.describe_secret(
        "arn:secret:a"
    )

    assert result["Name"] == "secret-a"
    assert result["RotationEnabled"] is True
    assert result["Tags"][0]["Key"] == "Environment"


def test_invalid_sdk_error_is_wrapped():
    service, _, client = make_service()

    client.describe_secret.side_effect = Exception(
        "boom"
    )

    with pytest.raises(
        RuntimeError,
        match="AWS SDK error during Secrets Manager",
    ):
        service.describe_secret(
            "arn:secret:a"
        )
