from unittest.mock import Mock, patch

import pytest
from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.services.inspector import (
    InspectorService,
)


def make_response():
    return {
        "accounts": [
            {
                "accountId": "123456789012",
                "state": {
                    "status": "ENABLED",
                },
                "resourceState": {
                    "ec2": {
                        "status": "ENABLED",
                    },
                    "ecr": {
                        "status": "DISABLED",
                    },
                    "lambda": {
                        "status": "ENABLED",
                    },
                    "lambdaCode": {
                        "status": "DISABLED",
                    },
                },
            }
        ],
        "failedAccounts": [],
    }


def test_get_account_status_normalizes_response():
    client = Mock()
    client.batch_get_account_status.return_value = (
        make_response()
    )

    session = Mock()

    with patch(
        "scanner.aws.services.inspector.create_aws_client",
        return_value=client,
    ):
        service = InspectorService(session)

    result = service.get_account_status()

    client.batch_get_account_status.assert_called_once_with()

    assert result["account_id"] == "123456789012"
    assert result["account_status"] == "ENABLED"
    assert result["ec2_status"] == "ENABLED"
    assert result["ecr_status"] == "DISABLED"
    assert result["lambda_status"] == "ENABLED"
    assert result["lambda_code_status"] == "DISABLED"


def test_get_account_status_raises_for_failed_account():
    client = Mock()
    client.batch_get_account_status.return_value = {
        "accounts": [],
        "failedAccounts": [
            {
                "accountId": "123456789012",
                "status": "DISABLED",
                "errorCode": "ACCESS_DENIED",
                "errorMessage": "Access denied",
            }
        ],
    }

    with patch(
        "scanner.aws.services.inspector.create_aws_client",
        return_value=client,
    ):
        service = InspectorService(Mock())

    with pytest.raises(
        RuntimeError,
        match="ACCESS_DENIED: Access denied",
    ):
        service.get_account_status()


def test_get_account_status_raises_when_no_account_data():
    client = Mock()
    client.batch_get_account_status.return_value = {
        "accounts": [],
        "failedAccounts": [],
    }

    with patch(
        "scanner.aws.services.inspector.create_aws_client",
        return_value=client,
    ):
        service = InspectorService(Mock())

    with pytest.raises(
        RuntimeError,
        match="returned no account data",
    ):
        service.get_account_status()


def test_get_account_status_wraps_client_error():
    client = Mock()

    client_error = ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "Access denied",
            }
        },
        "BatchGetAccountStatus",
    )

    client.batch_get_account_status.side_effect = (
        client_error
    )

    with patch(
        "scanner.aws.services.inspector.create_aws_client",
        return_value=client,
    ):
        service = InspectorService(Mock())

    with pytest.raises(
        RuntimeError,
        match="AccessDeniedException: Access denied",
    ):
        service.get_account_status()


def test_get_account_status_wraps_sdk_error():
    client = Mock()
    client.batch_get_account_status.side_effect = (
        BotoCoreError()
    )

    with patch(
        "scanner.aws.services.inspector.create_aws_client",
        return_value=client,
    ):
        service = InspectorService(Mock())

    with pytest.raises(
        RuntimeError,
        match="AWS SDK error",
    ):
        service.get_account_status()
