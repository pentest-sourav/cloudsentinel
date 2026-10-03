from unittest.mock import Mock, patch

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.session import AWS_RETRY_CONFIG, create_aws_session


def test_create_aws_session():
    with patch("scanner.aws.session.boto3.Session") as mock_session:
        create_aws_session(
            profile_name="cloudsentinel",
            region_name="ap-south-1",
        )

        mock_session.assert_called_once_with(
            profile_name="cloudsentinel",
            region_name="ap-south-1",
        )


def test_create_aws_session_assumes_role():
    base_session = Mock(spec=boto3.Session)
    assumed_session = Mock(spec=boto3.Session)
    sts_client = Mock()

    base_session.client.return_value = sts_client

    sts_client.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "ASIAEXAMPLE",
            "SecretAccessKey": "secret-example",
            "SessionToken": "token-example",
        }
    }

    with patch(
        "scanner.aws.session.boto3.Session",
        side_effect=[base_session, assumed_session],
    ) as mock_session:
        result = create_aws_session(
            profile_name="cloudsentinel",
            region_name="ap-south-1",
            role_arn=(
                "arn:aws:iam::123456789012:"
                "role/CloudSentinelAuditRole"
            ),
            external_id="cloudsentinel-external-id",
        )

    assert result is assumed_session

    base_session.client.assert_called_once_with(
        "sts",
        config=AWS_RETRY_CONFIG,
    )

    sts_client.assume_role.assert_called_once_with(
        RoleArn=(
            "arn:aws:iam::123456789012:"
            "role/CloudSentinelAuditRole"
        ),
        RoleSessionName="CloudSentinelScan",
        ExternalId="cloudsentinel-external-id",
        DurationSeconds=900,
    )

    mock_session.assert_any_call(
        aws_access_key_id="ASIAEXAMPLE",
        aws_secret_access_key="secret-example",
        aws_session_token="token-example",
        region_name="ap-south-1",
    )


def test_create_aws_session_retry_configuration():
    assert isinstance(AWS_RETRY_CONFIG, Config)
    assert AWS_RETRY_CONFIG.retries == {
        "mode": "standard",
        "max_attempts": 5,
    }


def test_create_aws_session_assumes_role_requires_external_id():
    with patch("scanner.aws.session.boto3.Session"):
        try:
            create_aws_session(
                role_arn=(
                    "arn:aws:iam::123456789012:"
                    "role/CloudSentinelAuditRole"
                ),
                region_name="ap-south-1",
            )
            assert False, "Expected ValueError"
        except ValueError as exc:
            assert "external_id is required" in str(exc)


def test_create_aws_session_handles_assume_role_client_error():
    base_session = Mock(spec=boto3.Session)
    sts_client = Mock()

    base_session.client.return_value = sts_client

    sts_client.assume_role.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "Not authorized to assume role",
            }
        },
        "AssumeRole",
    )

    with patch(
        "scanner.aws.session.boto3.Session",
        return_value=base_session,
    ):
        try:
            create_aws_session(
                role_arn=(
                    "arn:aws:iam::123456789012:"
                    "role/CloudSentinelAuditRole"
                ),
            )
            assert False, "Expected RuntimeError"
        except RuntimeError as exc:
            assert "AWS role assumption failed" in str(exc)
            assert "AccessDenied" in str(exc)


def test_create_aws_session_handles_assume_role_boto_core_error():
    base_session = Mock(spec=boto3.Session)
    sts_client = Mock()

    base_session.client.return_value = sts_client
    sts_client.assume_role.side_effect = BotoCoreError()

    with patch(
        "scanner.aws.session.boto3.Session",
        return_value=base_session,
    ):
        try:
            create_aws_session(
                role_arn=(
                    "arn:aws:iam::123456789012:"
                    "role/CloudSentinelAuditRole"
                ),
            )
            assert False, "Expected RuntimeError"
        except RuntimeError as exc:
            assert "AWS SDK error during role assumption" in str(exc)
