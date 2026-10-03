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
        DurationSeconds=900,
        ExternalId="cloudsentinel-external-id",
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


def test_create_aws_session_requires_external_id_for_role_assumption():
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


def test_create_aws_session_rejects_invalid_duration():
    with patch("scanner.aws.session.boto3.Session"):
        for duration in (899, 43_201):
            try:
                create_aws_session(
                    role_arn=(
                        "arn:aws:iam::123456789012:"
                        "role/CloudSentinelAuditRole"
                    ),
                    external_id="cloudsentinel-external-id",
                    duration_seconds=duration,
                )
                assert False, "Expected ValueError"
            except ValueError as exc:
                assert "duration_seconds must be an integer between 900 and 43200 seconds." in str(exc)


def test_create_aws_session_rejects_blank_or_long_session_name():
    with patch("scanner.aws.session.boto3.Session"):
        for session_name in ("", " " , "x" * 65):
            try:
                create_aws_session(
                    role_arn=(
                        "arn:aws:iam::123456789012:"
                        "role/CloudSentinelAuditRole"
                    ),
                    external_id="cloudsentinel-external-id",
                    role_session_name=session_name,
                )
                assert False, "Expected ValueError"
            except ValueError:
                pass


def test_create_aws_session_uses_configured_duration():
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
    ), patch(
        "scanner.aws.session.settings.aws_sts_session_duration_seconds",
        1800,
    ):
        result = create_aws_session(
            role_arn=(
                "arn:aws:iam::123456789012:"
                "role/CloudSentinelAuditRole"
            ),
            external_id="cloudsentinel-external-id",
        )

    assert result is assumed_session
    sts_client.assume_role.assert_called_once_with(
        RoleArn=(
            "arn:aws:iam::123456789012:"
            "role/CloudSentinelAuditRole"
        ),
        RoleSessionName="CloudSentinelScan",
        DurationSeconds=1800,
        ExternalId="cloudsentinel-external-id",
    )


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
                external_id="cloudsentinel-external-id",
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
                external_id="cloudsentinel-external-id",
            )
            assert False, "Expected RuntimeError"
        except RuntimeError as exc:
            assert "AWS SDK error during role assumption" in str(exc)


def test_create_aws_session_rejects_invalid_role_session_name_characters():
    with patch("scanner.aws.session.boto3.Session"):
        try:
            create_aws_session(
                role_arn=(
                    "arn:aws:iam::123456789012:"
                    "role/CloudSentinelAuditRole"
                ),
                external_id="cloudsentinel-external-id",
                role_session_name="CloudSentinel Scan!",
            )
            assert False, "Expected ValueError"
        except ValueError as exc:
            assert "unsupported AWS STS characters" in str(exc)
