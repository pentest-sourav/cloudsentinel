from unittest.mock import Mock

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.provider import AWSProvider


def test_verify_identity():
    fake_session = Mock(spec=boto3.Session)
    fake_sts = Mock()

    fake_sts.get_caller_identity.return_value = {
        "Account": "123456789012",
        "Arn": "arn:aws:iam::123456789012:user/test-user",
    }

    fake_session.client.return_value = fake_sts

    provider = AWSProvider(fake_session)

    identity = provider.verify_identity()

    assert identity.provider == "aws"
    assert identity.account_id == "123456789012"
    assert identity.display_name == (
        "arn:aws:iam::123456789012:user/test-user"
    )

    fake_sts.get_caller_identity.assert_called_once()


def test_verify_identity_handles_client_error():
    fake_session = Mock(spec=boto3.Session)
    fake_sts = Mock()

    fake_sts.get_caller_identity.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "User is not authorized",
            }
        },
        "GetCallerIdentity",
    )

    fake_session.client.return_value = fake_sts

    provider = AWSProvider(fake_session)

    try:
        provider.verify_identity()
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        assert "AWS identity verification failed" in str(exc)
        assert "AccessDenied" in str(exc)


def test_verify_identity_handles_boto_core_error():
    fake_session = Mock(spec=boto3.Session)
    fake_sts = Mock()

    fake_sts.get_caller_identity.side_effect = BotoCoreError()

    fake_session.client.return_value = fake_sts

    provider = AWSProvider(fake_session)

    try:
        provider.verify_identity()
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        assert "AWS SDK error during identity verification" in str(exc)
