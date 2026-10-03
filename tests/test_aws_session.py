from unittest.mock import Mock, patch

import pytest

from scanner.aws.session import create_aws_session


ROLE_ARN = "arn:aws:iam::123456789012:role/CloudSentinelAuditRole"
EXTERNAL_ID = "cloudsentinel-test-external-id"


def test_create_aws_session_uses_short_lived_external_id_assume_role():
    base_session = Mock()
    sts = Mock()
    sts.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "ASIAEXAMPLE",
            "SecretAccessKey": "secret",
            "SessionToken": "token",
        }
    }
    base_session.client.return_value = sts
    assumed_session = Mock()

    with patch(
        "scanner.aws.session.boto3.Session",
        side_effect=[base_session, assumed_session],
    ):
        result = create_aws_session(
            role_arn=ROLE_ARN,
            external_id=EXTERNAL_ID,
            region_name="ap-south-1",
            role_session_name="CloudSentinelScan-42",
            duration_seconds=900,
        )

    sts.assume_role.assert_called_once_with(
        RoleArn=ROLE_ARN,
        RoleSessionName="CloudSentinelScan-42",
        DurationSeconds=900,
        ExternalId=EXTERNAL_ID,
    )

    assert result is assumed_session


@pytest.mark.parametrize("duration_seconds", [899, 43_201])
def test_create_aws_session_rejects_invalid_sts_duration(duration_seconds):
    with pytest.raises(
        ValueError,
        match="duration_seconds must be between 900 and 43200 seconds",
    ):
        create_aws_session(
            role_arn=ROLE_ARN,
            external_id=EXTERNAL_ID,
            duration_seconds=duration_seconds,
        )


def test_create_aws_session_requires_external_id_for_role_assumption():
    with pytest.raises(
        ValueError,
        match="external_id is required",
    ):
        create_aws_session(
            role_arn=ROLE_ARN,
            external_id=None,
        )


def test_create_aws_session_preserves_normal_boto3_chain_without_role():
    session = Mock()

    with patch(
        "scanner.aws.session.boto3.Session",
        return_value=session,
    ) as session_factory:
        result = create_aws_session(region_name="ap-south-1")

    session_factory.assert_called_once_with(
        profile_name=None,
        region_name="ap-south-1",
    )
    assert result is session
