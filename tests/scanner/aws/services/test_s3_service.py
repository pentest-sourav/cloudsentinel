from unittest.mock import Mock

import boto3
from botocore.exceptions import ClientError

from scanner.aws.services.s3 import S3Service


def test_list_buckets():
    fake_session = Mock(spec=boto3.Session)
    fake_s3 = Mock()

    fake_s3.list_buckets.return_value = {
        "Buckets": [
            {
                "Name": "cloudsentinel-test-bucket",
                "CreationDate": "2026-09-16T10:00:00Z",
            },
            {
                "Name": "cloudsentinel-logs",
                "CreationDate": "2026-09-15T10:00:00Z",
            },
        ]
    }

    fake_session.client.return_value = fake_s3

    service = S3Service(fake_session)

    buckets = service.list_buckets()

    assert len(buckets) == 2

    assert buckets[0]["name"] == "cloudsentinel-test-bucket"
    assert buckets[0]["creation_date"] == "2026-09-16T10:00:00Z"

    assert buckets[1]["name"] == "cloudsentinel-logs"
    assert buckets[1]["creation_date"] == "2026-09-15T10:00:00Z"

    fake_s3.list_buckets.assert_called_once()


def test_get_public_access_block():
    fake_session = Mock(spec=boto3.Session)
    fake_s3 = Mock()

    fake_s3.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    }

    fake_session.client.return_value = fake_s3

    service = S3Service(fake_session)

    config = service.get_public_access_block(
        "cloudsentinel-test-bucket"
    )

    assert config == {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }

    fake_s3.get_public_access_block.assert_called_once_with(
        Bucket="cloudsentinel-test-bucket"
    )


def test_get_public_access_block_when_configuration_is_missing():
    fake_session = Mock(spec=boto3.Session)
    fake_s3 = Mock()

    fake_s3.get_public_access_block.side_effect = ClientError(
        {
            "Error": {
                "Code": "NoSuchPublicAccessBlockConfiguration",
                "Message": "The public access block configuration was not found",
            }
        },
        "GetPublicAccessBlock",
    )

    fake_session.client.return_value = fake_s3

    service = S3Service(fake_session)

    config = service.get_public_access_block(
        "cloudsentinel-no-config"
    )

    assert config == {}

    fake_s3.get_public_access_block.assert_called_once_with(
        Bucket="cloudsentinel-no-config"
    )


def test_get_public_access_block_handles_other_client_error():
    fake_session = Mock(spec=boto3.Session)
    fake_s3 = Mock()

    fake_s3.get_public_access_block.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "Access denied",
            }
        },
        "GetPublicAccessBlock",
    )

    fake_session.client.return_value = fake_s3

    service = S3Service(fake_session)

    try:
        service.get_public_access_block(
            "cloudsentinel-private-bucket"
        )
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        assert "S3 Public Access Block check failed" in str(exc)
        assert "AccessDenied" in str(exc)
