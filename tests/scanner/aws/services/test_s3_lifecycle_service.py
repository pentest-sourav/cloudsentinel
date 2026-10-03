from unittest.mock import Mock

import boto3
from botocore.exceptions import ClientError

from scanner.aws.services.s3 import S3Service


def test_get_bucket_lifecycle_configuration():
    fake_session = Mock(spec=boto3.Session)
    fake_s3 = Mock()
    fake_s3.get_bucket_lifecycle_configuration.return_value = {
        "Rules": [
            {"ID": "retention", "Status": "Enabled"}
        ]
    }
    fake_session.client.return_value = fake_s3

    service = S3Service(fake_session)

    config = service.get_bucket_lifecycle_configuration("bucket-a")

    assert config == {
        "Rules": [
            {"ID": "retention", "Status": "Enabled"}
        ]
    }
    fake_s3.get_bucket_lifecycle_configuration.assert_called_once_with(
        Bucket="bucket-a"
    )


def test_get_bucket_lifecycle_configuration_when_missing():
    fake_session = Mock(spec=boto3.Session)
    fake_s3 = Mock()
    fake_s3.get_bucket_lifecycle_configuration.side_effect = ClientError(
        {
            "Error": {
                "Code": "NoSuchLifecycleConfiguration",
                "Message": "The lifecycle configuration does not exist",
            }
        },
        "GetBucketLifecycleConfiguration",
    )
    fake_session.client.return_value = fake_s3

    service = S3Service(fake_session)

    assert service.get_bucket_lifecycle_configuration("bucket-a") == {}
