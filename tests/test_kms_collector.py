from unittest.mock import MagicMock

from scanner.aws.collectors.kms import KMSDataCollector


def test_collect_kms_keys_normalizes_customer_managed_key():
    service = MagicMock()

    service.list_keys.return_value = [
        {"KeyId": "key-1"},
    ]

    service.describe_key.return_value = {
        "KeyId": "key-1",
        "Arn": "arn:aws:kms:us-east-1:123456789012:key/key-1",
        "Description": "test",
        "KeyManager": "CUSTOMER",
        "KeyState": "Enabled",
        "KeyUsage": "ENCRYPT_DECRYPT",
        "KeySpec": "SYMMETRIC_DEFAULT",
        "Origin": "AWS_KMS",
        "MultiRegion": False,
    }

    service.get_key_rotation_status.return_value = True

    service.get_key_policy.return_value = {
        "policy": '{"Version":"2012-10-17","Statement":[]}',
        "policy_name": "default",
    }

    collector = KMSDataCollector(service)

    result = collector.collect_keys()

    assert result == [
        {
            "key_id": "key-1",
            "key_arn": (
                "arn:aws:kms:us-east-1:123456789012:key/key-1"
            ),
            "description": "test",
            "key_manager": "CUSTOMER",
            "key_state": "Enabled",
            "key_usage": "ENCRYPT_DECRYPT",
            "key_spec": "SYMMETRIC_DEFAULT",
            "origin": "AWS_KMS",
            "multi_region": False,
            "deletion_date": None,
            "valid_to": None,
            "rotation_enabled": True,
            "key_policy": {
                "policy": '{"Version":"2012-10-17","Statement":[]}',
                "policy_name": "default",
            },
        }
    ]


def test_collect_kms_keys_does_not_query_rotation_for_aws_managed_key():
    service = MagicMock()

    service.list_keys.return_value = [{"KeyId": "key-1"}]

    service.describe_key.return_value = {
        "KeyId": "key-1",
        "KeyManager": "AWS",
        "KeyState": "Enabled",
    }

    service.get_key_policy.return_value = None

    collector = KMSDataCollector(service)

    result = collector.collect_keys()

    assert result[0]["rotation_enabled"] is None
    service.get_key_rotation_status.assert_not_called()
