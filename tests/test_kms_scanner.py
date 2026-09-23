from unittest.mock import MagicMock

from scanner.aws.scanners.kms import KMSScanner


def test_kms_scanner_executes_registry():
    service = MagicMock()

    service.list_keys.return_value = [
        {"KeyId": "key-1"},
    ]

    service.describe_key.return_value = {
        "KeyId": "key-1",
        "Arn": "arn:aws:kms:us-east-1:123456789012:key/key-1",
        "KeyManager": "CUSTOMER",
        "KeyState": "Enabled",
    }

    service.get_key_rotation_status.return_value = False

    service.get_key_policy.return_value = {
        "policy": {
            "Version": "2012-10-17",
            "Statement": [],
        },
        "policy_name": "default",
    }

    scanner = KMSScanner(service)

    findings = scanner.scan()

    assert len(findings) == 1
    assert findings[0].rule_id == "CS-AWS-KMS-001"
