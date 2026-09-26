from unittest.mock import Mock

from scanner.aws.scanners.firehose import FirehoseScanner


def test_scanner_returns_finding_for_unencrypted_stream():
    service = Mock()
    service.list_delivery_streams.return_value = [
        "insecure-stream"
    ]
    service.describe_delivery_stream.return_value = {
        "DeliveryStreamName": "insecure-stream",
        "DeliveryStreamEncryptionConfiguration": {
            "Status": "DISABLED",
        },
    }

    scanner = FirehoseScanner(service)

    findings = scanner.scan()

    assert any(
        finding.rule_id == "CS-AWS-FIREHOSE-001"
        for finding in findings
    )


def test_scanner_does_not_find_encrypted_stream():
    service = Mock()
    service.list_delivery_streams.return_value = [
        "secure-stream"
    ]
    service.describe_delivery_stream.return_value = {
        "DeliveryStreamName": "secure-stream",
        "DeliveryStreamEncryptionConfiguration": {
            "Status": "ENABLED",
        },
    }

    scanner = FirehoseScanner(service)

    findings = scanner.scan()

    assert not any(
        finding.rule_id == "CS-AWS-FIREHOSE-001"
        for finding in findings
    )
