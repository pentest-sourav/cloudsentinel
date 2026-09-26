from engine.rules.aws.firehose.protection import (
    check_firehose_encryption,
)


def test_encrypted_stream_passes():
    resource = {
        "delivery_stream_name": "secure-stream",
        "encryption_status": "ENABLED",
    }

    assert check_firehose_encryption(
        **resource
    ) is None


def test_unencrypted_stream_fails():
    resource = {
        "delivery_stream_name": "insecure-stream",
        "encryption_status": "DISABLED",
    }

    result = check_firehose_encryption(
        **resource
    )

    assert result is not None
    assert result.delivery_stream_name == "insecure-stream"
    assert result.evidence["encryption_status"] == "DISABLED"


def test_enabling_state_is_detected():
    resource = {
        "delivery_stream_name": "stream",
        "encryption_status": "ENABLING",
    }

    result = check_firehose_encryption(
        **resource
    )

    assert result is not None


def test_failed_encryption_state_is_detected():
    resource = {
        "delivery_stream_name": "stream",
        "encryption_status": "ENABLING_FAILED",
    }

    result = check_firehose_encryption(
        **resource
    )

    assert result is not None


def test_missing_encryption_status_does_not_create_false_positive():
    resource = {
        "delivery_stream_name": "unknown-stream",
        "encryption_status": None,
    }

    assert check_firehose_encryption(
        **resource
    ) is None
