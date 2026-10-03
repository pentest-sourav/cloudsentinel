import json
import logging

from backend.app.core.logging import (
    JsonFormatter,
    configure_logging,
    get_request_id,
    reset_request_id,
    set_request_id,
)


def test_json_formatter_emits_structured_fields():
    token = set_request_id("request-123")
    try:
        record = logging.LogRecord(
            name="cloudsentinel.test",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="scan started",
            args=(),
            exc_info=None,
        )
        record.scan_id = 42
        rendered = JsonFormatter().format(record)
    finally:
        reset_request_id(token)

    payload = json.loads(rendered)
    assert payload["level"] == "INFO"
    assert payload["logger"] == "cloudsentinel.test"
    assert payload["message"] == "scan started"
    assert payload["request_id"] == "request-123"
    assert payload["scan_id"] == 42
    assert payload["timestamp"]


def test_request_id_context_can_be_set_and_reset():
    assert get_request_id() is None
    token = set_request_id("request-456")
    assert get_request_id() == "request-456"
    reset_request_id(token)
    assert get_request_id() is None


def test_configure_logging_is_idempotent():
    configure_logging(service="test", level="INFO", log_format="json")
    configure_logging(service="test", level="INFO", log_format="json")

    handlers = [
        handler
        for handler in logging.getLogger().handlers
        if getattr(handler, "_cloudsentinel_handler", False)
    ]
    assert len(handlers) == 1
