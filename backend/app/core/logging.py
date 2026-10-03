from __future__ import annotations

import json
import logging
import os
import sys
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

_request_id: ContextVar[str | None] = ContextVar(
    "cloudsentinel_request_id",
    default=None,
)


def set_request_id(request_id: str):
    return _request_id.set(request_id)


def reset_request_id(token) -> None:
    _request_id.reset(token)


def get_request_id() -> str | None:
    return _request_id.get()


class JsonFormatter(logging.Formatter):
    """Structured JSON formatter suitable for production log ingestion."""

    RESERVED = {
        "args", "asctime", "created", "exc_info", "exc_text",
        "filename", "funcName", "levelname", "levelno", "lineno",
        "message", "module", "msecs", "msg", "name", "pathname",
        "process", "processName", "relativeCreated", "stack_info",
        "taskName", "thread", "threadName",
    }

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=UTC
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        request_id = get_request_id()
        if request_id:
            payload["request_id"] = request_id

        for key, value in record.__dict__.items():
            if key in self.RESERVED or key.startswith("_"):
                continue
            try:
                json.dumps(value)
            except TypeError:
                continue
            payload[key] = value

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
        )


def configure_logging(
    *,
    service: str,
    level: str | None = None,
    log_format: str | None = None,
) -> None:
    """Configure one process-wide handler without duplicating handlers."""
    resolved_level = (level or os.getenv("LOG_LEVEL", "INFO")).upper()
    resolved_format = (
        log_format or os.getenv("LOG_FORMAT", "auto")
    ).lower()

    if resolved_format == "auto":
        resolved_format = (
            "json"
            if os.getenv("APP_ENVIRONMENT", "development").lower()
            == "production"
            else "text"
        )

    formatter: logging.Formatter
    if resolved_format == "json":
        formatter = JsonFormatter()
    else:
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s"
        )

    root = logging.getLogger()
    root.setLevel(resolved_level)

    handler = next(
        (
            existing
            for existing in root.handlers
            if getattr(existing, "_cloudsentinel_handler", False)
        ),
        None,
    )

    if handler is None:
        handler = logging.StreamHandler(sys.stdout)
        handler._cloudsentinel_handler = True
        root.addHandler(handler)

    handler.setFormatter(formatter)
    handler.setLevel(resolved_level)

    logging.getLogger("cloudsentinel").info(
        "Logging configured",
        extra={"service": service, "log_format": resolved_format},
    )
