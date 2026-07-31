from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from typing import Any, TextIO

_FIELD_RE = re.compile(r"[^a-zA-Z0-9_.:/@+\\-]")
_OWNED_HANDLER = "_flasgo_owned_handler"
_STANDARD_RECORD_FIELDS = frozenset(logging.makeLogRecord({}).__dict__)


def sanitize_log_value(value: object, *, limit: int = 256) -> str:
    raw = "" if value is None else str(value)
    escaped = raw.replace("\r", r"\r").replace("\n", r"\n").replace("\x00", r"\0")
    normalized = _FIELD_RE.sub("?", escaped)
    return normalized[:limit]


class FlasgoJSONFormatter(logging.Formatter):
    """Format bounded Flasgo event fields as one JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key in _STANDARD_RECORD_FIELDS or key.startswith("_"):
                continue
            payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=False, default=str)


class _FlasgoTextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        pieces = [record.getMessage()]
        for key in (
            "event",
            "request_id",
            "method",
            "route",
            "status",
            "client",
            "duration_ms",
            "outcome",
            "close_code",
        ):
            value = getattr(record, key, None)
            if value is not None:
                pieces.append(f"{key}={value}")
        return f"{record.levelname.lower()} {' '.join(pieces)}"


def configure_logging(
    *,
    format: str = "text",
    level: str | int = "INFO",
    stream: TextIO | None = None,
) -> logging.Logger:
    """Configure only the ``flasgo`` logger hierarchy."""

    normalized = format.strip().lower()
    if normalized not in {"text", "json"}:
        raise ValueError("LOG_FORMAT must be 'text' or 'json'.")
    logger = logging.getLogger("flasgo")
    logger.setLevel(level)
    handler = next((item for item in logger.handlers if getattr(item, _OWNED_HANDLER, False)), None)
    if handler is None:
        handler = logging.StreamHandler(stream)
        setattr(handler, _OWNED_HANDLER, True)
        logger.addHandler(handler)
    handler.setLevel(level)
    handler.setFormatter(FlasgoJSONFormatter() if normalized == "json" else _FlasgoTextFormatter())
    logger.propagate = False
    return logger


def log_event(
    logger: logging.Logger,
    level: int,
    event: str,
    **fields: object,
) -> None:
    safe_fields: dict[str, object] = {"event": sanitize_log_value(event, limit=64)}
    for key, value in fields.items():
        if value is None:
            continue
        if isinstance(value, (int, float, bool)):
            safe_fields[key] = value
        else:
            safe_fields[key] = sanitize_log_value(value)
    logger.log(level, safe_fields["event"], extra=safe_fields)
