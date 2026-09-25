import io
import json
import logging
from collections.abc import Iterator

import pytest
from flasgo.logging import configure_logging, log_event


@pytest.fixture(autouse=True)
def restore_flasgo_logger() -> Iterator[None]:
    """configure_logging mutates the process-wide ``flasgo`` logger, so restore it after every test."""
    logger = logging.getLogger("flasgo")
    handlers, level, propagate = list(logger.handlers), logger.level, logger.propagate
    yield
    logger.handlers[:] = handlers
    logger.setLevel(level)
    logger.propagate = propagate


def _raise_and_log(name: str) -> None:
    try:
        raise ZeroDivisionError("boom")
    except ZeroDivisionError:
        logging.getLogger(name).debug("background task exception", exc_info=True)


def test_text_formatter_includes_tracebacks() -> None:
    stream = io.StringIO()
    configure_logging(format="text", level="DEBUG", stream=stream)

    _raise_and_log("flasgo.background")

    output = stream.getvalue()
    assert output.startswith("debug background task exception\nTraceback (most recent call last):")
    assert "ZeroDivisionError: boom" in output


def test_json_formatter_includes_tracebacks_and_event_fields() -> None:
    stream = io.StringIO()
    configure_logging(format="json", level="DEBUG", stream=stream)

    _raise_and_log("flasgo.background")
    log_event(logging.getLogger("flasgo.access"), logging.INFO, "http-request", route="/a\nb", status=200)

    first, second = (json.loads(line) for line in stream.getvalue().splitlines())
    assert "ZeroDivisionError: boom" in first["exception"]
    assert second["event"] == "http-request"
    assert second["route"] == "/a\\nb"
    assert second["status"] == 200


@pytest.mark.parametrize("level", ["info", " Debug ", "WARNING"])
def test_log_level_names_are_case_insensitive(level: str) -> None:
    logger = configure_logging(level=level, stream=io.StringIO())
    assert logger.level == logging.getLevelName(level.strip().upper())


def test_reconfiguring_logging_rebinds_the_stream() -> None:
    first, second = io.StringIO(), io.StringIO()
    configure_logging(stream=first)
    configure_logging(stream=second)

    logging.getLogger("flasgo.test").info("hello")

    assert first.getvalue() == ""
    assert second.getvalue() == "info hello\n"


def test_invalid_log_format_is_rejected() -> None:
    with pytest.raises(ValueError, match="LOG_FORMAT must be 'text' or 'json'"):
        configure_logging(format="xml")
