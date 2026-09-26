"""Helpers shared by several test modules."""

from typing import Any

from flasgo import Flasgo

METRICS_TOKEN = "metrics-test-token-" + "m" * 32


def extract_cookie(set_cookie_header: str, name: str) -> str | None:
    """Return a cookie's value from newline-joined Set-Cookie headers, or ``None``."""
    for line in set_cookie_header.split("\n"):
        raw = line.strip()
        if raw.startswith(f"{name}="):
            return raw.split(";", 1)[0].split("=", 1)[1]
    return None


def metrics_app(**settings: Any) -> Flasgo:
    """Build a metrics-enabled app with CSRF disabled and overridable settings."""
    return Flasgo(settings={"CSRF_ENABLED": False, "METRICS_ENABLED": True, "METRICS_BEARER_TOKEN": METRICS_TOKEN, **settings})
