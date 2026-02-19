from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from .request import Request
from .response import Response


def _format_http_date(value: datetime) -> str:
    return value.strftime("%a, %d %b %Y %H:%M:%S GMT")


def build_set_cookie(
    name: str,
    value: str,
    *,
    max_age: int | None = None,
    secure: bool = True,
    http_only: bool = True,
    same_site: str = "Lax",
    path: str = "/",
) -> str:
    _validate_cookie_part(name, part="name")
    _validate_cookie_part(value, part="value")
    chunks = [f"{name}={value}", f"Path={path}", f"SameSite={same_site}"]
    if max_age is not None:
        expires_at = datetime.now(UTC) + timedelta(seconds=max_age)
        chunks.append(f"Max-Age={max_age}")
        chunks.append(f"Expires={_format_http_date(expires_at)}")
    if secure:
        chunks.append("Secure")
    if http_only:
        chunks.append("HttpOnly")
    return "; ".join(chunks)


def _default_secret_key() -> str:
    return secrets.token_urlsafe(48)


def _validate_cookie_part(value: str, *, part: str) -> None:
    if any(char in value for char in ("\r", "\n", "\x00")):
        msg = f"Invalid cookie {part}: contains control characters."
        raise ValueError(msg)
    if part == "name" and any(char in value for char in (";", "=", " ")):
        msg = "Invalid cookie name: contains forbidden separators."
        raise ValueError(msg)
    if part == "value" and any(char in value for char in (";", ",", " ", "\t")):
        msg = "Invalid cookie value: contains forbidden separators."
        raise ValueError(msg)


@dataclass(slots=True)
class SecurityConfig:
    allowed_hosts: set[str] = field(default_factory=lambda: {"127.0.0.1", "localhost"})
    enforce_allowed_hosts: bool = True

    csrf_enabled: bool = True
    csrf_cookie_name: str = "fango-csrf"
    csrf_header_name: str = "x-csrf-token"
    csrf_trusted_origins: set[str] = field(default_factory=set)
    csrf_check_origin: bool = True
    csrf_require_origin: bool = True
    csrf_safe_methods: frozenset[str] = field(default_factory=lambda: frozenset({"GET", "HEAD", "OPTIONS", "TRACE"}))
    csrf_cookie_secure: bool = True

    session_cookie_name: str = "fango-session"
    session_cookie_max_age: int = 60 * 60 * 24 * 7
    session_cookie_secure: bool = True
    session_cookie_http_only: bool = True
    session_cookie_same_site: str = "Lax"
    enforce_no_store_cache: bool = True

    max_request_body_bytes: int = 1_048_576
    max_request_head_bytes: int = 16_384
    request_read_timeout_seconds: float = 10.0
    security_failure_rate_limit: int = 50
    security_failure_window_seconds: int = 60
    log_security_events: bool = True

    security_headers: dict[str, str] = field(
        default_factory=lambda: {
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "strict-origin-when-cross-origin",
            "x-xss-protection": "0",
            "permissions-policy": "camera=(), microphone=(), geolocation=()",
            "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
            "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            "cache-control": "no-store, no-cache, must-revalidate, max-age=0",
            "pragma": "no-cache",
            "expires": "0",
        }
    )

    secret_key: str = field(default_factory=_default_secret_key)


def host_is_allowed(host: str | None, *, allowed_hosts: set[str]) -> bool:
    if host is None:
        return False
    hostname = host.split(":", 1)[0].strip().lower()
    for pattern in allowed_hosts:
        p = pattern.lower()
        if p == hostname:
            return True
        if p.startswith(".") and hostname.endswith(p):
            return True
    return False


def ensure_csrf_cookie(request: Request, response: Response, config: SecurityConfig) -> None:
    existing = request.cookies.get(config.csrf_cookie_name)
    if existing:
        return
    token = secrets.token_urlsafe(32)
    response.cookies.append(
        build_set_cookie(
            config.csrf_cookie_name,
            token,
            secure=config.csrf_cookie_secure,
            http_only=False,
            same_site="Lax",
        )
    )


def csrf_is_valid(request: Request, config: SecurityConfig) -> bool:
    if request.method in config.csrf_safe_methods:
        return True
    if config.csrf_check_origin and not _csrf_origin_is_valid(request, config):
        return False
    cookie_token = request.cookies.get(config.csrf_cookie_name)
    header_token = request.headers.get(config.csrf_header_name.lower())
    if not cookie_token or not header_token:
        return False
    return secrets.compare_digest(cookie_token, header_token)


def apply_security_headers(response: Response, config: SecurityConfig) -> None:
    for key, value in config.security_headers.items():
        response.headers.setdefault(key, value)
    if config.enforce_no_store_cache:
        response.headers["cache-control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["pragma"] = "no-cache"
        response.headers["expires"] = "0"


def _csrf_origin_is_valid(request: Request, config: SecurityConfig) -> bool:
    origin = request.headers.get("origin")
    if origin:
        return _origin_matches_request(origin, request, config)
    referer = request.headers.get("referer")
    if referer:
        return _origin_matches_request(referer, request, config)
    return not config.csrf_require_origin


def _origin_matches_request(origin_value: str, request: Request, config: SecurityConfig) -> bool:
    parsed = urlsplit(origin_value)
    if not parsed.scheme or not parsed.netloc:
        return False
    origin_scheme = parsed.scheme.lower()
    origin_host = parsed.netloc.lower()
    request_scheme = request.scheme
    request_host = (request.headers.get("host") or "").strip().lower()
    if request_host and origin_host == request_host and origin_scheme == request_scheme:
        return True
    for trusted in config.csrf_trusted_origins:
        normalized = trusted.strip().lower()
        if "://" in normalized:
            if f"{parsed.scheme}://{origin_host}" == normalized:
                return True
            continue
        if origin_host == normalized:
            return True
        if normalized.startswith(".") and origin_host.split(":", 1)[0].endswith(normalized):
            return True
    return False
