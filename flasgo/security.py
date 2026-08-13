from __future__ import annotations

import ipaddress
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from .request import Request
from .response import Response
from .session import hmac_digest

_CSRF_TOKEN_VERSION = "v1"
_CSRF_SIGNING_SALT = "flasgo.csrf"


def _format_http_date(value: datetime) -> str:
    return value.strftime("%a, %d %b %Y %H:%M:%S GMT")


_SAME_SITE_VALUES = {"lax": "Lax", "strict": "Strict", "none": "None"}


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
    _validate_cookie_path(path)
    normalized_same_site = _SAME_SITE_VALUES.get(same_site.strip().lower())
    if normalized_same_site is None:
        raise ValueError("Cookie SameSite must be one of 'Lax', 'Strict', or 'None'.")
    if normalized_same_site == "None" and not secure:
        raise ValueError("Cookies with SameSite=None must also set secure=True.")
    chunks = [f"{name}={value}", f"Path={path}", f"SameSite={normalized_same_site}"]
    if max_age is not None:
        expires_at = datetime.now(UTC) + timedelta(seconds=max_age)
        chunks.append(f"Max-Age={max_age}")
        chunks.append(f"Expires={_format_http_date(expires_at)}")
    if secure:
        chunks.append("Secure")
    if http_only:
        chunks.append("HttpOnly")
    return "; ".join(chunks)


def _validate_cookie_path(path: str) -> None:
    if not path:
        raise ValueError("Invalid cookie path: must not be empty.")
    # RFC 6265 allows printable US-ASCII except ';' in cookie paths.
    if ";" in path or any(ord(char) < 0x20 or ord(char) == 0x7F for char in path):
        raise ValueError("Invalid cookie path: contains forbidden characters.")
    try:
        path.encode("latin-1")
    except UnicodeEncodeError as exc:
        raise ValueError("Invalid cookie path: must be Latin-1 encodable.") from exc


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
    csrf_cookie_name: str = "flasgo-csrf"
    csrf_header_name: str = "x-csrf-token"
    csrf_trusted_origins: set[str] = field(default_factory=set)
    csrf_check_origin: bool = True
    csrf_require_origin: bool = True
    csrf_safe_methods: frozenset[str] = field(default_factory=lambda: frozenset({"GET", "HEAD", "OPTIONS", "TRACE"}))
    csrf_cookie_secure: bool = True

    session_cookie_name: str = "flasgo-session"
    session_cookie_max_age: int = 60 * 60 * 24 * 7
    session_cookie_secure: bool = True
    session_cookie_http_only: bool = True
    session_cookie_same_site: str = "Lax"
    enforce_no_store_cache: bool = True

    max_request_body_bytes: int = 1_048_576
    max_request_head_bytes: int = 16_384
    request_read_timeout_seconds: float = 10.0
    max_multipart_parts: int = 1_000
    max_form_fields: int = 1_000
    max_validation_depth: int = 64
    max_validation_work: int = 10_000
    max_validation_issues: int = 100
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
    hostname = _host_header_hostname(host)
    if hostname is None:
        return False
    for pattern in allowed_hosts:
        p = _allowed_host_pattern(pattern)
        if p is None:
            continue
        if p == hostname:
            return True
        if p.startswith(".") and hostname.endswith(p):
            return True
    return False


def _host_header_hostname(host: str | None) -> str | None:
    if host is None:
        return None
    raw = host.strip().lower()
    if not raw or any(char in raw for char in ("\x00", "\r", "\n", "/", "\\", "@")):
        return None
    if raw.startswith("["):
        end = raw.find("]")
        if end <= 1:
            return None
        hostname = raw[1:end]
        remainder = raw[end + 1 :]
        if remainder and (not remainder.startswith(":") or not remainder[1:].isdigit()):
            return None
        return hostname.rstrip(".") or None
    if raw.count(":") > 1:
        return None
    if ":" in raw:
        hostname, port = raw.rsplit(":", 1)
        if not port.isdigit():
            return None
    else:
        hostname = raw
    return hostname.rstrip(".") or None


def _allowed_host_pattern(pattern: str) -> str | None:
    normalized = _host_header_hostname(pattern)
    if normalized is not None:
        return normalized
    raw = pattern.strip().lower().rstrip(".")
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        pass
    if raw.startswith(".") and raw.count(":") == 0:
        return raw
    return None


def ensure_csrf_cookie(
    request: Request,
    response: Response,
    config: SecurityConfig,
    *,
    session_token: str | None = None,
) -> None:
    if session_token is None:
        session_token = request.cookies.get(config.session_cookie_name)
    existing = request.cookies.get(config.csrf_cookie_name)
    if existing and _csrf_token_is_valid(existing, config, session_token=session_token):
        return
    token = _build_csrf_token(config, session_token=session_token)
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
    if not _constant_time_equal(cookie_token, header_token):
        return False
    return _csrf_token_is_valid(
        cookie_token,
        config,
        session_token=request.cookies.get(config.session_cookie_name),
    )


def _build_csrf_token(config: SecurityConfig, *, session_token: str | None) -> str:
    nonce = secrets.token_urlsafe(32)
    signature = _csrf_signature(nonce, config, session_token=session_token)
    return f"{_CSRF_TOKEN_VERSION}.{nonce}.{signature}"


def _csrf_token_is_valid(token: str, config: SecurityConfig, *, session_token: str | None) -> bool:
    try:
        version, nonce, signature = token.split(".")
    except ValueError:
        return False
    if version != _CSRF_TOKEN_VERSION or not nonce or not signature:
        return False
    expected = _csrf_signature(nonce, config, session_token=session_token)
    return _constant_time_equal(signature, expected)


def _csrf_signature(nonce: str, config: SecurityConfig, *, session_token: str | None) -> str:
    binding = session_token or "anonymous"
    payload = f"{_CSRF_TOKEN_VERSION}\x00{nonce}\x00{binding}".encode()
    return hmac_digest(f"{_CSRF_SIGNING_SALT}:{config.secret_key}", payload)


def _constant_time_equal(left: str, right: str) -> bool:
    try:
        return secrets.compare_digest(left.encode("ascii"), right.encode("ascii"))
    except UnicodeEncodeError:
        return False


def apply_security_headers(response: Response, config: SecurityConfig) -> None:
    for key, value in config.security_headers.items():
        if key in {"cache-control", "pragma", "expires"} and response.allow_public_cache:
            continue
        response.headers.setdefault(key, value)
    if config.enforce_no_store_cache and not response.allow_public_cache:
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
            if f"{origin_scheme}://{origin_host}" == normalized:
                return True
            continue
        if origin_host == normalized:
            return True
        if normalized.startswith(".") and origin_host.split(":", 1)[0].endswith(normalized):
            return True
    return False


def websocket_origin_is_allowed(
    origin_value: str,
    *,
    request_scheme: str,
    request_host: str,
    allowed_origins: set[str],
) -> bool:
    """Validate a WebSocket Origin using exact origins only."""

    candidate = _canonical_origin(origin_value)
    if candidate is None:
        return False
    same_origin = _canonical_origin(f"{request_scheme}://{request_host}")
    if candidate == same_origin:
        return True
    return candidate in {_canonical_origin(item) for item in allowed_origins}


def _canonical_origin(value: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlsplit(value.strip())
        port = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    if (
        scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        return None
    return scheme, parsed.hostname.lower(), port or (443 if scheme == "https" else 80)
