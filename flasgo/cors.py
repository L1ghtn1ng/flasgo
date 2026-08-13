from __future__ import annotations

import ipaddress
import re
from collections.abc import Collection
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .request import Request
from .response import Response

_HTTP_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_DNS_HOST_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?$"
)
_CORS_RESPONSE_HEADER_PREFIX = "access-control-"
_FORBIDDEN_EXPOSE_HEADERS = frozenset({"set-cookie", "set-cookie2"})


@dataclass(frozen=True, slots=True)
class CORSConfig:
    """Explicit cross-origin response-sharing policy for one or more HTTP routes."""

    allow_origins: Collection[str]
    allow_methods: Collection[str] = field(default_factory=lambda: frozenset({"GET", "HEAD"}))
    allow_headers: Collection[str] = field(default_factory=frozenset)
    expose_headers: Collection[str] = field(default_factory=frozenset)
    allow_credentials: bool = False
    max_age: int = 600

    def __post_init__(self) -> None:
        origins = _normalize_allowed_origins(self.allow_origins)
        methods = _normalize_methods(self.allow_methods)
        allow_headers = _normalize_header_names(self.allow_headers, setting="allow_headers")
        expose_headers = _normalize_header_names(self.expose_headers, setting="expose_headers")

        if "*" in allow_headers or "*" in expose_headers:
            raise ValueError("CORS header wildcards are not supported. List each allowed or exposed header explicitly.")
        forbidden_exposed = expose_headers & _FORBIDDEN_EXPOSE_HEADERS
        if forbidden_exposed:
            raise ValueError("CORS expose_headers cannot include Set-Cookie or Set-Cookie2.")
        if not isinstance(self.allow_credentials, bool):
            raise TypeError("CORS allow_credentials must be True or False.")
        if self.allow_credentials and "*" in origins:
            raise ValueError("CORS wildcard origins cannot be combined with allow_credentials=True.")
        if isinstance(self.max_age, bool) or not isinstance(self.max_age, int) or not 0 <= self.max_age <= 86_400:
            raise ValueError("CORS max_age must be an integer between 0 and 86400 seconds.")

        object.__setattr__(self, "allow_origins", origins)
        object.__setattr__(self, "allow_methods", methods)
        object.__setattr__(self, "allow_headers", allow_headers)
        object.__setattr__(self, "expose_headers", expose_headers)

    @property
    def allows_any_origin(self) -> bool:
        return "*" in self.allow_origins

    def allows_origin(self, origin: str) -> bool:
        return self.allows_any_origin or origin in self.allow_origins

    def allows_method(self, method: str) -> bool:
        return method.upper() in self.allow_methods

    def allows_headers(self, headers: Collection[str]) -> bool:
        return all(header.lower() in self.allow_headers for header in headers)


@dataclass(frozen=True, slots=True)
class _CORSPreflight:
    origin: str | None
    method: str | None
    headers: frozenset[str]
    error: str | None = None


def _parse_cors_preflight(request: Request) -> _CORSPreflight | None:
    if request.method != "OPTIONS":
        return None

    origins = _scope_header_values(request, b"origin")
    requested_methods = _scope_header_values(request, b"access-control-request-method")
    if not origins or not requested_methods:
        return None
    if len(origins) != 1 or len(requested_methods) != 1:
        return _CORSPreflight(None, None, frozenset(), "duplicate control header")

    origin = _normalize_request_origin(origins[0])
    method = requested_methods[0].strip()
    if origin is None:
        return _CORSPreflight(None, None, frozenset(), "invalid origin")
    if not _HTTP_TOKEN_RE.fullmatch(method):
        return _CORSPreflight(origin, None, frozenset(), "invalid requested method")

    requested_headers = _scope_header_values(request, b"access-control-request-headers")
    parsed_headers: set[str] = set()
    for value in requested_headers:
        parts = value.split(",")
        if not parts or any(not part.strip() for part in parts):
            return _CORSPreflight(origin, method.upper(), frozenset(), "invalid requested header")
        for part in parts:
            header = part.strip().lower()
            if not _HTTP_TOKEN_RE.fullmatch(header) or header == "*":
                return _CORSPreflight(origin, method.upper(), frozenset(), "invalid requested header")
            parsed_headers.add(header)

    return _CORSPreflight(origin, method.upper(), frozenset(parsed_headers))


def _build_cors_preflight_response(config: CORSConfig, preflight: _CORSPreflight) -> Response:
    if preflight.error is not None or preflight.origin is None or preflight.method is None:
        return _cors_preflight_denied_response(status_code=400)

    headers: dict[str, str] = {}
    _add_vary(headers, "Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers")
    if not config.allows_origin(preflight.origin):
        return Response.text("CORS preflight denied.", status_code=403, headers=headers)
    if not config.allows_method(preflight.method) or not config.allows_headers(preflight.headers):
        _set_cors_origin_headers(headers, config, preflight.origin)
        return Response.text("CORS preflight denied.", status_code=403, headers=headers)

    _set_cors_origin_headers(headers, config, preflight.origin)
    headers["access-control-allow-methods"] = preflight.method
    if preflight.headers:
        headers["access-control-allow-headers"] = ", ".join(sorted(preflight.headers))
    headers["access-control-max-age"] = str(config.max_age)
    response = Response(body=b"", status_code=204, headers=headers, allow_public_cache=True)
    response.headers.pop("content-type", None)
    return response


def _cors_preflight_denied_response(*, status_code: int = 403) -> Response:
    headers: dict[str, str] = {}
    _add_vary(headers, "Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers")
    return Response.text("CORS preflight denied.", status_code=status_code, headers=headers)


def _apply_cors_response_headers(request: Request, response: Response, config: CORSConfig) -> None:
    for name in list(response.headers):
        if name.lower().startswith(_CORS_RESPONSE_HEADER_PREFIX):
            del response.headers[name]

    _add_vary(response.headers, "Origin")
    if not config.allows_method(request.method):
        return

    origins = _scope_header_values(request, b"origin")
    if len(origins) != 1:
        return
    origin = _normalize_request_origin(origins[0])
    if origin is None or not config.allows_origin(origin):
        return

    _set_cors_origin_headers(response.headers, config, origin)
    if config.expose_headers:
        response.headers["access-control-expose-headers"] = ", ".join(sorted(config.expose_headers))


def _set_cors_origin_headers(headers: dict[str, str], config: CORSConfig, origin: str) -> None:
    headers["access-control-allow-origin"] = "*" if config.allows_any_origin else origin
    if config.allow_credentials:
        headers["access-control-allow-credentials"] = "true"


def _normalize_allowed_origins(values: Collection[str]) -> frozenset[str]:
    if isinstance(values, str):
        raise TypeError("CORS allow_origins must be a collection of origins, not one string.")
    normalized: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            raise TypeError("Every CORS allow_origins entry must be a string.")
        if value == "*":
            normalized.add(value)
            continue
        origin = _canonical_origin(value)
        if origin is None:
            raise ValueError(
                "CORS allow_origins entries must be exact ASCII http:// or https:// origins without paths."
            )
        normalized.add(origin)
    if not normalized:
        raise ValueError("CORS allow_origins must contain at least one exact origin or '*'.")
    if "*" in normalized and len(normalized) != 1:
        raise ValueError("CORS wildcard origin '*' must be the only allow_origins entry.")
    return frozenset(normalized)


def _normalize_methods(values: Collection[str]) -> frozenset[str]:
    if isinstance(values, str):
        raise TypeError("CORS allow_methods must be a collection of method names, not one string.")
    normalized: set[str] = set()
    for value in values:
        if not isinstance(value, str) or not _HTTP_TOKEN_RE.fullmatch(value):
            raise ValueError("Every CORS allow_methods entry must be a valid HTTP method token.")
        if value == "*":
            raise ValueError("CORS allow_methods does not support '*'. List each allowed method explicitly.")
        normalized.add(value.upper())
    if not normalized:
        raise ValueError("CORS allow_methods must contain at least one HTTP method.")
    if "GET" in normalized:
        normalized.add("HEAD")
    return frozenset(normalized)


def _normalize_header_names(values: Collection[str], *, setting: str) -> frozenset[str]:
    if isinstance(values, str):
        raise TypeError(f"CORS {setting} must be a collection of header names, not one string.")
    normalized: set[str] = set()
    for value in values:
        if not isinstance(value, str) or not _HTTP_TOKEN_RE.fullmatch(value):
            raise ValueError(f"Every CORS {setting} entry must be a valid HTTP header name.")
        normalized.add(value.lower())
    return frozenset(normalized)


def _normalize_request_origin(value: str) -> str | None:
    if value in {"*", "null"}:
        return None
    return _canonical_origin(value)


def _canonical_origin(value: str) -> str | None:
    if not value or value != value.strip() or not value.isascii():
        return None
    if any(character in value for character in ("\x00", "\r", "\n", "\\", "%")):
        return None
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname
    if (
        scheme not in {"http", "https"}
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        return None
    host = hostname.lower()
    if not host or any(character.isspace() for character in host):
        return None
    try:
        host = ipaddress.ip_address(host).compressed
    except ValueError:
        if _DNS_HOST_RE.fullmatch(host) is None:
            return None
    if ":" in host:
        host = f"[{host}]"
    default_port = 443 if scheme == "https" else 80
    authority = host if port is None or port == default_port else f"{host}:{port}"
    return f"{scheme}://{authority}"


def _scope_header_values(request: Request, name: bytes) -> list[str]:
    return [
        value.decode("latin-1")
        for key, value in request.scope.get("headers", [])
        if isinstance(key, bytes) and isinstance(value, bytes) and key.lower() == name
    ]


def _add_vary(headers: dict[str, str], *names: str) -> None:
    vary_keys = [key for key in headers if key.lower() == "vary"]
    current = [item.strip() for key in vary_keys for item in headers[key].split(",") if item.strip()]
    for key in vary_keys:
        del headers[key]
    if "*" in current:
        headers["vary"] = "*"
        return
    existing = {item.lower() for item in current}
    for name in names:
        if name.lower() not in existing:
            current.append(name)
            existing.add(name.lower())
    headers["vary"] = ", ".join(current)
