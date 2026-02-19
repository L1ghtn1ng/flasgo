from __future__ import annotations

import importlib
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, cast

from .security import SecurityConfig


def _default_security_headers() -> dict[str, str]:
    return {
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "strict-origin-when-cross-origin",
        "x-xss-protection": "0",
        "permissions-policy": "camera=(), microphone=(), geolocation=()",
        "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    }


@dataclass
class Settings:
    DEBUG: bool = False
    SECRET_KEY: str = field(default_factory=lambda: secrets.token_urlsafe(48))

    ALLOWED_HOSTS: set[str] = field(default_factory=lambda: {"127.0.0.1", "localhost"})
    ENFORCE_ALLOWED_HOSTS: bool = True

    CSRF_ENABLED: bool = True
    CSRF_COOKIE_NAME: str = "fango-csrf"
    CSRF_HEADER_NAME: str = "x-csrf-token"
    CSRF_TRUSTED_ORIGINS: set[str] = field(default_factory=set)
    CSRF_CHECK_ORIGIN: bool = True
    CSRF_REQUIRE_ORIGIN: bool = True
    CSRF_COOKIE_SECURE: bool = True

    SESSION_COOKIE_NAME: str = "fango-session"
    SESSION_COOKIE_MAX_AGE: int = 60 * 60 * 24 * 7
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_HTTP_ONLY: bool = True
    SESSION_COOKIE_SAME_SITE: str = "Lax"
    ENFORCE_NO_STORE_CACHE: bool = True
    MAX_REQUEST_BODY_BYTES: int = 1_048_576
    MAX_REQUEST_HEAD_BYTES: int = 16_384
    REQUEST_READ_TIMEOUT_SECONDS: float = 10.0
    SECURITY_FAILURE_RATE_LIMIT: int = 50
    SECURITY_FAILURE_WINDOW_SECONDS: int = 60
    LOG_SECURITY_EVENTS: bool = True
    ENABLE_DOCS: bool = False
    DOCS_PATH: str = "/docs"
    OPENAPI_PATH: str = "/openapi.json"
    API_TITLE: str = "Fango API"
    API_VERSION: str = "0.1.0"
    API_DESCRIPTION: str = ""
    SSRF_ENABLED: bool = True
    SSRF_ALLOWED_SCHEMES: set[str] = field(default_factory=lambda: {"http", "https"})
    SSRF_ALLOWED_HOSTS: set[str] = field(default_factory=set)
    SSRF_ALLOW_PRIVATE_NETWORKS: bool = False
    SSRF_ALLOW_USERINFO: bool = False
    SSRF_ALLOW_UNRESOLVABLE_HOSTS: bool = False

    SECURITY_HEADERS: dict[str, str] = field(default_factory=_default_security_headers)
    EXTRA: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_security_config(self) -> SecurityConfig:
        return SecurityConfig(
            allowed_hosts=set(self.ALLOWED_HOSTS),
            enforce_allowed_hosts=self.ENFORCE_ALLOWED_HOSTS,
            csrf_enabled=self.CSRF_ENABLED,
            csrf_cookie_name=self.CSRF_COOKIE_NAME,
            csrf_header_name=self.CSRF_HEADER_NAME,
            csrf_trusted_origins=set(self.CSRF_TRUSTED_ORIGINS),
            csrf_check_origin=self.CSRF_CHECK_ORIGIN,
            csrf_require_origin=self.CSRF_REQUIRE_ORIGIN,
            csrf_cookie_secure=self.CSRF_COOKIE_SECURE,
            session_cookie_name=self.SESSION_COOKIE_NAME,
            session_cookie_max_age=self.SESSION_COOKIE_MAX_AGE,
            session_cookie_secure=self.SESSION_COOKIE_SECURE,
            session_cookie_http_only=self.SESSION_COOKIE_HTTP_ONLY,
            session_cookie_same_site=self.SESSION_COOKIE_SAME_SITE,
            enforce_no_store_cache=self.ENFORCE_NO_STORE_CACHE,
            max_request_body_bytes=self.MAX_REQUEST_BODY_BYTES,
            max_request_head_bytes=self.MAX_REQUEST_HEAD_BYTES,
            request_read_timeout_seconds=self.REQUEST_READ_TIMEOUT_SECONDS,
            security_failure_rate_limit=self.SECURITY_FAILURE_RATE_LIMIT,
            security_failure_window_seconds=self.SECURITY_FAILURE_WINDOW_SECONDS,
            log_security_events=self.LOG_SECURITY_EVENTS,
            security_headers=dict(self.SECURITY_HEADERS),
            secret_key=self.SECRET_KEY,
        )

    @classmethod
    def from_mapping(cls, values: Mapping[str, Any]) -> Settings:
        known = {field_name for field_name in cls.__dataclass_fields__ if field_name != "EXTRA"}
        mapped: dict[str, Any] = {}
        extra: dict[str, Any] = {}
        for key, value in values.items():
            if key in known:
                mapped[key] = value
            else:
                extra[key] = value
        config = cls(**mapped)
        config.EXTRA = extra
        return config

    @classmethod
    def from_object(cls, obj: object) -> Settings:
        values: dict[str, Any] = {}
        for name in dir(obj):
            if name.isupper():
                values[name] = getattr(obj, name)
        return cls.from_mapping(values)

    def get(self, key: str, default: Any = None) -> Any:
        if hasattr(self, key):
            return getattr(self, key)
        return self.EXTRA.get(key, default)


type SettingsInput = Settings | Mapping[str, Any] | str | object


def load_settings(source: SettingsInput | None) -> Settings:
    if source is None:
        return Settings()
    if isinstance(source, Settings):
        return source
    if isinstance(source, Mapping):
        return Settings.from_mapping(cast(Mapping[str, Any], source))
    if isinstance(source, str):
        module = importlib.import_module(source)
        return Settings.from_object(module)
    return Settings.from_object(source)
