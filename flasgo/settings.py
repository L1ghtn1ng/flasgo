import importlib
import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, cast

from .security import (
    SecurityConfig,
    StrictBoolFields,
    allowed_host_pattern,
    canonical_origin,
    default_secret_key,
    default_security_headers,
    validate_cookie_name,
)


@dataclass
class Settings(StrictBoolFields):
    DEBUG: bool = False
    SECRET_KEY: str = field(default_factory=default_secret_key)

    ALLOWED_HOSTS: set[str] = field(default_factory=lambda: {"127.0.0.1", "localhost"})
    ENFORCE_ALLOWED_HOSTS: bool = True

    CSRF_ENABLED: bool = True
    CSRF_COOKIE_NAME: str = "flasgo-csrf"
    CSRF_HEADER_NAME: str = "x-csrf-token"
    CSRF_TRUSTED_ORIGINS: set[str] = field(default_factory=set)
    CSRF_CHECK_ORIGIN: bool = True
    CSRF_REQUIRE_ORIGIN: bool = True
    CSRF_COOKIE_SECURE: bool = True

    SESSION_COOKIE_NAME: str = "flasgo-session"
    SESSION_COOKIE_MAX_AGE: int = 60 * 60 * 24 * 7
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_HTTP_ONLY: bool = True
    SESSION_COOKIE_SAME_SITE: str = "Lax"
    ENFORCE_NO_STORE_CACHE: bool = True
    MAX_REQUEST_BODY_BYTES: int = 1_048_576
    MAX_REQUEST_HEAD_BYTES: int = 16_384
    REQUEST_READ_TIMEOUT_SECONDS: float = 10.0
    MAX_MULTIPART_PARTS: int = 1_000
    MAX_FORM_FIELDS: int = 1_000
    MAX_VALIDATION_DEPTH: int = 64
    MAX_VALIDATION_WORK: int = 10_000
    MAX_VALIDATION_ISSUES: int = 100
    SECURITY_FAILURE_RATE_LIMIT: int = 50
    SECURITY_FAILURE_WINDOW_SECONDS: int = 60
    LOG_SECURITY_EVENTS: bool = True
    TRUST_INCOMING_REQUEST_ID: bool = False
    LOG_FORMAT: str = "text"
    LOG_LEVEL: str = "INFO"
    WEBSOCKET_ENFORCE_ORIGIN: bool = True
    WEBSOCKET_ALLOWED_ORIGINS: set[str] = field(default_factory=set)
    WEBSOCKET_ALLOW_MISSING_ORIGIN: bool = False
    WEBSOCKET_MAX_MESSAGE_BYTES: int = 65_536
    WEBSOCKET_MAX_MESSAGES_PER_MINUTE: int = 120
    SERVER_LIMIT_CONCURRENCY: int = 1_000
    METRICS_ENABLED: bool = False
    METRICS_PATH: str = "/metrics"
    METRICS_BEARER_TOKEN: str | None = None
    METRICS_EVENT_LOOP_ENABLED: bool = True
    METRICS_EVENT_LOOP_INTERVAL_SECONDS: float = 0.1
    OTEL_ENABLED: bool = False
    OTEL_SERVICE_NAME: str = "flasgo"
    OTEL_SERVICE_VERSION: str | None = None
    OTEL_TRACE_SAMPLE_RATIO: float = 1.0
    OTEL_EXCLUDED_PATHS: set[str] = field(default_factory=set)
    OTEL_SET_GLOBAL_PROVIDER: bool = True
    ENABLE_DOCS: bool = False
    DOCS_AUTH_BACKEND: str | None = None
    DOCS_PATH: str = "/docs"
    OPENAPI_PATH: str = "/openapi.json"
    API_TITLE: str = "Flasgo API"
    API_VERSION: str = "0.9.1"
    API_DESCRIPTION: str = ""
    API_SERVERS: list[str] = field(default_factory=list)
    SSRF_ENABLED: bool = True
    SSRF_ALLOWED_SCHEMES: set[str] = field(default_factory=lambda: {"http", "https"})
    SSRF_ALLOWED_HOSTS: set[str] = field(default_factory=set)
    SSRF_ALLOW_PRIVATE_NETWORKS: bool = False
    SSRF_ALLOW_USERINFO: bool = False
    SSRF_ALLOW_UNRESOLVABLE_HOSTS: bool = False
    SSRF_RESOLUTION_TIMEOUT_SECONDS: float | None = 5.0

    SECURITY_HEADERS: dict[str, str] = field(default_factory=default_security_headers)
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
            max_multipart_parts=self.MAX_MULTIPART_PARTS,
            max_form_fields=self.MAX_FORM_FIELDS,
            max_validation_depth=self.MAX_VALIDATION_DEPTH,
            max_validation_work=self.MAX_VALIDATION_WORK,
            max_validation_issues=self.MAX_VALIDATION_ISSUES,
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
        # Only settings fields, not methods such as ``get`` or ``to_security_config``.
        if key in self.__dataclass_fields__:
            return getattr(self, key)
        return self.EXTRA.get(key, default)


type SettingsInput = Settings | Mapping[str, Any] | str | object


def load_settings(source: SettingsInput | None) -> Settings:
    """Load and validate settings from an instance, mapping, module name, or object."""
    if source is None:
        return Settings()
    if isinstance(source, Settings):
        source._validate_boolean_fields()
        return source
    if isinstance(source, Mapping):
        return Settings.from_mapping(cast(Mapping[str, Any], source))
    if isinstance(source, str):
        module = importlib.import_module(source)
        return Settings.from_object(module)
    return Settings.from_object(source)


_INSECURE_SENTINEL = "dev-insecure-secret-change-this"
_BEARER_TOKEN_RE = re.compile(r"^[A-Za-z0-9._~+/-]+=*$")


def validate_app_config(settings: Settings, security: SecurityConfig) -> None:
    """Reject invalid settings and security configuration before the application serves requests."""
    if not security.secret_key:
        raise ValueError("SECRET_KEY must be configured. Set it to a long random value before starting Flasgo.")
    if security.secret_key == _INSECURE_SENTINEL:
        raise ValueError("SECRET_KEY uses an insecure default value. Replace it with a unique random secret.")
    if len(security.secret_key) < 32:
        raise ValueError("SECRET_KEY must be at least 32 characters.")
    same_site = security.session_cookie_same_site.strip().lower()
    if same_site not in {"lax", "strict", "none"}:
        raise ValueError("SESSION_COOKIE_SAME_SITE must be one of 'Lax', 'Strict', or 'None'.")
    if same_site == "none" and not security.session_cookie_secure:
        raise ValueError("SESSION_COOKIE_SAME_SITE='None' requires SESSION_COOKIE_SECURE=True.")
    validate_cookie_name(security.session_cookie_name)
    validate_cookie_name(security.csrf_cookie_name)
    max_age = security.session_cookie_max_age
    if isinstance(max_age, bool) or not isinstance(max_age, int) or max_age <= 0:
        # Zero or negative values make every session cookie expire immediately.
        raise ValueError("SESSION_COOKIE_MAX_AGE must be a positive number of seconds.")
    for pattern in security.allowed_hosts:
        if not isinstance(pattern, str) or allowed_host_pattern(pattern) is None:
            raise ValueError(
                f"ALLOWED_HOSTS entry {pattern!r} is not a hostname, IP address, or '.suffix' pattern. "
                "Wildcards such as '*' are not supported; list each host or use '.example.com'."
            )
    if security.max_request_body_bytes <= 0:
        raise ValueError("MAX_REQUEST_BODY_BYTES must be greater than 0.")
    if security.max_request_head_bytes <= 0:
        raise ValueError("MAX_REQUEST_HEAD_BYTES must be greater than 0.")
    if security.request_read_timeout_seconds <= 0:
        raise ValueError("REQUEST_READ_TIMEOUT_SECONDS must be greater than 0.")
    if security.max_multipart_parts <= 0:
        raise ValueError("MAX_MULTIPART_PARTS must be greater than 0.")
    if security.max_form_fields <= 0:
        raise ValueError("MAX_FORM_FIELDS must be greater than 0.")
    ssrf_timeout = settings.SSRF_RESOLUTION_TIMEOUT_SECONDS
    if ssrf_timeout is not None and ssrf_timeout <= 0:
        raise ValueError("SSRF_RESOLUTION_TIMEOUT_SECONDS must be greater than 0 or None.")
    if security.max_validation_depth <= 0:
        raise ValueError("MAX_VALIDATION_DEPTH must be greater than 0.")
    if security.max_validation_work <= 0:
        raise ValueError("MAX_VALIDATION_WORK must be greater than 0.")
    if security.max_validation_issues < 2:
        raise ValueError("MAX_VALIDATION_ISSUES must be at least 2.")
    if security.security_failure_window_seconds <= 0:
        raise ValueError("SECURITY_FAILURE_WINDOW_SECONDS must be greater than 0.")
    if not settings.SSRF_ALLOWED_SCHEMES:
        raise ValueError("SSRF_ALLOWED_SCHEMES must not be empty. Include at least one scheme such as 'https'.")
    if not isinstance(settings.OTEL_SERVICE_NAME, str) or not settings.OTEL_SERVICE_NAME.strip():
        raise ValueError("OTEL_SERVICE_NAME must not be empty.")
    if settings.OTEL_SERVICE_VERSION is not None and not isinstance(settings.OTEL_SERVICE_VERSION, str):
        raise ValueError("OTEL_SERVICE_VERSION must be a string or None.")
    if (
        isinstance(settings.OTEL_TRACE_SAMPLE_RATIO, bool)
        or not isinstance(settings.OTEL_TRACE_SAMPLE_RATIO, int | float)
        or not 0 <= settings.OTEL_TRACE_SAMPLE_RATIO <= 1
    ):
        raise ValueError("OTEL_TRACE_SAMPLE_RATIO must be between 0 and 1 inclusive.")
    if any(not isinstance(path, str) or not path.startswith("/") for path in settings.OTEL_EXCLUDED_PATHS):
        raise ValueError("Every OTEL_EXCLUDED_PATHS entry must start with '/'.")
    if not settings.DOCS_PATH.startswith("/"):
        raise ValueError("DOCS_PATH must start with '/'. Example: '/docs'.")
    if not settings.OPENAPI_PATH.startswith("/"):
        raise ValueError("OPENAPI_PATH must start with '/'. Example: '/openapi.json'.")
    if settings.DOCS_PATH == settings.OPENAPI_PATH:
        raise ValueError("DOCS_PATH and OPENAPI_PATH must be different so each endpoint has its own URL.")
    if settings.DOCS_AUTH_BACKEND is not None and (
        not isinstance(settings.DOCS_AUTH_BACKEND, str) or not settings.DOCS_AUTH_BACKEND.strip()
    ):
        raise ValueError("DOCS_AUTH_BACKEND must be a non-empty registered backend name or None.")
    if any(not isinstance(url, str) or not url.strip() for url in settings.API_SERVERS):
        raise ValueError("API_SERVERS entries must be non-empty URL strings.")
    if settings.LOG_FORMAT.strip().lower() not in {"text", "json"}:
        raise ValueError("LOG_FORMAT must be 'text' or 'json'.")
    if settings.LOG_LEVEL.upper() not in logging.getLevelNamesMapping():
        raise ValueError("LOG_LEVEL must be a standard Python logging level such as INFO or WARNING.")
    if settings.WEBSOCKET_MAX_MESSAGE_BYTES <= 0:
        raise ValueError("WEBSOCKET_MAX_MESSAGE_BYTES must be greater than 0.")
    if settings.WEBSOCKET_MAX_MESSAGES_PER_MINUTE <= 0:
        raise ValueError("WEBSOCKET_MAX_MESSAGES_PER_MINUTE must be greater than 0.")
    if settings.SERVER_LIMIT_CONCURRENCY <= 0:
        raise ValueError("SERVER_LIMIT_CONCURRENCY must be greater than 0.")
    for origin in settings.WEBSOCKET_ALLOWED_ORIGINS:
        if canonical_origin(origin) is None:
            raise ValueError("WEBSOCKET_ALLOWED_ORIGINS entries must be exact http:// or https:// origins without paths.")
    for entry in security.csrf_trusted_origins:
        if not _valid_csrf_trusted_origin(entry):
            # An entry that can never match would otherwise silently reject every request from that origin.
            raise ValueError(
                f"CSRF_TRUSTED_ORIGINS entry {entry!r} is not supported. Use an http(s) origin such as "
                "'https://partner.example', a wildcard such as 'https://*.example.com', a host, or a '.example.com' suffix."
            )
    if not settings.METRICS_PATH.startswith("/"):
        raise ValueError("METRICS_PATH must start with '/'.")
    if not isinstance(settings.METRICS_EVENT_LOOP_ENABLED, bool):
        raise ValueError("METRICS_EVENT_LOOP_ENABLED must be a boolean.")
    interval = settings.METRICS_EVENT_LOOP_INTERVAL_SECONDS
    if isinstance(interval, bool) or not isinstance(interval, int | float) or not 0.01 <= interval <= 60:
        raise ValueError("METRICS_EVENT_LOOP_INTERVAL_SECONDS must be between 0.01 and 60.")
    if settings.METRICS_ENABLED:
        token = settings.METRICS_BEARER_TOKEN
        if not isinstance(token, str) or len(token) < 32 or _BEARER_TOKEN_RE.fullmatch(token) is None:
            raise ValueError("METRICS_BEARER_TOKEN must contain at least 32 bearer-safe ASCII characters when metrics are enabled.")
        if settings.METRICS_PATH in {settings.DOCS_PATH, settings.OPENAPI_PATH}:
            raise ValueError("METRICS_PATH must not conflict with DOCS_PATH or OPENAPI_PATH.")


def _valid_csrf_trusted_origin(entry: object) -> bool:
    """Accept only the entry forms that CSRF origin matching understands."""
    if not isinstance(entry, str):
        return False
    text = entry.strip().lower()
    if "://" not in text:
        return allowed_host_pattern(text) is not None
    scheme, _, authority = text.partition("://")
    authority = authority.removeprefix("*.")
    return canonical_origin(f"{scheme}://{authority}") is not None
