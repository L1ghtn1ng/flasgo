from __future__ import annotations

import copy
import inspect
import json
import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlsplit

from .request import Request


@dataclass(slots=True)
class User:
    id: str | None = None
    is_authenticated: bool = False
    scopes: frozenset[str] = frozenset()
    data: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def anonymous(cls) -> User:
        return cls()


@dataclass(slots=True, frozen=True)
class AuthResult:
    user: User | None = None
    challenge: str | None = None


type AuthIdentity = User | None | AuthResult
type AuthBackend = Callable[[Request], AuthIdentity | Awaitable[AuthIdentity]]
type PermissionCallable = Callable[[Request, User], bool | Awaitable[bool]]
type TokenValidator = Callable[[str], User | None | Awaitable[User | None]]
_OPENAPI_SCHEME_ATTR = "__flasgo_openapi_security_scheme__"
_OPENAPI_COMPONENT_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_HTTP_AUTH_SCHEME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_SECURITY_SCHEME_COMMON_FIELDS = {"type", "description", "deprecated"}
_SECURITY_SCHEME_TYPE_FIELDS = {
    "apiKey": {"name", "in"},
    "http": {"scheme", "bearerFormat"},
    "mutualTLS": set(),
    "oauth2": {"flows", "oauth2MetadataUrl"},
    "openIdConnect": {"openIdConnectUrl"},
}
_OAUTH_FLOW_FIELDS = {
    "implicit": {"authorizationUrl", "refreshUrl", "scopes"},
    "password": {"tokenUrl", "refreshUrl", "scopes"},
    "clientCredentials": {"tokenUrl", "refreshUrl", "scopes"},
    "authorizationCode": {"authorizationUrl", "tokenUrl", "refreshUrl", "scopes"},
    "deviceAuthorization": {"deviceAuthorizationUrl", "tokenUrl", "refreshUrl", "scopes"},
}
_OAUTH_REQUIRED_FLOW_FIELDS = {
    "implicit": {"authorizationUrl", "scopes"},
    "password": {"tokenUrl", "scopes"},
    "clientCredentials": {"tokenUrl", "scopes"},
    "authorizationCode": {"authorizationUrl", "tokenUrl", "scopes"},
    "deviceAuthorization": {"deviceAuthorizationUrl", "tokenUrl", "scopes"},
}


@runtime_checkable
class Permission(Protocol):
    def has_permission(self, request: Request, user: User) -> bool | Awaitable[bool]: ...


type PermissionLike = Permission | PermissionCallable


class AllowAny:
    def has_permission(self, request: Request, user: User) -> bool:
        return True


class IsAuthenticated:
    def has_permission(self, request: Request, user: User) -> bool:
        return user.is_authenticated


@dataclass(slots=True, frozen=True)
class HasScope:
    scope: str

    def has_permission(self, request: Request, user: User) -> bool:
        return self.scope in user.scopes


def extract_bearer_token(authorization_header: str | None, *, scheme: str = "Bearer") -> str | None:
    if not authorization_header:
        return None
    prefix = f"{scheme.strip()} "
    if authorization_header[: len(prefix)].lower() != prefix.lower():
        return None
    token = authorization_header[len(prefix) :].strip()
    return token or None


def bearer_token_backend(
    validate_token: TokenValidator,
    *,
    scheme: str = "Bearer",
) -> AuthBackend:
    normalized_scheme = scheme.strip() or "Bearer"

    async def backend(request: Request) -> AuthResult:
        token = extract_bearer_token(
            request.headers.get("authorization"),
            scheme=normalized_scheme,
        )
        if token is None:
            return AuthResult(user=None, challenge=normalized_scheme)

        resolved = validate_token(token)
        candidate = await resolved if inspect.isawaitable(resolved) else resolved
        if not isinstance(candidate, User):
            return AuthResult(user=None, challenge=normalized_scheme)
        return AuthResult(user=candidate, challenge=None)

    if _HTTP_AUTH_SCHEME_RE.fullmatch(normalized_scheme):
        set_auth_backend_openapi_scheme(
            backend,
            {"type": "http", "scheme": normalized_scheme.lower()},
        )
    return backend


def set_auth_backend_openapi_scheme(backend: AuthBackend, scheme: dict[str, Any]) -> None:
    """Attach validated OpenAPI metadata to a Flasgo authentication backend."""

    setattr(backend, _OPENAPI_SCHEME_ATTR, copy.deepcopy(scheme))


def auth_backend_openapi_scheme(backend: AuthBackend) -> dict[str, Any] | None:
    value = getattr(backend, _OPENAPI_SCHEME_ATTR, None)
    return copy.deepcopy(value) if isinstance(value, dict) else None


def validate_openapi_security_scheme(name: str, scheme: Mapping[str, object]) -> dict[str, Any]:
    """Validate and copy a local OpenAPI 3.2 Security Scheme Object."""

    if not _OPENAPI_COMPONENT_NAME_RE.fullmatch(name):
        raise ValueError("OpenAPI security scheme names may contain only letters, digits, '.', '-', and '_'.")
    if not isinstance(scheme, Mapping):
        raise TypeError("openapi_scheme must be a mapping containing a local Security Scheme Object.")
    copied = copy.deepcopy(dict(scheme))
    try:
        json.dumps(copied, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("openapi_scheme must contain only finite JSON-compatible values.") from exc
    if "$ref" in copied:
        raise ValueError("openapi_scheme must be a local Security Scheme Object; $ref is not supported.")

    scheme_type = copied.get("type")
    if not isinstance(scheme_type, str) or scheme_type not in _SECURITY_SCHEME_TYPE_FIELDS:
        supported = ", ".join(sorted(_SECURITY_SCHEME_TYPE_FIELDS))
        raise ValueError(f"openapi_scheme.type must be one of: {supported}.")
    allowed = _SECURITY_SCHEME_COMMON_FIELDS | _SECURITY_SCHEME_TYPE_FIELDS[scheme_type]
    _reject_unknown_fields(copied, allowed=allowed, context="openapi_scheme")
    _optional_string(copied, "description", context="openapi_scheme", allow_empty=True)
    if "deprecated" in copied and not isinstance(copied["deprecated"], bool):
        raise ValueError("openapi_scheme.deprecated must be a boolean.")

    if scheme_type == "apiKey":
        _required_string(copied, "name", context="openapi_scheme")
        location = _required_string(copied, "in", context="openapi_scheme")
        if location not in {"query", "header", "cookie"}:
            raise ValueError("openapi_scheme.in must be 'query', 'header', or 'cookie' for an apiKey scheme.")
    elif scheme_type == "http":
        http_scheme = _required_string(copied, "scheme", context="openapi_scheme")
        if _HTTP_AUTH_SCHEME_RE.fullmatch(http_scheme) is None:
            raise ValueError("openapi_scheme.scheme must be a valid RFC 9110 HTTP token.")
        _optional_string(copied, "bearerFormat", context="openapi_scheme")
        if "bearerFormat" in copied and http_scheme.lower() != "bearer":
            raise ValueError("openapi_scheme.bearerFormat is valid only when scheme is 'bearer'.")
    elif scheme_type == "oauth2":
        if "oauth2MetadataUrl" in copied:
            _require_https_url(copied["oauth2MetadataUrl"], field="openapi_scheme.oauth2MetadataUrl")
        _validate_oauth_flows(copied.get("flows"))
    elif scheme_type == "openIdConnect":
        _require_https_url(copied.get("openIdConnectUrl"), field="openapi_scheme.openIdConnectUrl")
    return copied


def _validate_oauth_flows(value: object) -> None:
    if not isinstance(value, Mapping):
        raise ValueError("openapi_scheme.flows must be a mapping for an oauth2 scheme.")
    flows = dict(value)
    _reject_unknown_fields(flows, allowed=set(_OAUTH_FLOW_FIELDS), context="openapi_scheme.flows")
    for flow_name, flow_value in flows.items():
        if flow_name.startswith("x-"):
            continue
        if not isinstance(flow_value, Mapping):
            raise ValueError(f"openapi_scheme.flows.{flow_name} must be a mapping.")
        flow = dict(flow_value)
        context = f"openapi_scheme.flows.{flow_name}"
        _reject_unknown_fields(flow, allowed=_OAUTH_FLOW_FIELDS[flow_name], context=context)
        missing = sorted(_OAUTH_REQUIRED_FLOW_FIELDS[flow_name] - flow.keys())
        if missing:
            raise ValueError(f"{context} is missing required fields: {', '.join(missing)}.")
        scopes = flow.get("scopes")
        if not isinstance(scopes, Mapping) or any(
            not isinstance(scope, str) or not isinstance(description, str) for scope, description in scopes.items()
        ):
            raise ValueError(f"{context}.scopes must map string scope names to string descriptions.")
        for field_name in ("authorizationUrl", "deviceAuthorizationUrl", "tokenUrl", "refreshUrl"):
            if field_name in flow:
                _require_https_url(flow[field_name], field=f"{context}.{field_name}")


def _reject_unknown_fields(value: Mapping[str, object], *, allowed: set[str], context: str) -> None:
    invalid_keys = sorted(
        str(key) for key in value if not isinstance(key, str) or (key not in allowed and not key.startswith("x-"))
    )
    if invalid_keys:
        raise ValueError(f"{context} contains unsupported fields: {', '.join(invalid_keys)}.")


def _required_string(value: Mapping[str, object], field: str, *, context: str) -> str:
    candidate = value.get(field)
    if not isinstance(candidate, str) or not candidate.strip():
        raise ValueError(f"{context}.{field} must be a non-empty string.")
    return candidate


def _optional_string(
    value: Mapping[str, object],
    field: str,
    *,
    context: str,
    allow_empty: bool = False,
) -> None:
    if field not in value:
        return
    candidate = value[field]
    if not isinstance(candidate, str) or (not allow_empty and not candidate.strip()):
        qualifier = "a string" if allow_empty else "a non-empty string"
        raise ValueError(f"{context}.{field} must be {qualifier}.")


def _require_https_url(value: object, *, field: str) -> None:
    if not isinstance(value, str) or any(char.isspace() or ord(char) == 127 for char in value):
        raise ValueError(f"{field} must be an absolute HTTPS URL.")
    parsed = urlsplit(value)
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(f"{field} must be an absolute HTTPS URL.") from exc
    invalid = (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.netloc.endswith(":")
    )
    if invalid:
        raise ValueError(f"{field} must be an absolute HTTPS URL without embedded credentials.")
