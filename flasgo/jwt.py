from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from .auth import AuthBackend, AuthResult, User, extract_bearer_token, set_auth_backend_openapi_scheme
from .request import Request

_RESERVED_CLAIMS = frozenset({"alg", "aud", "exp", "iat", "iss", "nbf", "scope", "sub"})
_FORBIDDEN_SCOPE_CLAIMS = frozenset({"alg", "aud", "exp", "iat", "iss", "jti", "nbf", "sub"})


def jwt_backend(
    secret: str | bytes,
    *,
    issuer: str,
    audience: str,
    leeway: float = 0,
    scope_claim: str = "scope",
) -> AuthBackend:
    """Build a strict HS256 bearer authentication backend."""

    _validate_scope_claim(scope_claim)
    jwt = _load_pyjwt()
    key = _validate_configuration(secret, issuer=issuer, audience=audience, leeway=leeway)

    async def backend(request: Request) -> AuthResult:
        token = extract_bearer_token(request.headers.get("authorization"))
        if token is None:
            return AuthResult(user=None, challenge="Bearer")
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=["HS256"],
                audience=audience,
                issuer=issuer,
                leeway=leeway,
                options={"require": ["aud", "exp", "iat", "iss", "sub"]},
            )
            subject = claims.get("sub")
            if not isinstance(subject, str) or not subject:
                return AuthResult(user=None, challenge="Bearer")
            scopes = _normalize_scopes(claims.get(scope_claim, ()))
            if scopes is None:
                return AuthResult(user=None, challenge="Bearer")
        except jwt.PyJWTError, TypeError, ValueError:
            return AuthResult(user=None, challenge="Bearer")
        return AuthResult(
            user=User(id=subject, is_authenticated=True, scopes=scopes, data=dict(claims)),
            challenge=None,
        )

    set_auth_backend_openapi_scheme(
        backend,
        {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
    )
    return backend


def encode_jwt(
    subject: str,
    secret: str | bytes,
    *,
    issuer: str,
    audience: str,
    expires_in: int = 900,
    scopes: Iterable[str] = (),
    scope_claim: str = "scope",
    additional_claims: Mapping[str, Any] | None = None,
) -> str:
    """Encode a short-lived HS256 token accepted by :func:`jwt_backend`."""

    _validate_scope_claim(scope_claim)
    jwt = _load_pyjwt()
    key = _validate_configuration(secret, issuer=issuer, audience=audience, leeway=0)
    if not subject:
        raise ValueError("JWT subject must not be empty.")
    if expires_in <= 0:
        raise ValueError("JWT expires_in must be greater than 0 seconds.")
    normalized_scopes = frozenset(str(scope).strip() for scope in scopes)
    if "" in normalized_scopes:
        raise ValueError("JWT scopes must not contain empty values.")
    extra = dict(additional_claims or {})
    conflict = (_RESERVED_CLAIMS | {scope_claim}).intersection(extra)
    if conflict:
        raise ValueError(f"JWT additional_claims cannot override reserved claims: {', '.join(sorted(conflict))}.")
    now = datetime.now(UTC)
    claims: dict[str, Any] = {
        **extra,
        "sub": subject,
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(seconds=expires_in),
    }
    if normalized_scopes:
        claims[scope_claim] = " ".join(sorted(normalized_scopes))
    return str(jwt.encode(claims, key, algorithm="HS256"))


def _validate_configuration(
    secret: str | bytes,
    *,
    issuer: str,
    audience: str,
    leeway: float,
) -> bytes:
    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    if len(key) < 32:
        raise ValueError("JWT HS256 secrets must contain at least 32 bytes.")
    if not issuer:
        raise ValueError("JWT issuer must not be empty.")
    if not audience:
        raise ValueError("JWT audience must not be empty.")
    if leeway < 0:
        raise ValueError("JWT leeway must not be negative.")
    return key


def _validate_scope_claim(scope_claim: str) -> None:
    if not isinstance(scope_claim, str) or not scope_claim:
        raise ValueError("JWT scope_claim must not be empty.")
    if scope_claim in _FORBIDDEN_SCOPE_CLAIMS:
        raise ValueError(f"JWT scope_claim {scope_claim!r} conflicts with a reserved or registered JWT claim.")


def _normalize_scopes(value: object) -> frozenset[str] | None:
    if isinstance(value, str):
        return frozenset(item for item in value.split() if item)
    if isinstance(value, list | tuple | set) and all(isinstance(item, str) and item for item in value):
        return frozenset(cast(Iterable[str], value))
    if value is None or value == ():
        return frozenset()
    return None


def _load_pyjwt() -> Any:
    try:
        import jwt
    except ImportError as exc:
        raise RuntimeError("JWT helpers require the optional dependency. Install Flasgo with `flasgo[jwt]`.") from exc
    return jwt
