from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

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
    if not authorization_header.startswith(prefix):
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

    return backend
