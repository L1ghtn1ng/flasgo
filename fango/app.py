from __future__ import annotations

import asyncio
import inspect
import logging
import time
from collections.abc import Awaitable, Callable, Iterable
from contextvars import ContextVar
from typing import Any

from .auth import AuthBackend, AuthIdentity, AuthResult, IsAuthenticated, Permission, PermissionLike, User
from .exceptions import HTTPException
from .openapi import build_openapi_spec
from .request import Request
from .response import Response, ResponseValue, to_response
from .routing import Endpoint, MatchResult, Route
from .security import (
    SecurityConfig,
    apply_security_headers,
    build_set_cookie,
    csrf_is_valid,
    ensure_csrf_cookie,
    host_is_allowed,
)
from .server import run_dev_server
from .session import Session, SessionSigner
from .settings import SettingsInput, load_settings
from .ssrf import SSRFConfig, SSRFGuard
from .types import Receive, Scope, Send

BeforeMiddleware = Callable[[Request], ResponseValue | Awaitable[ResponseValue] | None]
AfterMiddleware = Callable[[Request, Response], ResponseValue | Awaitable[ResponseValue]]
ErrorHandler = Callable[[Request, Exception], ResponseValue | Awaitable[ResponseValue]]

_request_ctx: ContextVar[Request | None] = ContextVar("fango_request", default=None)
_session_ctx: ContextVar[Session | None] = ContextVar("fango_session", default=None)
_user_ctx: ContextVar[User | None] = ContextVar("fango_user", default=None)


class _DefaultAuthBackend:
    def __call__(self, req: Request) -> User | None:
        return None


_default_auth_backend = _DefaultAuthBackend()


class RouteAuth:
    __slots__ = ("backend", "permissions")

    def __init__(self, backend: str, permissions: tuple[PermissionLike, ...]) -> None:
        self.backend = backend
        self.permissions = permissions


def request() -> Request:
    req = _request_ctx.get()
    if req is None:
        raise RuntimeError("No active request context.")
    return req


def session() -> Session:
    current = _session_ctx.get()
    if current is None:
        raise RuntimeError("No active session context.")
    return current


def user() -> User:
    current = _user_ctx.get()
    if current is None:
        raise RuntimeError("No active user context.")
    return current


class Fango:
    def __init__(
        self,
        *,
        settings: SettingsInput | None = None,
        security: SecurityConfig | None = None,
    ) -> None:
        self.settings = load_settings(settings)
        self.security = security or self.settings.to_security_config()
        self._validate_security_config()
        self._routes: list[Route] = []
        self._before: list[BeforeMiddleware] = []
        self._after: list[AfterMiddleware] = []
        self._error_handlers: dict[type[Exception], ErrorHandler] = {}
        self._session_signer = SessionSigner(self.security.secret_key)
        self._auth_backends: dict[str, AuthBackend] = {"default": _default_auth_backend}
        self._route_auth: dict[Endpoint, RouteAuth] = {}
        self._openapi_cache: dict[str, Any] | None = None
        self._openapi_dirty = True
        self._security_failures: dict[str, tuple[float, int]] = {}
        self._logger = logging.getLogger("fango.security")
        self.ssrf = SSRFGuard(
            SSRFConfig(
                enabled=bool(self.settings.SSRF_ENABLED),
                allowed_schemes=frozenset(scheme.lower() for scheme in self.settings.SSRF_ALLOWED_SCHEMES),
                allowed_hosts={host.lower() for host in self.settings.SSRF_ALLOWED_HOSTS},
                allow_private_networks=bool(self.settings.SSRF_ALLOW_PRIVATE_NETWORKS),
                allow_userinfo=bool(self.settings.SSRF_ALLOW_USERINFO),
                allow_unresolvable_hosts=bool(self.settings.SSRF_ALLOW_UNRESOLVABLE_HOSTS),
            )
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            response = Response.text("Unsupported scope type", status_code=500)
            await response.send(send)
            return

        req = Request(scope, receive)
        req.scope["max_request_body_bytes"] = self.security.max_request_body_bytes
        req_token = _request_ctx.set(req)
        loaded_session = self._load_session(req)
        req.scope["session"] = loaded_session
        session_token = _session_ctx.set(loaded_session)
        req.scope["user"] = User.anonymous()
        user_token = _user_ctx.set(req.scope["user"])
        try:
            response = await self._dispatch(req)
        except Exception as exc:
            response = await self._handle_error(req, exc)
        finally:
            _user_ctx.reset(user_token)
            _session_ctx.reset(session_token)
            _request_ctx.reset(req_token)

        try:
            apply_security_headers(response, self.security)
            if self.security.csrf_enabled:
                ensure_csrf_cookie(req, response, self.security)
            self._persist_session(req, response)
            await response.send(send)
        except Exception:
            self._log_security_event(
                logging.ERROR,
                "response-send-failed",
                req=req,
            )
            fallback = Response.text("Internal Server Error", status_code=500)
            apply_security_headers(fallback, self.security)
            await fallback.send(send)

    def route(
        self,
        path: str,
        *,
        methods: Iterable[str] = ("GET",),
        name: str | None = None,
    ) -> Callable[[Endpoint], Endpoint]:
        def decorator(func: Endpoint) -> Endpoint:
            self.add_route(path, func, methods=methods, name=name)
            return func

        return decorator

    def get(self, path: str, *, name: str | None = None) -> Callable[[Endpoint], Endpoint]:
        return self.route(path, methods=("GET",), name=name)

    def post(self, path: str, *, name: str | None = None) -> Callable[[Endpoint], Endpoint]:
        return self.route(path, methods=("POST",), name=name)

    def put(self, path: str, *, name: str | None = None) -> Callable[[Endpoint], Endpoint]:
        return self.route(path, methods=("PUT",), name=name)

    def patch(self, path: str, *, name: str | None = None) -> Callable[[Endpoint], Endpoint]:
        return self.route(path, methods=("PATCH",), name=name)

    def delete(self, path: str, *, name: str | None = None) -> Callable[[Endpoint], Endpoint]:
        return self.route(path, methods=("DELETE",), name=name)

    def before_request(self, fn: BeforeMiddleware) -> BeforeMiddleware:
        self._before.append(fn)
        return fn

    def after_request(self, fn: AfterMiddleware) -> AfterMiddleware:
        self._after.append(fn)
        return fn

    def errorhandler(self, error_type: type[Exception]) -> Callable[[ErrorHandler], ErrorHandler]:
        def decorator(fn: ErrorHandler) -> ErrorHandler:
            self._error_handlers[error_type] = fn
            return fn

        return decorator

    def register_auth_backend(self, name: str, backend: AuthBackend) -> None:
        normalized = name.strip()
        if not normalized:
            raise ValueError("Auth backend name must not be empty.")
        self._auth_backends[normalized] = backend

    def authorize(
        self,
        *permissions: PermissionLike,
        backend: str = "default",
    ) -> Callable[[Endpoint], Endpoint]:
        backend_name = backend.strip()
        if not backend_name:
            raise ValueError("Auth backend name must not be empty.")

        def decorator(endpoint: Endpoint) -> Endpoint:
            route_permissions = permissions or (IsAuthenticated(),)
            self._route_auth[endpoint] = RouteAuth(
                backend=backend_name,
                permissions=route_permissions,
            )
            return endpoint

        return decorator

    def add_route(
        self,
        path: str,
        endpoint: Endpoint,
        *,
        methods: Iterable[str] = ("GET",),
        name: str | None = None,
    ) -> None:
        normalized = frozenset(method.upper() for method in methods)
        if "GET" in normalized:
            normalized = frozenset((*normalized, "HEAD"))
        self._routes.append(Route(path, normalized, endpoint, name=name))
        self._openapi_dirty = True

    def run(self, *, host: str = "127.0.0.1", port: int = 8000) -> None:
        asyncio.run(
            run_dev_server(
                self,
                host,
                port,
                max_request_body_bytes=self.security.max_request_body_bytes,
                max_request_head_bytes=self.security.max_request_head_bytes,
                request_read_timeout_seconds=self.security.request_read_timeout_seconds,
            )
        )

    def validate_outbound_url(self, url: str) -> str:
        return self.ssrf.validate_url(url)

    def _handle_docs_request(self, req: Request) -> Response | None:
        if not self.settings.ENABLE_DOCS:
            return None

        docs_path = self.settings.DOCS_PATH
        openapi_path = self.settings.OPENAPI_PATH
        if req.path not in {docs_path, openapi_path}:
            return None
        if req.method not in {"GET", "HEAD"}:
            return Response.text("Method Not Allowed", status_code=405)

        if req.path == openapi_path:
            return Response.json(self._openapi_spec())

        return Response.html(
            _swagger_ui_html(
                openapi_path=openapi_path,
                title=self.settings.API_TITLE,
            ),
            headers={
                "content-security-policy": (
                    "default-src 'self'; "
                    "script-src 'self' https://unpkg.com; "
                    "style-src 'self' 'unsafe-inline' https://unpkg.com; "
                    "img-src 'self' data: https:; "
                    "connect-src 'self'; "
                    "font-src https://unpkg.com; "
                    "frame-ancestors 'none'"
                )
            },
        )

    def _openapi_spec(self) -> dict[str, Any]:
        if self._openapi_cache is not None and not self._openapi_dirty:
            return self._openapi_cache
        spec = build_openapi_spec(
            routes=self._routes,
            title=self.settings.API_TITLE,
            version=self.settings.API_VERSION,
            description=self.settings.API_DESCRIPTION,
        )
        self._openapi_cache = spec
        self._openapi_dirty = False
        return spec

    def _validate_security_config(self) -> None:
        if not self.security.secret_key:
            raise ValueError("SECRET_KEY must be configured.")
        if self.security.secret_key == "dev-insecure-secret-change-this":
            raise ValueError("SECRET_KEY uses an insecure default value.")
        if not self.settings.DEBUG and len(self.security.secret_key) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters when DEBUG is False.")
        if self.security.max_request_body_bytes <= 0:
            raise ValueError("MAX_REQUEST_BODY_BYTES must be greater than 0.")
        if self.security.max_request_head_bytes <= 0:
            raise ValueError("MAX_REQUEST_HEAD_BYTES must be greater than 0.")
        if self.security.request_read_timeout_seconds <= 0:
            raise ValueError("REQUEST_READ_TIMEOUT_SECONDS must be greater than 0.")
        if self.security.security_failure_window_seconds <= 0:
            raise ValueError("SECURITY_FAILURE_WINDOW_SECONDS must be greater than 0.")
        if not self.settings.SSRF_ALLOWED_SCHEMES:
            raise ValueError("SSRF_ALLOWED_SCHEMES must not be empty.")
        if not self.settings.DOCS_PATH.startswith("/"):
            raise ValueError("DOCS_PATH must start with '/'.")
        if not self.settings.OPENAPI_PATH.startswith("/"):
            raise ValueError("OPENAPI_PATH must start with '/'.")
        if self.settings.DOCS_PATH == self.settings.OPENAPI_PATH:
            raise ValueError("DOCS_PATH and OPENAPI_PATH must be different.")

    async def _dispatch(self, req: Request) -> Response:
        if self.security.enforce_allowed_hosts and not host_is_allowed(
            req.headers.get("host"), allowed_hosts=self.security.allowed_hosts
        ):
            self._log_security_event(logging.WARNING, "host-check-failed", req=req)
            if self._register_security_failure(req):
                return Response.text("Too Many Requests", status_code=429)
            return Response.text("Bad host header", status_code=400)

        if self.security.csrf_enabled and not csrf_is_valid(req, self.security):
            self._log_security_event(logging.WARNING, "csrf-check-failed", req=req)
            if self._register_security_failure(req):
                return Response.text("Too Many Requests", status_code=429)
            return Response.text("CSRF validation failed", status_code=403)

        docs_response = self._handle_docs_request(req)
        if docs_response is not None:
            return docs_response

        for fn in self._before:
            value = await _maybe_await(fn(req))
            if value is not None:
                response = to_response(value)
                return await self._run_after_middleware(req, response)

        match, path_exists = self._match_route(req.path, req.method)
        if match is None and path_exists:
            return Response.text("Method Not Allowed", status_code=405)
        if match is None:
            return Response.text("Not Found", status_code=404)

        auth_response = await self._authorize_request(req, match.endpoint)
        if auth_response is not None:
            return auth_response

        raw_response = await self._call_endpoint(req, match)
        response = to_response(raw_response)
        return await self._run_after_middleware(req, response)

    async def _run_after_middleware(self, req: Request, response: Response) -> Response:
        current = response
        for fn in self._after:
            current = to_response(await _maybe_await(fn(req, current)))
        return current

    async def _call_endpoint(self, req: Request, match: MatchResult) -> ResponseValue:
        signature = inspect.signature(match.endpoint)
        if "request" in signature.parameters:
            value = match.endpoint(request=req, **match.params)
        else:
            value = match.endpoint(**match.params)
        return await _maybe_await(value)

    def _match_route(self, path: str, method: str) -> tuple[MatchResult | None, bool]:
        path_exists = False
        for route in self._routes:
            result = route.match(path, method)
            if result is not None:
                return result, True
            if route.path_matches(path):
                path_exists = True
        return None, path_exists

    async def _handle_error(self, req: Request, exc: Exception) -> Response:
        if isinstance(exc, HTTPException):
            response = Response.text(
                exc.detail or str(exc.status_code),
                status_code=exc.status_code,
            )
            response.headers.update({key.lower(): value for key, value in exc.headers.items()})
            return response

        self._log_security_event(logging.ERROR, "unhandled-exception", req=req)

        for klass in type(exc).__mro__:
            handler = self._error_handlers.get(klass)
            if handler is None:
                continue
            response = to_response(await _maybe_await(handler(req, exc)))
            return response
        return Response.text("Internal Server Error", status_code=500)

    def _load_session(self, req: Request) -> Session:
        token = req.cookies.get(self.security.session_cookie_name)
        if not token:
            return Session({})
        data = self._session_signer.loads(token, max_age=self.security.session_cookie_max_age)
        return Session(data or {})

    def _persist_session(self, req: Request, response: Response) -> None:
        current = req.scope.get("session")
        if not isinstance(current, Session) or not current.modified:
            return
        if not current.data:
            response.cookies.append(
                build_set_cookie(
                    self.security.session_cookie_name,
                    "",
                    max_age=0,
                    secure=self.security.session_cookie_secure,
                    http_only=self.security.session_cookie_http_only,
                    same_site=self.security.session_cookie_same_site,
                )
            )
            return
        token = self._session_signer.dumps(current.data)
        response.cookies.append(
            build_set_cookie(
                self.security.session_cookie_name,
                token,
                max_age=self.security.session_cookie_max_age,
                secure=self.security.session_cookie_secure,
                http_only=self.security.session_cookie_http_only,
                same_site=self.security.session_cookie_same_site,
            )
        )

    async def _authorize_request(self, req: Request, endpoint: Endpoint) -> Response | None:
        auth = self._route_auth.get(endpoint)
        if auth is None:
            return None

        backend = self._auth_backends.get(auth.backend)
        if backend is None:
            self._log_security_event(logging.ERROR, "auth-backend-missing", req=req)
            return Response.text("Auth backend is not configured", status_code=500)

        challenge: str | None = None
        try:
            authenticated = await _maybe_await(backend(req))
        except Exception:
            self._log_security_event(logging.ERROR, "auth-backend-error", req=req)
            if self._register_security_failure(req):
                return Response.text("Too Many Requests", status_code=429)
            return Response.text("Unauthorized", status_code=401)

        auth_result = _normalize_auth_identity(authenticated)
        resolved_user = auth_result.user or User.anonymous()
        challenge = auth_result.challenge
        req.scope["user"] = resolved_user
        _user_ctx.set(resolved_user)

        for permission in auth.permissions:
            allowed = await self._evaluate_permission(permission, req, resolved_user)
            if not allowed:
                self._log_security_event(logging.WARNING, "permission-denied", req=req)
                if self._register_security_failure(req):
                    return Response.text("Too Many Requests", status_code=429)
                return _permission_denied_response(resolved_user, challenge=challenge)
        return None

    def _register_security_failure(self, req: Request) -> bool:
        limit = self.security.security_failure_rate_limit
        if limit <= 0:
            return False
        client = req.client_ip or "unknown"
        window = self.security.security_failure_window_seconds
        now = time.monotonic()
        if len(self._security_failures) > 10_000:
            cutoff = now - window
            self._security_failures = {
                key: value for key, value in self._security_failures.items() if value[0] >= cutoff
            }
        start, count = self._security_failures.get(client, (now, 0))
        if now - start >= window:
            start = now
            count = 0
        count += 1
        self._security_failures[client] = (start, count)
        return count > limit

    def _log_security_event(self, level: int, event: str, *, req: Request) -> None:
        if not self.security.log_security_events:
            return
        self._logger.log(
            level,
            "%s method=%s path=%s client=%s",
            event,
            req.method,
            req.path,
            req.client_ip,
        )

    async def _evaluate_permission(
        self,
        permission: PermissionLike,
        req: Request,
        current_user: User,
    ) -> bool:
        if isinstance(permission, Permission):
            try:
                check = permission.has_permission(req, current_user)
            except Exception:
                self._log_security_event(logging.ERROR, "permission-check-error", req=req)
                return False
        else:
            try:
                check = permission(req, current_user)
            except Exception:
                self._log_security_event(logging.ERROR, "permission-check-error", req=req)
                return False
        try:
            return bool(await _maybe_await(check))
        except Exception:
            self._log_security_event(logging.ERROR, "permission-check-error", req=req)
            return False


def _swagger_ui_html(*, openapi_path: str, title: str) -> str:
    return f"""<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{title} Docs</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
    <style>
      html, body {{
        margin: 0;
        padding: 0;
      }}
      #swagger-ui {{
        min-height: 100vh;
      }}
    </style>
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
      window.ui = SwaggerUIBundle({{
        url: "{openapi_path}",
        dom_id: "#swagger-ui",
        deepLinking: true,
      }});
    </script>
  </body>
</html>
"""


def _normalize_auth_identity(identity: AuthIdentity) -> AuthResult:
    if isinstance(identity, AuthResult):
        return identity
    if isinstance(identity, User):
        return AuthResult(user=identity, challenge=None)
    return AuthResult(user=None, challenge=None)


def _permission_denied_response(user: User, *, challenge: str | None) -> Response:
    if not user.is_authenticated:
        headers = {"www-authenticate": challenge} if challenge else {}
        return Response.text("Unauthorized", status_code=401, headers=headers)
    return Response.text("Forbidden", status_code=403)


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value
