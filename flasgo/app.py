from __future__ import annotations

import asyncio
import html
import inspect
import json
import logging
import re
import secrets
import time
from collections.abc import AsyncGenerator, Awaitable, Callable, Iterable, Mapping, Sequence
from contextvars import ContextVar
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit
from uuid import uuid4

from .auth import (
    AuthBackend,
    AuthIdentity,
    AuthResult,
    IsAuthenticated,
    Permission,
    PermissionLike,
    User,
    extract_bearer_token,
)
from .debug import Debug
from .exceptions import HTTPException
from .logging import configure_logging, log_event
from .metrics import Metrics
from .openapi import build_openapi_spec
from .ratelimit import (
    RateLimiter,
    build_rate_limit_response,
    endpoint_rate_limits,
    rate_limit,
    rate_limit_success_headers,
)
from .request import Request
from .response import Response, ResponseValue, to_response
from .routing import (
    Endpoint,
    MatchResult,
    Route,
    WebSocketEndpoint,
    WebSocketMatchResult,
    WebSocketRoute,
)
from .security import (
    SecurityConfig,
    apply_security_headers,
    build_set_cookie,
    csrf_is_valid,
    ensure_csrf_cookie,
    host_is_allowed,
    websocket_origin_is_allowed,
)
from .server import run_dev_server
from .session import Session, SessionSigner
from .settings import SettingsInput, load_settings
from .ssrf import SSRFConfig, SSRFGuard, SSRFResolvedURL
from .staticfiles import StaticDirectory, build_static_response, resolve_static_directory
from .templating import JinjaTemplates
from .types import Receive, Scope, Send
from .websockets import WebSocket, WebSocketDisconnect

if TYPE_CHECKING:
    from .testing import TestClient

BeforeMiddleware = Callable[[Request], ResponseValue | Awaitable[ResponseValue] | None]
AfterMiddleware = Callable[[Request, Response], ResponseValue | Awaitable[ResponseValue]]
ErrorHandler = Callable[[Request, Exception], ResponseValue | Awaitable[ResponseValue]]
LifespanHandler = Callable[["Flasgo"], AsyncGenerator[None]]

_request_ctx: ContextVar[Request | None] = ContextVar("flasgo_request", default=None)
_session_ctx: ContextVar[Session | None] = ContextVar("flasgo_session", default=None)
_user_ctx: ContextVar[User | None] = ContextVar("flasgo_user", default=None)
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_METRIC_HTTP_METHODS = frozenset({"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"})
_INSECURE_SENTINEL = "dev-insecure-secret-change-this"


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
    """Return the active request for the current handler."""

    req = _request_ctx.get()
    if req is None:
        raise RuntimeError("No active request context. Access flasgo.request only while handling an HTTP request.")
    return req


def session() -> Session:
    """Return the active session for the current handler."""

    current = _session_ctx.get()
    if current is None:
        raise RuntimeError("No active session context. Access flasgo.session only while handling an HTTP request.")
    return current


def user() -> User:
    """Return the active user for the current handler."""

    current = _user_ctx.get()
    if current is None:
        raise RuntimeError("No active user context. Access flasgo.current_user only while handling an HTTP request.")
    return current


class Flasgo:
    """Async-first web application with Flask-style routing and secure defaults."""

    def __init__(
        self,
        *,
        settings: SettingsInput | None = None,
        security: SecurityConfig | None = None,
        templates: JinjaTemplates | None = None,
        static_folder: str | Path | None = None,
        static_url_path: str = "/static",
        static_cache_max_age: int = 3600,
    ) -> None:
        self.settings = load_settings(settings)
        self.security = security or self.settings.to_security_config()
        self._validate_security_config()
        self._routes: list[Route] = []
        self._websocket_routes: list[WebSocketRoute] = []
        self._static_directories: list[StaticDirectory] = []
        self._before: list[BeforeMiddleware] = []
        self._after: list[AfterMiddleware] = []
        self._error_handlers: dict[type[Exception], ErrorHandler] = {}
        self._session_signer = SessionSigner(self.security.secret_key)
        self._auth_backends: dict[str, AuthBackend] = {"default": _default_auth_backend}
        self._route_auth: dict[object, RouteAuth] = {}
        self._rate_limiter = RateLimiter()
        self._openapi_cache: dict[str, Any] | None = None
        self._openapi_dirty = True
        self._security_failures: dict[str, tuple[float, int]] = {}
        self._logger = logging.getLogger("flasgo.security")
        self._access_logger = logging.getLogger("flasgo.access")
        self._websocket_logger = logging.getLogger("flasgo.websocket")
        self._lifespan_logger = logging.getLogger("flasgo.lifespan")
        self._lifespan_handler: LifespanHandler | None = None
        self._lifespan_iterator: AsyncGenerator[None] | None = None
        self._lifespan_active = False
        self.state = SimpleNamespace()
        self._metrics = Metrics() if self.settings.METRICS_ENABLED else None
        self.templates = templates
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
        if static_folder is not None:
            self.configure_static(
                static_folder,
                url_path=static_url_path,
                cache_max_age=static_cache_max_age,
            )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        scope_type = scope.get("type")
        if scope_type == "http":
            await self._handle_http(scope, receive, send)
            return
        if scope_type == "websocket":
            await self._handle_websocket(scope, receive, send)
            return
        if scope_type == "lifespan":
            await self._handle_lifespan(scope, receive, send)
            return
        log_event(self._logger, logging.ERROR, "unsupported-asgi-scope", scope_type=scope_type)
        raise RuntimeError(f"Unsupported ASGI scope type: {scope_type!r}")

    async def _handle_http(self, scope: Scope, receive: Receive, send: Send) -> None:
        started = time.perf_counter()
        scope["request_id"] = self._request_id_for_scope(scope)
        req = Request(scope, receive)
        req.scope["max_request_body_bytes"] = self.security.max_request_body_bytes
        instrument = self._metrics is not None and req.path != self.settings.METRICS_PATH
        if instrument:
            self._metrics.http_active.inc()
        req_token = _request_ctx.set(req)
        loaded_session = self._load_session(req)
        req.scope["session"] = loaded_session
        session_token = _session_ctx.set(loaded_session)
        req.scope["user"] = User.anonymous()
        user_token = _user_ctx.set(req.scope["user"])
        try:
            try:
                response = await self._dispatch(req)
            except Exception as exc:
                response = await self._handle_error(req, exc)
            finally:
                _user_ctx.reset(user_token)
                _session_ctx.reset(session_token)
                _request_ctx.reset(req_token)

            try:
                self._prepare_response(req, response)
            except Exception:
                self._log_security_event(logging.ERROR, "response-prepare-failed", req=req)
                response = Response.text(
                    "Internal Server Error. Check the application logs for the original failure.",
                    status_code=500,
                    headers={"x-request-id": req.request_id},
                )
                apply_security_headers(response, self.security)
                response.prepare()

            sent = False
            try:
                await response.send(send, head_only=req.method == "HEAD")
                sent = True
            except Exception:
                self._log_security_event(logging.ERROR, "response-send-failed", req=req)

            duration = time.perf_counter() - started
            route = str(req.scope.get("route_template", "<unmatched>"))
            log_event(
                self._access_logger,
                logging.INFO,
                "http-request-complete" if sent else "http-response-send-failed",
                request_id=req.request_id,
                method=req.method,
                route=route,
                status=response.status_code,
                client=req.client_ip,
                duration_ms=round(duration * 1000, 3),
            )
            if instrument:
                metric_method = req.method if req.method in _METRIC_HTTP_METHODS else "OTHER"
                self._metrics.http_requests.labels(
                    method=metric_method,
                    route=route,
                    status=str(response.status_code),
                ).inc()
                self._metrics.http_duration.labels(method=metric_method, route=route).observe(duration)

            if sent and response.background is not None:
                response.background.bind_request_id(req.request_id)
                if self._metrics is not None:
                    response.background.bind_observer(self._metrics.observe_background)
                await response.background()
        finally:
            if instrument:
                self._metrics.http_active.dec()

    async def _handle_lifespan(self, scope: Scope, receive: Receive, send: Send) -> None:
        state = scope.get("state")
        if isinstance(state, dict):
            state["flasgo"] = self.state
        while True:
            message = await receive()
            message_type = message.get("type")
            if message_type == "lifespan.startup":
                configure_logging(format=self.settings.LOG_FORMAT, level=self.settings.LOG_LEVEL)
                if self._lifespan_active:
                    await send(
                        {
                            "type": "lifespan.startup.failed",
                            "message": "Flasgo lifespan is already active.",
                        }
                    )
                    return
                try:
                    if self._lifespan_handler is not None:
                        iterator = self._lifespan_handler(self)
                        await anext(iterator)
                        self._lifespan_iterator = iterator
                    self._lifespan_active = True
                    if self._metrics is not None:
                        self._metrics.observe_lifespan("startup", "success")
                    await send({"type": "lifespan.startup.complete"})
                except Exception:
                    if self._lifespan_iterator is not None:
                        await self._lifespan_iterator.aclose()
                        self._lifespan_iterator = None
                    log_event(self._lifespan_logger, logging.ERROR, "lifespan-startup-failed")
                    self._lifespan_logger.debug("lifespan startup exception", exc_info=True)
                    if self._metrics is not None:
                        self._metrics.observe_lifespan("startup", "failure")
                    await send(
                        {
                            "type": "lifespan.startup.failed",
                            "message": "Application startup failed; see logs.",
                        }
                    )
                    return
            elif message_type == "lifespan.shutdown":
                try:
                    if self._lifespan_active and self._lifespan_iterator is not None:
                        try:
                            await anext(self._lifespan_iterator)
                        except StopAsyncIteration:
                            pass
                        else:
                            raise RuntimeError("A Flasgo lifespan handler must yield exactly once.")
                    self._lifespan_iterator = None
                    self._lifespan_active = False
                    if self._metrics is not None:
                        self._metrics.observe_lifespan("shutdown", "success")
                    await send({"type": "lifespan.shutdown.complete"})
                except Exception:
                    log_event(self._lifespan_logger, logging.ERROR, "lifespan-shutdown-failed")
                    self._lifespan_logger.debug("lifespan shutdown exception", exc_info=True)
                    if self._metrics is not None:
                        self._metrics.observe_lifespan("shutdown", "failure")
                    await send(
                        {
                            "type": "lifespan.shutdown.failed",
                            "message": "Application shutdown failed; see logs.",
                        }
                    )
                finally:
                    self._lifespan_iterator = None
                    self._lifespan_active = False
                return
            else:
                raise RuntimeError(f"Unexpected lifespan event: {message_type!r}")

    async def _handle_websocket(self, scope: Scope, receive: Receive, send: Send) -> None:
        started = time.perf_counter()
        scope["request_id"] = self._request_id_for_scope(scope)
        websocket = WebSocket(
            scope,
            receive,
            send,
            max_message_bytes=self.settings.WEBSOCKET_MAX_MESSAGE_BYTES,
            max_messages_per_minute=self.settings.WEBSOCKET_MAX_MESSAGES_PER_MINUTE,
        )
        route = "<unmatched>"
        outcome = "error"
        active = False
        try:
            await websocket.receive_connect()
            match = self._match_websocket_route(websocket.path)
            if match is None:
                outcome = "not_found"
                await websocket.deny(404, "Not Found")
                return
            route = match.route_path
            websocket.path_params = dict(match.params)
            upgrade_req = self._request_from_websocket_scope(scope)
            loaded_session = self._load_session(upgrade_req)
            upgrade_req.scope["session"] = loaded_session
            upgrade_req.scope["user"] = User.anonymous()
            scope["session"] = loaded_session
            scope["user"] = upgrade_req.scope["user"]

            host_values = _scope_header_values(scope, b"host")
            if self.security.enforce_allowed_hosts and (
                len(host_values) != 1 or not host_is_allowed(host_values[0], allowed_hosts=self.security.allowed_hosts)
            ):
                self._log_security_event(logging.WARNING, "websocket-host-failed", req=upgrade_req)
                outcome = "invalid_host"
                await websocket.deny(400, "Invalid Host")
                return
            if not self._websocket_origin_allowed(upgrade_req):
                self._log_security_event(logging.WARNING, "websocket-origin-failed", req=upgrade_req)
                outcome = "invalid_origin"
                await websocket.deny(403, "Forbidden")
                return

            denial = await self._authorize_websocket(upgrade_req, match.endpoint)
            scope["user"] = upgrade_req.scope["user"]
            if denial is not None:
                status, headers = denial
                outcome = f"denied_{status}"
                await websocket.deny(status, _status_text(status), headers=headers)
                return

            if self._metrics is not None:
                self._metrics.websocket_active.labels(route=route).inc()
                active = True
            try:
                await self._call_websocket_endpoint(websocket, match)
                outcome = "closed" if websocket.disconnected else "success"
            except WebSocketDisconnect:
                outcome = "closed"
            except Exception:
                outcome = "handler_error"
                log_event(
                    self._websocket_logger,
                    logging.ERROR,
                    "websocket-handler-error",
                    request_id=websocket.request_id,
                    route=route,
                    client=websocket.client_ip,
                )
                self._websocket_logger.debug("websocket handler exception", exc_info=True)
                if websocket.accepted:
                    await websocket.close(1011, "Internal Error")
                elif not websocket.disconnected:
                    await websocket.deny(500, "Internal Server Error")
            finally:
                if websocket.accepted:
                    await websocket.close(1000)
                elif not websocket.disconnected:
                    await websocket.deny(403, "WebSocket was not accepted")
        except WebSocketDisconnect:
            outcome = "closed"
        except Exception:
            outcome = "dispatch_error"
            log_event(
                self._websocket_logger,
                logging.ERROR,
                "websocket-dispatch-error",
                request_id=websocket.request_id,
                route=route,
                client=websocket.client_ip,
            )
            self._websocket_logger.debug("websocket dispatch exception", exc_info=True)
            try:
                if websocket.accepted:
                    await websocket.close(1011, "Internal Error")
                elif not websocket.disconnected:
                    await websocket.deny(500, "Internal Server Error")
            except WebSocketDisconnect:
                pass
        finally:
            duration = time.perf_counter() - started
            if self._metrics is not None:
                if active:
                    self._metrics.websocket_active.labels(route=route).dec()
                self._metrics.websocket_connections.labels(route=route, outcome=outcome).inc()
                self._metrics.websocket_duration.labels(route=route).observe(duration)
            log_event(
                self._websocket_logger,
                logging.INFO,
                "websocket-complete",
                request_id=websocket.request_id,
                route=route,
                client=websocket.client_ip,
                outcome=outcome,
                close_code=websocket.close_code,
                duration_ms=round(duration * 1000, 3),
            )

    def _request_from_websocket_scope(self, scope: Scope) -> Request:
        done = False

        async def empty_receive() -> dict[str, Any]:
            nonlocal done
            if not done:
                done = True
                return {"type": "http.request", "body": b"", "more_body": False}
            return {"type": "http.disconnect"}

        scheme = str(scope.get("scheme", "ws")).lower()
        http_scope = {
            **scope,
            "type": "http",
            "method": "GET",
            "scheme": "https" if scheme == "wss" else "http",
            "http_version": scope.get("http_version", "1.1"),
            "flasgo.websocket_upgrade": True,
        }
        return Request(http_scope, empty_receive)

    def _websocket_origin_allowed(self, req: Request) -> bool:
        if not self.settings.WEBSOCKET_ENFORCE_ORIGIN:
            return True
        origins = _scope_header_values(req.scope, b"origin")
        if not origins:
            return self.settings.WEBSOCKET_ALLOW_MISSING_ORIGIN
        if len(origins) != 1:
            return False
        return websocket_origin_is_allowed(
            origins[0],
            request_scheme=req.scheme,
            request_host=req.headers.get("host") or "",
            allowed_origins=self.settings.WEBSOCKET_ALLOWED_ORIGINS,
        )

    async def _authorize_websocket(
        self,
        req: Request,
        endpoint: WebSocketEndpoint,
    ) -> tuple[int, dict[str, str]] | None:
        auth = self._route_auth.get(endpoint)
        if auth is None:
            return None
        backend = self._auth_backends.get(auth.backend)
        if backend is None:
            self._log_security_event(logging.ERROR, "auth-backend-missing", req=req)
            return 500, {}
        try:
            authenticated = await _maybe_await(backend(req))
        except Exception:
            self._log_security_event(logging.ERROR, "auth-backend-error", req=req)
            return 500, {}
        auth_result = _normalize_auth_identity(authenticated)
        resolved_user = auth_result.user or User.anonymous()
        req.scope["user"] = resolved_user
        for permission in auth.permissions:
            if not await self._evaluate_permission(permission, req, resolved_user):
                self._log_security_event(logging.WARNING, "permission-denied", req=req)
                status = 403 if resolved_user.is_authenticated else 401
                headers = {"www-authenticate": auth_result.challenge} if auth_result.challenge else {}
                return status, headers
        return None

    async def _call_websocket_endpoint(
        self,
        websocket: WebSocket,
        match: WebSocketMatchResult,
    ) -> None:
        signature = inspect.signature(match.endpoint)
        parameters = signature.parameters
        should_inject = "websocket" in parameters or any(
            parameter.annotation in {WebSocket, "WebSocket"} for parameter in parameters.values()
        )
        value = match.endpoint(websocket=websocket, **match.params) if should_inject else match.endpoint(**match.params)
        await _maybe_await(value)

    def _match_websocket_route(self, path: str) -> WebSocketMatchResult | None:
        for route in self._websocket_routes:
            result = route.match(path)
            if result is not None:
                return result
        return None

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

    def websocket(
        self,
        path: str,
        *,
        name: str | None = None,
    ) -> Callable[[WebSocketEndpoint], WebSocketEndpoint]:
        def decorator(func: WebSocketEndpoint) -> WebSocketEndpoint:
            self.add_websocket_route(path, func, name=name)
            return func

        return decorator

    def add_websocket_route(
        self,
        path: str,
        endpoint: WebSocketEndpoint,
        *,
        name: str | None = None,
    ) -> None:
        self._websocket_routes.append(WebSocketRoute(path, endpoint, name=name))

    def lifespan(self, fn: LifespanHandler) -> LifespanHandler:
        if self._lifespan_handler is not None:
            raise RuntimeError("Only one Flasgo lifespan handler may be registered.")
        if not inspect.isasyncgenfunction(fn):
            raise TypeError("A Flasgo lifespan handler must be an async generator that yields exactly once.")
        self._lifespan_handler = fn
        return fn

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
            raise ValueError("Auth backend name must not be empty. Pass a stable name such as 'default' or 'bearer'.")
        self._auth_backends[normalized] = backend

    def authorize[T: Callable[..., Any]](
        self,
        *permissions: PermissionLike,
        backend: str = "default",
    ) -> Callable[[T], T]:
        backend_name = backend.strip()
        if not backend_name:
            raise ValueError("Auth backend name must not be empty. Pass the name used in register_auth_backend(...).")

        def decorator(endpoint: T) -> T:
            route_permissions = permissions or (IsAuthenticated(),)
            self._route_auth[endpoint] = RouteAuth(
                backend=backend_name,
                permissions=route_permissions,
            )
            return endpoint

        return decorator

    def ratelimit(
        self,
        requests: int,
        *,
        per: float,
        scope: str | None = None,
        key_func: Callable[[Request], str | None] | None = None,
    ) -> Callable[[Endpoint], Endpoint]:
        return rate_limit(requests, per=per, scope=scope, key_func=key_func)

    def add_route(
        self,
        path: str,
        endpoint: Endpoint,
        *,
        methods: Iterable[str] = ("GET",),
        name: str | None = None,
    ) -> None:
        reserved_paths: set[str] = set()
        if self.settings.METRICS_ENABLED:
            reserved_paths.add(self.settings.METRICS_PATH)
        if self.settings.ENABLE_DOCS:
            reserved_paths.update((self.settings.DOCS_PATH, self.settings.OPENAPI_PATH))
        if path in reserved_paths:
            raise ValueError(f"Route {path!r} conflicts with an enabled internal endpoint.")
        normalized = frozenset(method.upper() for method in methods)
        if "GET" in normalized:
            normalized = frozenset((*normalized, "HEAD"))
        self._routes.append(Route(path, normalized, endpoint, name=name))
        self._openapi_dirty = True

    def run(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 8000,
        reload: bool | None = None,
        reload_dirs: Sequence[str | Path] | None = None,
    ) -> None:
        configure_logging(format=self.settings.LOG_FORMAT, level=self.settings.LOG_LEVEL)
        asyncio.run(
            run_dev_server(
                self,
                host,
                port,
                reload=bool(self.settings.DEBUG) if reload is None else reload,
                reload_dirs=reload_dirs,
                websocket_max_message_bytes=self.settings.WEBSOCKET_MAX_MESSAGE_BYTES,
                limit_concurrency=self.settings.SERVER_LIMIT_CONCURRENCY,
            )
        )

    def configure_templates(
        self,
        template_dirs: str | Path | Sequence[str | Path],
        *,
        globals: Mapping[str, Any] | None = None,
        filters: Mapping[str, Callable[..., Any]] | None = None,
        tests: Mapping[str, Callable[..., Any]] | None = None,
        enable_async: bool = False,
        max_template_bytes: int = 262_144,
    ) -> JinjaTemplates:
        self.templates = JinjaTemplates(
            template_dirs,
            globals=globals,
            filters=filters,
            tests=tests,
            enable_async=enable_async,
            max_template_bytes=max_template_bytes,
        )
        return self.templates

    def render_template(self, template_name: str, context: Mapping[str, Any] | None = None) -> str:
        if self.templates is None:
            raise RuntimeError(
                "Templates are not configured. Call app.configure_templates(...) or pass templates=... first."
            )
        return self.templates.render(template_name, context)

    def configure_static(
        self,
        directory: str | Path,
        *,
        url_path: str = "/static",
        cache_max_age: int = 3600,
    ) -> None:
        static_directory = resolve_static_directory(
            directory,
            url_path=url_path,
            cache_max_age=cache_max_age,
        )
        self._static_directories.append(static_directory)
        self.add_route(
            f"{static_directory.url_path}/<path:filename>",
            self._build_static_endpoint(static_directory),
            methods=("GET",),
            name=f"static:{static_directory.url_path}",
        )

    def test_client(self) -> TestClient:
        from .testing import TestClient

        return TestClient(self)

    def resolve_outbound_url(self, url: str) -> SSRFResolvedURL:
        """Validate an outbound URL and return a pinned connection target."""

        return self.ssrf.resolve_url(url)

    def _request_id_for_scope(self, scope: Scope) -> str:
        if self.settings.TRUST_INCOMING_REQUEST_ID:
            for key, value in scope.get("headers", []):
                if key.lower() != b"x-request-id":
                    continue
                try:
                    candidate = value.decode("ascii")
                except UnicodeDecodeError:
                    break
                if _REQUEST_ID_RE.fullmatch(candidate):
                    return candidate
                break
        return uuid4().hex

    def _prepare_response(self, req: Request, response: Response) -> None:
        response.headers.setdefault("x-request-id", req.request_id)
        apply_security_headers(response, self.security)
        if self.security.csrf_enabled:
            ensure_csrf_cookie(req, response, self.security)
        self._persist_session(req, response)
        response.prepare()

    def _handle_metrics_request(self, req: Request) -> Response | None:
        if self._metrics is None or req.path != self.settings.METRICS_PATH:
            return None
        if req.method not in {"GET", "HEAD"}:
            return Response.text(
                "Method Not Allowed",
                status_code=405,
                headers={"allow": "GET, HEAD"},
            )
        token = extract_bearer_token(req.headers.get("authorization"))
        expected = self.settings.METRICS_BEARER_TOKEN or ""
        if token is None or not secrets.compare_digest(token, expected):
            self._log_security_event(logging.WARNING, "metrics-auth-failed", req=req)
            return Response.text(
                "Unauthorized",
                status_code=401,
                headers={"www-authenticate": "Bearer"},
            )
        body, content_type = self._metrics.render()
        return Response(body=body, content_type=content_type)

    def _handle_docs_request(self, req: Request) -> Response | None:
        if not self.settings.ENABLE_DOCS:
            return None

        docs_path = self.settings.DOCS_PATH
        openapi_path = self.settings.OPENAPI_PATH
        if req.path not in {docs_path, openapi_path}:
            return None
        if req.method not in {"GET", "HEAD"}:
            return Response.text(
                "Method Not Allowed. Use GET or HEAD for the documentation endpoints.",
                status_code=405,
                headers={"allow": "GET, HEAD"},
            )

        if req.path == openapi_path:
            return Response.json(self.openapi_spec())

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

    def openapi_spec(self) -> dict[str, Any]:
        """Return the cached OpenAPI document for the registered routes."""

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
            raise ValueError("SECRET_KEY must be configured. Set it to a long random value before starting Flasgo.")
        if self.security.secret_key == _INSECURE_SENTINEL:
            raise ValueError("SECRET_KEY uses an insecure default value. Replace it with a unique random secret.")
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
            raise ValueError("SSRF_ALLOWED_SCHEMES must not be empty. Include at least one scheme such as 'https'.")
        if not self.settings.DOCS_PATH.startswith("/"):
            raise ValueError("DOCS_PATH must start with '/'. Example: '/docs'.")
        if not self.settings.OPENAPI_PATH.startswith("/"):
            raise ValueError("OPENAPI_PATH must start with '/'. Example: '/openapi.json'.")
        if self.settings.DOCS_PATH == self.settings.OPENAPI_PATH:
            raise ValueError("DOCS_PATH and OPENAPI_PATH must be different so each endpoint has its own URL.")
        if self.settings.LOG_FORMAT.strip().lower() not in {"text", "json"}:
            raise ValueError("LOG_FORMAT must be 'text' or 'json'.")
        if self.settings.LOG_LEVEL.upper() not in logging.getLevelNamesMapping():
            raise ValueError("LOG_LEVEL must be a standard Python logging level such as INFO or WARNING.")
        if self.settings.WEBSOCKET_MAX_MESSAGE_BYTES <= 0:
            raise ValueError("WEBSOCKET_MAX_MESSAGE_BYTES must be greater than 0.")
        if self.settings.WEBSOCKET_MAX_MESSAGES_PER_MINUTE <= 0:
            raise ValueError("WEBSOCKET_MAX_MESSAGES_PER_MINUTE must be greater than 0.")
        if self.settings.SERVER_LIMIT_CONCURRENCY <= 0:
            raise ValueError("SERVER_LIMIT_CONCURRENCY must be greater than 0.")
        for origin in self.settings.WEBSOCKET_ALLOWED_ORIGINS:
            if not _valid_websocket_origin(origin):
                raise ValueError(
                    "WEBSOCKET_ALLOWED_ORIGINS entries must be exact http:// or https:// origins without paths."
                )
        if not self.settings.METRICS_PATH.startswith("/"):
            raise ValueError("METRICS_PATH must start with '/'.")
        if self.settings.METRICS_ENABLED:
            token = self.settings.METRICS_BEARER_TOKEN
            if not isinstance(token, str) or len(token) < 32:
                raise ValueError("METRICS_BEARER_TOKEN must contain at least 32 characters when metrics are enabled.")
            if self.settings.METRICS_PATH in {self.settings.DOCS_PATH, self.settings.OPENAPI_PATH}:
                raise ValueError("METRICS_PATH must not conflict with DOCS_PATH or OPENAPI_PATH.")

    async def _dispatch(self, req: Request) -> Response:
        host_values = _scope_header_values(req.scope, b"host")
        if self.security.enforce_allowed_hosts and (
            len(host_values) != 1 or not host_is_allowed(host_values[0], allowed_hosts=self.security.allowed_hosts)
        ):
            self._log_security_event(logging.WARNING, "host-check-failed", req=req)
            if self._register_security_failure(req):
                return _security_rate_limit_response()
            return Response.text(
                "Invalid Host header. Send a Host value in ALLOWED_HOSTS or update settings.ALLOWED_HOSTS.",
                status_code=400,
            )

        if self.security.csrf_enabled and not csrf_is_valid(req, self.security):
            self._log_security_event(logging.WARNING, "csrf-check-failed", req=req)
            if self._register_security_failure(req):
                return _security_rate_limit_response()
            return Response.text(
                "CSRF validation failed. Send matching CSRF cookie and header values plus a trusted Origin/Referer.",
                status_code=403,
            )

        metrics_response = self._handle_metrics_request(req)
        if metrics_response is not None:
            req.scope["route_template"] = self.settings.METRICS_PATH
            return metrics_response

        docs_response = self._handle_docs_request(req)
        if docs_response is not None:
            req.scope["route_template"] = req.path
            return docs_response

        debug_css_response = Debug.handle_debug_css(req, self.settings.DEBUG)
        if debug_css_response is not None:
            return debug_css_response

        for fn in self._before:
            value = await _maybe_await(fn(req))
            if value is not None:
                response = to_response(value)
                return await self._run_after_middleware(req, response)

        match, allowed_methods = self._match_route(req.path, req.method)
        if match is None and allowed_methods:
            return Response.text(
                f"Method Not Allowed. Use one of: {', '.join(sorted(allowed_methods))}.",
                status_code=405,
                headers={"allow": ", ".join(sorted(allowed_methods))},
            )
        if match is None:
            return Response.text(
                f"No route matches {req.path!r}. Check the URL or register a handler for this path.",
                status_code=404,
            )

        req.scope["route_template"] = match.route_path
        auth_response = await self._authorize_request(req, match.endpoint)
        if auth_response is not None:
            return auth_response

        rate_limit_result = await self._check_rate_limits(req, match.endpoint)
        if isinstance(rate_limit_result, Response):
            return await self._run_after_middleware(req, rate_limit_result)

        raw_response = await self._call_endpoint(req, match)
        response = to_response(raw_response)
        response.headers.update(rate_limit_result)
        return await self._run_after_middleware(req, response)

    async def _check_rate_limits(self, req: Request, endpoint: Endpoint) -> dict[str, str] | Response:
        headers: dict[str, str] = {}
        rules_list = list(endpoint_rate_limits(endpoint))
        if not rules_list:
            return headers

        # Check all rules atomically using batch method
        rules_with_ids = [(rule, f"{id(endpoint)}:{index}") for index, rule in enumerate(rules_list)]
        decisions = await self._rate_limiter.check_batch(rules_with_ids, req)

        # Process decisions
        allowed_decisions = []
        for decision in decisions:
            if not decision.allowed:
                self._log_security_event(logging.WARNING, "rate-limit-exceeded", req=req)
                return build_rate_limit_response(decision)
            allowed_decisions.append(decision)

        # Choose the most restrictive allowed decision (smallest remaining tokens)
        if allowed_decisions:
            canonical_decision = min(allowed_decisions, key=lambda d: (d.remaining, d.reset_after))
            headers.update(rate_limit_success_headers(canonical_decision))

        return headers

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

    def _build_static_endpoint(self, directory: StaticDirectory) -> Endpoint:
        def endpoint(*, request: Request, filename: str) -> Response:
            return build_static_response(directory, filename, request=request)

        return endpoint

    def _match_route(self, path: str, method: str) -> tuple[MatchResult | None, set[str]]:
        allowed_methods: set[str] = set()
        for route in self._routes:
            result = route.match(path, method)
            if result is not None:
                return result, set(route.methods)
            if route.path_matches(path):
                allowed_methods.update(route.methods)
        return None, allowed_methods

    async def _handle_error(self, req: Request, exc: Exception) -> Response:
        if isinstance(exc, HTTPException):
            response = Response.text(
                exc.detail or _status_text(exc.status_code),
                status_code=exc.status_code,
            )
            response.headers.update({key.lower(): value for key, value in exc.headers.items()})
            return response

        debug_response = Debug.render_template_debug_error(req, exc, self.settings.DEBUG)
        if debug_response is not None:
            return debug_response

        self._log_security_event(logging.ERROR, "unhandled-exception", req=req)

        for klass in type(exc).__mro__:
            handler = self._error_handlers.get(klass)
            if handler is None:
                continue
            response = to_response(await _maybe_await(handler(req, exc)))
            return response
        return Response.text(
            "Internal Server Error. Check the application logs for the original failure.",
            status_code=500,
        )

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
            return Response.text(
                f"Authentication backend {auth.backend!r} is not configured. "
                "Register it with app.register_auth_backend(...).",
                status_code=500,
            )

        challenge: str | None = None
        try:
            authenticated = await _maybe_await(backend(req))
        except Exception:
            self._log_security_event(logging.ERROR, "auth-backend-error", req=req)
            if self._register_security_failure(req):
                return _security_rate_limit_response()
            return Response.text(
                "Authentication failed. Provide valid credentials and retry.",
                status_code=401,
            )

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
                    return _security_rate_limit_response()
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
        log_event(
            self._logger,
            level,
            event,
            request_id=req.request_id,
            method=req.method,
            route=req.scope.get("route_template", req.path),
            client=req.client_ip,
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
    safe_title = html.escape(title, quote=True)
    openapi_path_json = json.dumps(openapi_path)
    return f"""<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{safe_title} Docs</title>
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
        url: {openapi_path_json},
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


def _valid_websocket_origin(value: str) -> bool:
    try:
        parsed = urlsplit(value.strip())
        _ = parsed.port
    except ValueError:
        return False
    return bool(
        parsed.scheme.lower() in {"http", "https"}
        and parsed.netloc
        and parsed.username is None
        and parsed.password is None
        and parsed.path in {"", "/"}
        and not parsed.query
        and not parsed.fragment
    )


def _scope_header_values(scope: Scope, name: bytes) -> list[str]:
    return [value.decode("latin-1") for key, value in scope.get("headers", []) if key.lower() == name]


def _status_text(status_code: int) -> str:
    return {
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        408: "Request Timeout",
        413: "Payload Too Large",
        429: "Too Many Requests",
        500: "Internal Server Error",
    }.get(status_code, str(status_code))


def _sanitize_log_value(value: object | None) -> str:
    raw = "" if value is None else str(value)
    return raw.replace("\x00", "\\x00").replace("\r", "\\r").replace("\n", "\\n")


def _security_rate_limit_response() -> Response:
    return Response.text(
        "Too many failed security checks from this client. Wait a moment before retrying.",
        status_code=429,
    )


def _permission_denied_response(user: User, *, challenge: str | None) -> Response:
    if not user.is_authenticated:
        headers = {"www-authenticate": challenge} if challenge else {}
        return Response.text(
            "Authentication required. Provide valid credentials and retry.",
            status_code=401,
            headers=headers,
        )
    return Response.text(
        "Forbidden. The authenticated user does not have permission to access this route.",
        status_code=403,
    )


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value
