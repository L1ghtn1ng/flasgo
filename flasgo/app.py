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
    auth_backend_openapi_scheme,
    extract_bearer_token,
    validate_openapi_security_scheme,
)
from .debug import Debug
from .di import resolve_endpoint_arguments
from .exceptions import HTTPException
from .logging import configure_logging, log_event
from .metrics import Metrics
from .openapi import build_openapi_spec
from .params import compile_endpoint_plan
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
from .telemetry import Telemetry
from .templating import JinjaTemplates
from .types import Receive, Scope, Send
from .validation import RequestValidationError
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
_HTTP_METHOD_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_BEARER_TOKEN_RE = re.compile(r"^[A-Za-z0-9._~+/-]+=*$")
_METRIC_HTTP_METHODS = frozenset({"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"})
# Stable HTTP server span known methods (RFC 9110 + PATCH + QUERY).
# Unknown methods use "HTTP" in the span name per OTel HTTP span naming rules.
_OTEL_HTTP_METHODS = frozenset(
    {"CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "QUERY", "TRACE"}
)
_INSECURE_SENTINEL = "dev-insecure-secret-change-this"
_SWAGGER_UI_VERSION = "5.32.12"
_SWAGGER_UI_CSS_INTEGRITY = "sha384-9Q2fpS+xeS4ffJy6CagnwoUl+4ldAYhOs9pgZuEKxypVModhmZFzeMlvVsAjf7uT"
_SWAGGER_UI_JS_INTEGRITY = "sha384-aPw2h1Un96ObRq1fD7AOgyf0r9jgkhMD51uBltHKtT0++4LsgMUkQD52RFNWcAil"


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
        tracer_provider: Any | None = None,
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
        self._auth_backend_schemes: dict[str, dict[str, Any]] = {}
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
        self._telemetry = (
            Telemetry(
                self._dispatch_asgi,
                settings=self.settings,
                span_details=self._otel_span_details,
                scope_headers=self._otel_scope_headers,
                tracer_provider=tracer_provider,
            )
            if self.settings.OTEL_ENABLED or tracer_provider is not None
            else None
        )
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
        if scope.get("type") in {"http", "websocket"}:
            scope["request_id"] = self._request_id_for_scope(scope)
            if self._telemetry is not None:
                await self._telemetry(scope, receive, send)
                return
        await self._dispatch_asgi(scope, receive, send)

    async def _dispatch_asgi(self, scope: Scope, receive: Receive, send: Send) -> None:
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
        if _request_head_size(scope) > self.security.max_request_head_bytes:
            response = Response.text(
                "Request headers exceed MAX_REQUEST_HEAD_BYTES.",
                status_code=431,
                headers={
                    "connection": "close",
                    "x-request-id": str(scope.get("request_id", "")),
                },
            )
            apply_security_headers(response, self.security)
            await response.send(send)
            return
        req = Request(scope, receive)
        req.scope["max_request_body_bytes"] = self.security.max_request_body_bytes
        req.scope["request_read_timeout_seconds"] = self.security.request_read_timeout_seconds
        req.scope["max_validation_depth"] = self.security.max_validation_depth
        req.scope["max_validation_work"] = self.security.max_validation_work
        req.scope["max_validation_issues"] = self.security.max_validation_issues
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
                    if self._telemetry is not None:
                        try:
                            await asyncio.to_thread(self._telemetry.shutdown)
                        except Exception:
                            log_event(self._lifespan_logger, logging.WARNING, "otel-shutdown-failed")
                            self._lifespan_logger.debug("OpenTelemetry shutdown exception", exc_info=True)
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

            websocket_auth = self._route_auth.get(match.endpoint)
            rate_phase = "pre_auth" if websocket_auth is not None else "all"
            rate_limit_result = await self._check_rate_limits(upgrade_req, match.endpoint, phase=rate_phase)
            if isinstance(rate_limit_result, Response):
                outcome = "rate_limited"
                await websocket.deny(
                    429,
                    _status_text(429),
                    headers=_websocket_rate_limit_headers(rate_limit_result),
                )
                return

            denial = await self._authorize_websocket(upgrade_req, match.endpoint)
            scope["user"] = upgrade_req.scope["user"]
            if denial is not None:
                status, headers = denial
                outcome = f"denied_{status}"
                await websocket.deny(status, _status_text(status), headers=headers)
                return

            if websocket_auth is not None:
                authenticated_rate_limit = await self._check_rate_limits(
                    upgrade_req,
                    match.endpoint,
                    phase="post_auth",
                )
                if isinstance(authenticated_rate_limit, Response):
                    outcome = "rate_limited"
                    await websocket.deny(
                        429,
                        _status_text(429),
                        headers=_websocket_rate_limit_headers(authenticated_rate_limit),
                    )
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
        if self._security_failure_is_limited(req):
            self._log_security_event(logging.WARNING, "security-failure-rate-limit-exceeded", req=req)
            return 429, {}
        try:
            authenticated = await _maybe_await(backend(req))
        except Exception:
            self._log_security_event(logging.ERROR, "auth-backend-error", req=req)
            if self._register_security_failure(req):
                return 429, {}
            return 500, {}
        auth_result = _normalize_auth_identity(authenticated)
        resolved_user = auth_result.user or User.anonymous()
        req.scope["user"] = resolved_user
        for permission in auth.permissions:
            if not await self._evaluate_permission(permission, req, resolved_user):
                self._log_security_event(logging.WARNING, "permission-denied", req=req)
                if self._register_security_failure(req):
                    return 429, {}
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

    def _otel_span_details(self, scope: Scope) -> tuple[str, dict[str, str]]:
        scope_type = str(scope.get("type", ""))
        path = str(scope.get("path", "/"))
        route = "<unmatched>"
        if scope_type == "http":
            method = str(scope.get("method", "GET")).upper()
            # Span name uses the known method token, or "HTTP" when method is unknown
            # (http.request.method may still be _OTHER on the span attributes from ASGI).
            span_method = method if method in _OTEL_HTTP_METHODS else "HTTP"
            match, _ = self._match_route(path, method)
            if match is not None:
                route = match.route_path
            else:
                path_route = self._otel_route_template(path)
                if path_route is not None:
                    route = path_route
            if (
                route == "<unmatched>"
                and path in {self.settings.DOCS_PATH, self.settings.OPENAPI_PATH}
                and self.settings.ENABLE_DOCS
            ):
                route = path
            elif route == "<unmatched>" and path == self.settings.METRICS_PATH and self.settings.METRICS_ENABLED:
                route = path
            return f"{span_method} {route}", {"http.route": route, "flasgo.request_id": str(scope["request_id"])}
        if scope_type == "websocket":
            match = self._match_websocket_route(path)
            if match is not None:
                route = match.route_path
            return f"WEBSOCKET {route}", {"http.route": route, "flasgo.request_id": str(scope["request_id"])}
        return scope_type or "ASGI", {}

    def _otel_scope_headers(self, scope: Scope) -> list[tuple[bytes, bytes]]:
        headers = list(scope.get("headers", []))
        if not self.security.enforce_allowed_hosts:
            return headers
        host_values = _scope_header_values(scope, b"host")
        if len(host_values) == 1 and host_is_allowed(host_values[0], allowed_hosts=self.security.allowed_hosts):
            return headers
        return [(name, value) for name, value in headers if name.lower() != b"host"]

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

    def register_auth_backend(
        self,
        name: str,
        backend: AuthBackend,
        *,
        openapi_scheme: Mapping[str, object] | None = None,
    ) -> None:
        normalized = name.strip()
        if not normalized:
            raise ValueError("Auth backend name must not be empty. Pass a stable name such as 'default' or 'bearer'.")
        scheme = auth_backend_openapi_scheme(backend) if openapi_scheme is None else openapi_scheme
        validated_scheme = None if scheme is None else validate_openapi_security_scheme(normalized, scheme)
        self._auth_backends[normalized] = backend
        if validated_scheme is None:
            self._auth_backend_schemes.pop(normalized, None)
        else:
            self._auth_backend_schemes[normalized] = validated_scheme
        self._openapi_dirty = True

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
            self._openapi_dirty = True
            return endpoint

        return decorator

    def ratelimit[T: Callable[..., Any]](
        self,
        requests: int,
        *,
        per: float,
        scope: str | None = None,
        key_func: Callable[[Request], str | None] | None = None,
    ) -> Callable[[T], T]:
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
        normalized_methods: set[str] = set()
        for method in methods:
            if not isinstance(method, str) or not _HTTP_METHOD_RE.fullmatch(method):
                raise ValueError("HTTP route methods must be non-empty RFC 9110 method tokens such as GET or QUERY.")
            normalized_methods.add(method.upper())
        if not normalized_methods:
            raise ValueError("HTTP routes require at least one method.")
        normalized = frozenset(normalized_methods)
        if "GET" in normalized:
            normalized = frozenset((*normalized, "HEAD"))
        plan = compile_endpoint_plan(endpoint, path)
        self._routes.append(Route(path, normalized, endpoint, plan, name=name))
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
                max_request_head_bytes=self.security.max_request_head_bytes,
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
        if not response.allow_public_cache:
            session_token = self._persist_session(req, response)
            if self.security.csrf_enabled:
                ensure_csrf_cookie(req, response, self.security, session_token=session_token)
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
        try:
            token_bytes = token.encode("ascii") if token is not None else None
            expected_bytes = expected.encode("ascii")
        except UnicodeEncodeError:
            token_bytes = None
            expected_bytes = b""
        if token_bytes is None or not secrets.compare_digest(token_bytes, expected_bytes):
            self._log_security_event(logging.WARNING, "metrics-auth-failed", req=req)
            return Response.text(
                "Unauthorized",
                status_code=401,
                headers={"www-authenticate": "Bearer"},
            )
        body, content_type = self._metrics.render()
        return Response(body=body, content_type=content_type)

    async def _handle_docs_request(self, req: Request) -> Response | None:
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

        auth_response = await self._authorize_docs_request(req)
        if auth_response is not None:
            return auth_response

        if req.path == openapi_path:
            return Response.json(self.openapi_spec())

        nonce = secrets.token_urlsafe(16)
        return Response.html(
            _swagger_ui_html(
                openapi_path=openapi_path,
                title=self.settings.API_TITLE,
                nonce=nonce,
            ),
            headers={
                "content-security-policy": (
                    "default-src 'self'; "
                    f"script-src 'self' https://unpkg.com 'nonce-{nonce}'; "
                    f"style-src 'self' https://unpkg.com 'nonce-{nonce}'; "
                    "img-src 'self' data:; "
                    "connect-src 'self'; "
                    "font-src https://unpkg.com; "
                    "object-src 'none'; "
                    "base-uri 'none'; "
                    "frame-ancestors 'none'; "
                    "form-action 'self'"
                )
            },
        )

    async def _authorize_docs_request(self, req: Request) -> Response | None:
        backend_name = self.settings.DOCS_AUTH_BACKEND
        if backend_name is None:
            return None
        backend = self._auth_backends.get(backend_name.strip())
        if backend is None:
            self._log_security_event(logging.ERROR, "docs-auth-backend-missing", req=req)
            return Response.text("Internal Server Error", status_code=500)
        if self._security_failure_is_limited(req):
            self._log_security_event(logging.WARNING, "security-failure-rate-limit-exceeded", req=req)
            return _security_rate_limit_response()
        try:
            identity = await _maybe_await(backend(req))
        except Exception:
            self._log_security_event(logging.ERROR, "docs-auth-backend-error", req=req)
            if self._register_security_failure(req):
                return _security_rate_limit_response()
            return Response.text("Internal Server Error", status_code=500)
        auth_result = _normalize_auth_identity(identity)
        resolved_user = auth_result.user or User.anonymous()
        req.scope["user"] = resolved_user
        _user_ctx.set(resolved_user)
        if not resolved_user.is_authenticated:
            self._log_security_event(logging.WARNING, "docs-auth-failed", req=req)
            if self._register_security_failure(req):
                return _security_rate_limit_response()
            return _permission_denied_response(resolved_user, challenge=auth_result.challenge)
        return None

    def openapi_spec(self) -> dict[str, Any]:
        """Return the cached OpenAPI document for the registered routes."""

        if self._openapi_cache is not None and not self._openapi_dirty:
            return self._openapi_cache
        spec = build_openapi_spec(
            routes=self._routes,
            route_auth=self._route_auth,
            auth_schemes=self._auth_backend_schemes,
            title=self.settings.API_TITLE,
            version=self.settings.API_VERSION,
            description=self.settings.API_DESCRIPTION,
            servers=self.settings.API_SERVERS,
            csrf_enabled=self.security.csrf_enabled,
            csrf_safe_methods=self.security.csrf_safe_methods,
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
        if self.security.max_validation_depth <= 0:
            raise ValueError("MAX_VALIDATION_DEPTH must be greater than 0.")
        if self.security.max_validation_work <= 0:
            raise ValueError("MAX_VALIDATION_WORK must be greater than 0.")
        if self.security.max_validation_issues < 2:
            raise ValueError("MAX_VALIDATION_ISSUES must be at least 2.")
        if self.security.security_failure_window_seconds <= 0:
            raise ValueError("SECURITY_FAILURE_WINDOW_SECONDS must be greater than 0.")
        if not self.settings.SSRF_ALLOWED_SCHEMES:
            raise ValueError("SSRF_ALLOWED_SCHEMES must not be empty. Include at least one scheme such as 'https'.")
        if not isinstance(self.settings.OTEL_SERVICE_NAME, str) or not self.settings.OTEL_SERVICE_NAME.strip():
            raise ValueError("OTEL_SERVICE_NAME must not be empty.")
        if self.settings.OTEL_SERVICE_VERSION is not None and not isinstance(self.settings.OTEL_SERVICE_VERSION, str):
            raise ValueError("OTEL_SERVICE_VERSION must be a string or None.")
        if (
            isinstance(self.settings.OTEL_TRACE_SAMPLE_RATIO, bool)
            or not isinstance(self.settings.OTEL_TRACE_SAMPLE_RATIO, int | float)
            or not 0 <= self.settings.OTEL_TRACE_SAMPLE_RATIO <= 1
        ):
            raise ValueError("OTEL_TRACE_SAMPLE_RATIO must be between 0 and 1 inclusive.")
        if any(not isinstance(path, str) or not path.startswith("/") for path in self.settings.OTEL_EXCLUDED_PATHS):
            raise ValueError("Every OTEL_EXCLUDED_PATHS entry must start with '/'.")
        if not self.settings.DOCS_PATH.startswith("/"):
            raise ValueError("DOCS_PATH must start with '/'. Example: '/docs'.")
        if not self.settings.OPENAPI_PATH.startswith("/"):
            raise ValueError("OPENAPI_PATH must start with '/'. Example: '/openapi.json'.")
        if self.settings.DOCS_PATH == self.settings.OPENAPI_PATH:
            raise ValueError("DOCS_PATH and OPENAPI_PATH must be different so each endpoint has its own URL.")
        if self.settings.DOCS_AUTH_BACKEND is not None and (
            not isinstance(self.settings.DOCS_AUTH_BACKEND, str) or not self.settings.DOCS_AUTH_BACKEND.strip()
        ):
            raise ValueError("DOCS_AUTH_BACKEND must be a non-empty registered backend name or None.")
        if any(not isinstance(url, str) or not url.strip() for url in self.settings.API_SERVERS):
            raise ValueError("API_SERVERS entries must be non-empty URL strings.")
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
            if not isinstance(token, str) or len(token) < 32 or _BEARER_TOKEN_RE.fullmatch(token) is None:
                raise ValueError(
                    "METRICS_BEARER_TOKEN must contain at least 32 bearer-safe ASCII characters "
                    "when metrics are enabled."
                )
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

        docs_response = await self._handle_docs_request(req)
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
        route_auth = self._route_auth.get(match.endpoint)
        rate_phase = "pre_auth" if route_auth is not None else "all"
        rate_limit_result = await self._check_rate_limits(req, match.endpoint, phase=rate_phase)
        if isinstance(rate_limit_result, Response):
            return await self._run_after_middleware(req, rate_limit_result)

        auth_response = await self._authorize_request(req, match.endpoint)
        if auth_response is not None:
            return auth_response

        if route_auth is not None:
            authenticated_rate_limit = await self._check_rate_limits(req, match.endpoint, phase="post_auth")
            if isinstance(authenticated_rate_limit, Response):
                return await self._run_after_middleware(req, authenticated_rate_limit)
            rate_limit_result.update(authenticated_rate_limit)

        raw_response = await self._call_endpoint(req, match)
        response = to_response(raw_response)
        response.headers.update(rate_limit_result)
        return await self._run_after_middleware(req, response)

    async def _check_rate_limits(
        self,
        req: Request,
        endpoint: Endpoint | WebSocketEndpoint,
        *,
        phase: str = "all",
    ) -> dict[str, str] | Response:
        headers: dict[str, str] = {}
        indexed_rules = [
            (index, rule)
            for index, rule in enumerate(endpoint_rate_limits(endpoint))
            if phase == "all"
            or (phase == "pre_auth" and rule.key_func is None)
            or (phase == "post_auth" and rule.key_func is not None)
        ]
        if not indexed_rules:
            return headers

        # Check all rules atomically using batch method
        rules_with_ids = [(rule, f"{id(endpoint)}:{index}") for index, rule in indexed_rules]
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
        arguments = await resolve_endpoint_arguments(match.endpoint_plan, req, match.params)
        value = match.endpoint(**arguments)
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

    def _otel_route_template(self, path: str) -> str | None:
        fallback: str | None = None
        for route in self._routes:
            if route.path_matches(path):
                if route.raw_path in self.settings.OTEL_EXCLUDED_PATHS:
                    return route.raw_path
                fallback = fallback or route.raw_path
        return fallback

    async def _handle_error(self, req: Request, exc: Exception) -> Response:
        if isinstance(exc, RequestValidationError):
            for klass in type(exc).__mro__:
                handler = self._error_handlers.get(klass)
                if handler is not None:
                    return to_response(await _maybe_await(handler(req, exc)))
            return Response.json(
                {
                    "error": "validation_error",
                    "detail": "Request validation failed.",
                    "errors": [issue.as_dict() for issue in exc.issues],
                },
                status_code=422,
            )
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

    def _persist_session(self, req: Request, response: Response) -> str | None:
        current = req.scope.get("session")
        if not isinstance(current, Session) or not current.modified:
            return req.cookies.get(self.security.session_cookie_name)
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
            return ""
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
        return token

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
        if self._security_failure_is_limited(req):
            self._log_security_event(logging.WARNING, "security-failure-rate-limit-exceeded", req=req)
            return _security_rate_limit_response()

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

    def _security_failure_is_limited(self, req: Request) -> bool:
        limit = self.security.security_failure_rate_limit
        if limit <= 0:
            return False
        client = req.client_ip or "unknown"
        state = self._security_failures.get(client)
        if state is None:
            return False
        start, count = state
        if time.monotonic() - start >= self.security.security_failure_window_seconds:
            self._security_failures.pop(client, None)
            return False
        return count >= limit

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


def _swagger_ui_html(*, openapi_path: str, title: str, nonce: str) -> str:
    safe_title = html.escape(title, quote=True)
    safe_nonce = html.escape(nonce, quote=True)
    openapi_path_json = json.dumps(openapi_path)
    return f"""<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{safe_title} Docs</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@{_SWAGGER_UI_VERSION}/swagger-ui.css"
      integrity="{_SWAGGER_UI_CSS_INTEGRITY}" crossorigin="anonymous" />
    <style nonce="{safe_nonce}">
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
    <script src="https://unpkg.com/swagger-ui-dist@{_SWAGGER_UI_VERSION}/swagger-ui-bundle.js"
      integrity="{_SWAGGER_UI_JS_INTEGRITY}" crossorigin="anonymous"></script>
    <script nonce="{safe_nonce}">
      window.ui = SwaggerUIBundle({{
        url: {openapi_path_json},
        dom_id: "#swagger-ui",
        deepLinking: true,
        queryConfigEnabled: false,
        validatorUrl: null,
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


def _request_head_size(scope: Scope) -> int:
    """Return a conservative byte count for an ASGI HTTP request head."""

    method = str(scope.get("method", "GET")).encode("ascii", "replace")
    raw_path = scope.get("raw_path")
    path = raw_path if isinstance(raw_path, bytes) else str(scope.get("path", "/")).encode("utf-8")
    query = scope.get("query_string", b"")
    query_bytes = query if isinstance(query, bytes) else b""
    target_size = len(path) + (1 + len(query_bytes) if query_bytes else 0)
    version = str(scope.get("http_version", "1.1")).encode("ascii", "replace")
    size = len(method) + 1 + target_size + len(b" HTTP/") + len(version) + len(b"\r\n")
    for name, value in scope.get("headers", []):
        if not isinstance(name, bytes) or not isinstance(value, bytes):
            continue
        size += len(name) + len(b": ") + len(value) + len(b"\r\n")
    return size + len(b"\r\n")


def _status_text(status_code: int) -> str:
    return {
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        408: "Request Timeout",
        413: "Payload Too Large",
        431: "Request Header Fields Too Large",
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


def _websocket_rate_limit_headers(response: Response) -> dict[str, str]:
    return {
        name: value
        for name, value in response.headers.items()
        if name == "retry-after" or name.startswith("ratelimit-") or name.startswith("x-ratelimit-")
    }


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
