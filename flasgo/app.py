from __future__ import annotations

import asyncio
import html
import inspect
import json
import logging
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from contextvars import ContextVar
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .auth import (
    AuthBackend,
    AuthIdentity,
    AuthResult,
    IsAuthenticated,
    Permission,
    PermissionLike,
    User,
)
from .debug import Debug
from .exceptions import HTTPException
from .openapi import build_openapi_spec
from .ratelimit import (
    RateLimiter,
    build_rate_limit_response,
    endpoint_rate_limits,
    rate_limit_success_headers,
)
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
from .ssrf import SSRFConfig, SSRFGuard, SSRFResolvedURL
from .staticfiles import StaticDirectory, build_static_response, resolve_static_directory
from .templating import JinjaTemplates
from .types import Receive, Scope, Send

if TYPE_CHECKING:
    from .testing import TestClient

BeforeMiddleware = Callable[[Request], ResponseValue | Awaitable[ResponseValue] | None]
AfterMiddleware = Callable[[Request, Response], ResponseValue | Awaitable[ResponseValue]]
ErrorHandler = Callable[[Request, Exception], ResponseValue | Awaitable[ResponseValue]]

_request_ctx: ContextVar[Request | None] = ContextVar("flasgo_request", default=None)
_session_ctx: ContextVar[Session | None] = ContextVar("flasgo_session", default=None)
_user_ctx: ContextVar[User | None] = ContextVar("flasgo_user", default=None)


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
        self._static_directories: list[StaticDirectory] = []
        self._before: list[BeforeMiddleware] = []
        self._after: list[AfterMiddleware] = []
        self._error_handlers: dict[type[Exception], ErrorHandler] = {}
        self._session_signer = SessionSigner(self.security.secret_key)
        self._auth_backends: dict[str, AuthBackend] = {"default": _default_auth_backend}
        self._route_auth: dict[Endpoint, RouteAuth] = {}
        self._rate_limiter = RateLimiter()
        self._openapi_cache: dict[str, Any] | None = None
        self._openapi_dirty = True
        self._security_failures: dict[str, tuple[float, int]] = {}
        self._logger = logging.getLogger("flasgo.security")
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
        if scope.get("type") != "http":
            response = Response.text(
                "Unsupported ASGI scope type. Flasgo only handles HTTP requests.",
                status_code=500,
            )
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
            await response.send(send, head_only=req.method == "HEAD")
        except Exception:
            self._log_security_event(
                logging.ERROR,
                "response-send-failed",
                req=req,
            )
            fallback = Response.text(
                "Internal Server Error. Check the application logs for the original failure.",
                status_code=500,
            )
            apply_security_headers(fallback, self.security)
            await fallback.send(send, head_only=req.method == "HEAD")

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
            raise ValueError("Auth backend name must not be empty. Pass a stable name such as 'default' or 'bearer'.")
        self._auth_backends[normalized] = backend

    def authorize(
        self,
        *permissions: PermissionLike,
        backend: str = "default",
    ) -> Callable[[Endpoint], Endpoint]:
        backend_name = backend.strip()
        if not backend_name:
            raise ValueError("Auth backend name must not be empty. Pass the name used in register_auth_backend(...).")

        def decorator(endpoint: Endpoint) -> Endpoint:
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
        from .ratelimit import rate_limit

        return rate_limit(requests, per=per, scope=scope, key_func=key_func)

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

    def run(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 8000,
        reload: bool | None = None,
        reload_dirs: Sequence[str | Path] | None = None,
    ) -> None:
        asyncio.run(
            run_dev_server(
                self,
                host,
                port,
                reload=bool(self.settings.DEBUG) if reload is None else reload,
                reload_dirs=reload_dirs,
                max_request_body_bytes=self.security.max_request_body_bytes,
                max_request_head_bytes=self.security.max_request_head_bytes,
                request_read_timeout_seconds=self.security.request_read_timeout_seconds,
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
        if self.security.secret_key == "dev-insecure-secret-change-this":
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

    async def _dispatch(self, req: Request) -> Response:
        if self.security.enforce_allowed_hosts and not host_is_allowed(
            req.headers.get("host"), allowed_hosts=self.security.allowed_hosts
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

        docs_response = self._handle_docs_request(req)
        if docs_response is not None:
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
        for index, rule in enumerate(endpoint_rate_limits(endpoint)):
            decision = await self._rate_limiter.check(
                rule,
                req,
                endpoint_id=f"{id(endpoint)}:{index}",
            )
            if not decision.allowed:
                self._log_security_event(logging.WARNING, "rate-limit-exceeded", req=req)
                return build_rate_limit_response(decision)
            headers.update(rate_limit_success_headers(decision))
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
        self._logger.log(
            level,
            "%s method=%s path=%s client=%s",
            _sanitize_log_value(event),
            _sanitize_log_value(req.method),
            _sanitize_log_value(req.path),
            _sanitize_log_value(req.client_ip),
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
