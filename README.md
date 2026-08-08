# Flasgo
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/L1ghtn1ng/flasgo) [![PyPI version](https://img.shields.io/pypi/v/flasgo.svg)](https://pypi.org/project/flasgo/)

Flasgo is an async-first Python web framework designed as a hybrid of:
- Flask ergonomics: decorator-based routing, minimal ceremony, quick iteration.
- Django security defaults: CSRF protection, host validation, secure headers, signed sessions.

The current framework release is `0.7.0`.

## Project goals

- Fast request handling with an ASGI core.
- First-class async support.
- Type-safe APIs with strict tooling.
- Minimal moving parts and sensible defaults.

## Requirements

- Python `>=3.14`
- Tooling: `uv`, `ruff`, `ty`, `pytest`

## Install in your project

```bash
uv add flasgo
```

Or with `pip`:

```bash
pip install flasgo
```

## Quick start

```bash
uv venv
uv sync --all-groups
```

Create `app.py`:

```python
import os
import secrets

from flasgo import Flasgo, Request, Response, redirect

app = Flasgo(
    static_folder="static",
    settings={
        "DEBUG": True,
        "SECRET_KEY": os.environ.get("FLASGO_SECRET_KEY", secrets.token_urlsafe(32)),
        "ALLOWED_HOSTS": {"127.0.0.1", "localhost"},
        "CSRF_ENABLED": True,
        "SESSION_COOKIE_SECURE": False,
        "CSRF_COOKIE_SECURE": False,
    },
)


@app.get("/")
async def home():
    return {"framework": "flasgo", "status": "ok"}


@app.post("/contact")
async def contact(request: Request) -> Response:
    form = await request.form()
    if form.get("email"):
        return redirect("/thanks")
    return Response.json({"error": "email is required"}, status_code=400)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, reload=True)
```

Run:

```bash
export FLASGO_SECRET_KEY="$(openssl rand -hex 32)"
uv run flasgo run app.py --reload
```

## Development run

Built-in dev server with automatic reload:

```bash
uv run flasgo run app.py --reload
```

Or explicitly:

```python
app.run(host="127.0.0.1", port=8000, reload=True)
```

The CLI also accepts import strings:

```bash
uv run flasgo run package.module:app --reload
```

You can still use `uvicorn` with reload:

```bash
uv run uvicorn app:app --reload --host 127.0.0.1 --port 8000
```

`app.run(...)` and `flasgo run` use Uvicorn's H11 implementation with proxy-header trust disabled, bounded HTTP
request heads and WebSocket queues/messages, lifespan enabled, and per-message compression disabled. Flasgo also
enforces `MAX_REQUEST_BODY_BYTES`, `MAX_REQUEST_HEAD_BYTES`, and `REQUEST_READ_TIMEOUT_SECONDS` inside the app so
those limits remain active under another ASGI server. The built-in runner is intended for local development;
configure a production ASGI process explicitly for deployment.

## WebSockets, lifespan, and background tasks

WebSocket routes use the same path converters, authorization decorators, and `@app.ratelimit(...)` rules as HTTP
routes. Flasgo checks the `Host` and exact `Origin` before acceptance, rejects missing origins by default, limits
messages to 64 KiB and 120 messages per minute per connection, and never writes modified sessions back through a
WebSocket handshake. Authentication failures and default per-IP route limits are enforced before an authentication
backend runs.

```python
from collections.abc import AsyncGenerator

from flasgo import Flasgo, Response, WebSocket

app = Flasgo()


@app.lifespan
async def lifespan(app: Flasgo) -> AsyncGenerator[None, None]:
    app.state.ready = True  # process-global; never store request data here
    yield
    app.state.ready = False


@app.websocket("/rooms/<int:room_id>")
async def room(websocket: WebSocket, room_id: int) -> None:
    await websocket.accept()
    async for message in websocket.iter_json():
        await websocket.send_json({"room": room_id, "echo": message})


@app.post("/jobs")
async def create_job() -> Response:
    response = Response.json({"accepted": True}, status_code=202)
    response.add_task(record_audit_event, "job-created")
    return response
```

Background tasks run sequentially after the final buffered response is sent successfully. A task failure is logged
and does not stop later tasks. Tasks are in-process best effort work, so use a durable queue for critical jobs.

For cross-origin WebSockets, add exact origins such as `https://app.example.com` to
`WEBSOCKET_ALLOWED_ORIGINS`. Set `WEBSOCKET_ALLOW_MISSING_ORIGIN=True` only for non-browser clients whose
authentication model does not rely on ambient cookies.

## Production deployment

Use a production ASGI server process and configure secrets with environment variables:

```python
import os
from flasgo import Flasgo

app = Flasgo(
    settings={
        "DEBUG": False,
        "SECRET_KEY": os.environ["FLASGO_SECRET_KEY"],
        "ALLOWED_HOSTS": {"api.example.com"},
        "CSRF_ENABLED": True,
        "SESSION_COOKIE_SECURE": True,
        "CSRF_COOKIE_SECURE": True,
        "SESSION_COOKIE_HTTP_ONLY": True,
    }
)
```

Run with workers:

```bash
export FLASGO_SECRET_KEY="$(openssl rand -hex 32)"
uv run uvicorn app:app --host 0.0.0.0 --port 8000 --workers 4
```

Put a reverse proxy/load balancer in front (Caddy, Cloudflare, etc.) for TLS termination and network controls.

## Security defaults

- Host header allowlist (`localhost`, `127.0.0.1` by default).
- HMAC-signed, session-bound CSRF double-submit cookie defense for unsafe methods.
- Signed session cookies (HMAC-SHA256).
- No-store cache headers by default to reduce sensitive data caching (CWE-524 mitigation).
- Static file path traversal and symlink escape protections.
- Request body/head limits and read timeouts at the application boundary, with H11 head limits in the built-in
  development server.
- Bounded validation depth, work, and returned issue counts.
- Optional per-client throttling for repeated security failures (`429`).
- Per-route rate limiting with `@app.ratelimit(...)` / `@rate_limit(...)`, using the ASGI client IP by default.
- Fail-closed rate-limit key capacity that preserves active quota accounting rather than evicting it under churn.
- Security event logging for host/CSRF/authz denials.
- Same-origin WebSocket handshakes, pre-accept auth, bounded messages, and connection-level message throttling.
- Locally generated request IDs by default; incoming IDs are ignored unless strict opt-in validation is enabled.
- Hardened headers (`CSP`, `HSTS`, `X-Frame-Options`, `Referrer-Policy`, etc.).

These defaults are intended to help teams avoid common OWASP Top 10 2025 failure modes around broken access control, cryptographic failures, security misconfiguration, software and data integrity issues, and SSRF.

## Rate limiting

Use `@app.ratelimit(requests, per=seconds)` on any route that needs abuse protection. Flasgo uses an in-process sliding-window counter keyed by the direct ASGI client IP address by default, returns `429 Too Many Requests` without running the endpoint body, and includes `Retry-After`, `RateLimit-*`, and `X-RateLimit-*` headers so clients know when to retry.

```python
from flasgo import Flasgo, rate_limit

app = Flasgo()


@app.post("/login")
@app.ratelimit(5, per=60)
def login():
    return {"ok": True}


@app.get("/reports")
@rate_limit(20, per=60, scope="expensive-reports")
def reports():
    return {"reports": []}


@app.get("/report-summary")
@rate_limit(20, per=60, scope="expensive-reports")
def report_summary():
    return {"summary": []}
```

Routes with the same `scope` share one quota, which is useful when several endpoints perform the same expensive operation. For authenticated APIs, pass a `key_func` to limit by a stable user or API-key identity instead of only by IP:

```python
@app.get("/me")
@app.ratelimit(100, per=60, key_func=lambda req: req.user.id if req.user else req.client_ip)
def me():
    return {"ok": True}
```

For protected HTTP and WebSocket routes, default IP-based rules execute before authentication so abusive requests do
not repeatedly invoke a backend. Rules with a custom `key_func` execute after successful authentication so they can
use the authenticated identity. Repeated authentication failures are also subject to the security-failure limiter.

The built-in limiter intentionally does not trust `X-Forwarded-For` by default because that header is client-controlled unless a trusted reverse proxy has sanitized it. In multi-process or multi-host production deployments, use a shared external limiter at the edge or a future shared-storage backend so all workers enforce the same quota.

## Typed request data and dependencies

Use `typing.Annotated` markers to bind and validate request data. Models use standard-library dataclasses; no
validation package is required. Path parameters continue to be inferred from the route, and unmarked non-path
parameters remain query parameters for compatibility.

```python
from dataclasses import dataclass
from typing import Annotated

from flasgo import Body, Cookie, Depends, Flasgo, Header, Query


@dataclass
class CreateWidget:
    name: str
    quantity: int


def page_size(limit: Annotated[int, Query(alias="page-size")] = 20) -> int:
    return limit


app = Flasgo()


@app.post("/widgets")
def create_widget(
    payload: Annotated[CreateWidget, Body()],
    limit: Annotated[int, Depends(page_size)],
    client_version: Annotated[int, Header()] = 1,
    session_id: Annotated[str, Cookie(alias="session-id")] = "anonymous",
) -> dict[str, object]:
    return {
        "name": payload.name,
        "quantity": payload.quantity,
        "limit": limit,
        "client_version": client_version,
        "session_id": session_id,
    }
```

`Body()` accepts JSON and `Form()` accepts URL-encoded or multipart data. `Header()` maps underscores to hyphens by
default, while scalar `Cookie()` uses the exact parameter name; both accept explicit aliases. Duplicate scalar headers
and duplicate cookie names are rejected instead of silently selecting a value. Collection headers accept both repeated
fields and OpenAPI `simple` comma-separated values. Optional collection unions and integer/boolean-valued enums are
converted from query, header, cookie, and form text before validation. Invalid values return safe JSON with status
`422` and field locations. `FormValidationError` also retains the parsed `FormData` for an explicit error handler to
redisplay safe fields in an HTML form. Dependencies may be sync or async, can depend on other providers, and are cached
once per request by default; use `Depends(provider, use_cache=False)` only when repeated execution is intentional.
Declare providers at module scope when using postponed annotations so Python can resolve their names.

Validation uses shared per-request budgets controlled by `MAX_VALIDATION_DEPTH`, `MAX_VALIDATION_WORK`, and
`MAX_VALIDATION_ISSUES`. When a limit is reached, Flasgo stops further recursive or union evaluation and returns one
bounded `validation_limit` or `too_many_errors` issue without reflecting rejected values.

The same per-route endpoint plan drives runtime binding and OpenAPI generation, so request models, aliases, validation
responses, and dependency-provided query fields stay aligned. Duplicate wire parameters merge requiredness when their
schemas agree; conflicting schemas are rejected instead of producing an inaccurate contract.

## Developer commands

```bash
uv lock --check
uv sync --frozen --group dev
uv pip check
uv run --frozen ruff check .
uv run --frozen ty check
uv run --frozen pytest
uv audit --frozen
uv build
git diff --check
```

## Operations and CLI

Set `LOG_FORMAT="json"` for bounded structured Flasgo logs. Every HTTP request and WebSocket connection gets a
locally generated request ID; opt into a trusted upstream ID only with `TRUST_INCOMING_REQUEST_ID=True`.

Prometheus metrics are an optional extra and are disabled by default:

```bash
uv add 'flasgo[metrics]'
```

```python
import os

from flasgo import Flasgo

app = Flasgo(
    settings={
        "METRICS_ENABLED": True,
        "METRICS_BEARER_TOKEN": os.environ["FLASGO_METRICS_TOKEN"],  # 32+ bearer-safe ASCII characters
    }
)
```

The `/metrics` endpoint requires that bearer token, does not instrument itself, and labels HTTP metrics with route
templates rather than user-controlled paths. The configured secret must use the standard bearer-token ASCII
character set; malformed or non-ASCII request credentials receive `401 Unauthorized`.

OpenTelemetry tracing is a separate optional extra. It keeps Prometheus as the metrics implementation and exports
traces over OTLP/HTTP using standard OpenTelemetry environment variables:

```bash
uv add 'flasgo[otel]'
export OTEL_EXPORTER_OTLP_ENDPOINT="https://otel-collector.example.com"
export OTEL_EXPORTER_OTLP_HEADERS="authorization=Bearer%20${OTEL_TOKEN}"
```

```python
app = Flasgo(
    settings={
        "OTEL_ENABLED": True,
        "OTEL_SERVICE_NAME": "billing-api",
        "OTEL_SERVICE_VERSION": "1.4.0",
        "OTEL_TRACE_SAMPLE_RATIO": 0.25,
        "OTEL_EXCLUDED_PATHS": {"/health"},
    }
)
```

HTTP span names and `http.route` use bounded route templates. Known methods (including `QUERY`) appear in the span
name; unknown methods use the stable `HTTP` placeholder so trace-name cardinality stays bounded. HTTP URL attributes
contain the real request path so stable OpenTelemetry semantic conventions remain accurate, while every non-empty
query value is replaced with `REDACTED` before instrumentation. WebSocket URL attributes remain template-only. `OTEL_EXCLUDED_PATHS` accepts
either exact paths or route templates such as `/reset/<token>`; template exclusions also apply to `405 Method Not
Allowed` requests, and `/metrics` is always excluded. Export runs in the SDK
batch processor, and Flasgo shuts down only tracer providers it creates. A Flasgo-built provider is also registered
as the process-global tracer provider so other OpenTelemetry instrumentations share its sampler and exporter; set
`OTEL_SET_GLOBAL_PROVIDER` to `False` to keep it private. Pass
`tracer_provider=` to `Flasgo(...)` for tests or an application-owned provider; its lifecycle remains caller-owned.
Active trace and span IDs are added to Flasgo event logs automatically.
Rejected or ambiguous `Host` values are removed from the scope passed to instrumentation before a denial response is
traced, preventing invalid authority data from entering span URL attributes.

Inspect an app without starting a server:

```bash
uv run flasgo routes app.py
uv run flasgo openapi app.py --output openapi.json
uv run flasgo check app.py
```

Optional database migrations delegate to Alembic without adding an ORM to Flasgo:

```bash
uv add 'flasgo[db]'
uv run flasgo db init
uv run flasgo db migrate -m "create users"
uv run flasgo db upgrade
```

## Codebase guide

Flasgo keeps each framework concern in a small module so new contributors can change one area without needing to understand the whole project at once:

- `flasgo/app.py`: ASGI entrypoint, request dispatch, middleware, routing integration, sessions, auth checks, rate-limit enforcement, and error handling.
- `flasgo/routing.py`: Flask-style path parsing and route matching.
- `flasgo/request.py`: request headers, cookies, query strings, body parsing, JSON, and forms.
- `flasgo/response.py`: response objects, response coercion, redirects, JSON, templates, and header validation.
- `flasgo/websockets.py`: WebSocket state, messages, close handling, and protocol limits.
- `flasgo/background.py`: post-response best-effort task execution.
- `flasgo/params.py`, `flasgo/validation.py`, and `flasgo/di.py`: endpoint plans, stdlib validation, and dependency resolution.
- `flasgo/openapi.py`: OpenAPI operations, request/response schemas, validation contracts, and auth requirements.
- `flasgo/jwt.py`: optional strict HS256 token encoding and authentication backend.
- `flasgo/logging.py`, `flasgo/metrics.py`, and `flasgo/telemetry.py`: request correlation and optional observability.
- `flasgo/security.py`: security configuration, CSRF, allowed hosts, secure cookies, and default security headers.
- `flasgo/ratelimit.py`: route decorator metadata and the in-process sliding-window limiter.
- `flasgo/auth.py`: users, auth backends, permissions, and bearer-token helpers.
- `flasgo/session.py`: signed session serialization.
- `flasgo/staticfiles.py`: static file resolution and safe file serving.
- `flasgo/templating.py`: Jinja environment setup and template loading protections.
- `flasgo/testing.py`: synchronous and async ASGI test client.

When adding a feature, prefer the existing pattern: keep public decorators on `Flasgo`, keep standalone helpers
importable from `flasgo`, add focused tests beside related behavior, and run the verification bundle above before
handing off.

## Public API surface

- CLI: `run`, `routes`, `openapi`, `check`, and optional `db` migration commands
- Core types: `Flasgo`, `Settings`, `Request`, `Response`, `Session`, `BackgroundTasks`
- Routing and lifecycle: `Flasgo.route`, `Flasgo.get`, `Flasgo.post`, `Flasgo.put`, `Flasgo.patch`,
  `Flasgo.delete`, `Flasgo.websocket`, `Flasgo.lifespan`, `Flasgo.state`, `Flasgo.before_request`,
  `Flasgo.after_request`, `Flasgo.errorhandler`
- App integrations: `Flasgo.register_auth_backend`, `Flasgo.authorize`, `Flasgo.ratelimit`,
  `Flasgo.configure_templates`, `Flasgo.render_template`, `Flasgo.configure_static`, `Flasgo.test_client`,
  `Flasgo.resolve_outbound_url`, `Flasgo.openapi_spec`
- Parameter and validation helpers: `Body`, `Query`, `Header`, `Cookie`, `Form`, `Depends`, `ValidationIssue`,
  `RequestValidationError`, `FormValidationError`
- Request data: `FormData`, `UploadedFile`
- HTTP errors: `HTTPException`, `abort`
- Auth and identity: `User`, `AuthResult`, `AllowAny`, `IsAuthenticated`, `HasScope`, `bearer_token_backend`,
  `extract_bearer_token`, `jwt_backend`, `encode_jwt`
- Rate limiting: `RateLimitRule`, `rate_limit`
- WebSockets: `WebSocket`, `WebSocketDisconnect`, `WebSocketException`
- Testing: `TestClient`, `TestResponse`, `SyncWebSocketSession`, `AsyncWebSocketSession`,
  `WebSocketHandshakeError`
- Flask-style globals and responses: `request`, `session`, `current_user`, `jsonify`, `redirect`,
  `Response.redirect`
- Templating: `BaseLoader`, `SecureTemplateLoader`, `JinjaTemplates`, `Template`, `TemplateNotFound`,
  `create_template_environment`, `render_template`, `Response.template`
- Logging: `FlasgoJSONFormatter`, `configure_logging`
- SSRF controls: `SSRFConfig`, `SSRFGuard`, `SSRFResolvedURL`, `SSRFViolation`
- Flask-style path params: `<name>`, `<int:name>`, `<float:name>`, `<path:name>`
- Optional OpenAPI spec + Swagger UI docs (disabled by default)
- Response coercion:
  - `str` / `bytes`
  - `dict` / `list` (JSON)
  - `(body, status)` / `(body, status, headers)`
  - `Response`
  - dataclass instances (JSON)

## Flask-style globals

```python
from flasgo import Flasgo, jsonify, request

app = Flasgo()


@app.get("/inspect")
def inspect():
    return jsonify({"method": request.method, "path": request.path})
```

## Templating

Flasgo includes a Jinja2 wrapper with secure defaults for HTML rendering:

- Sandboxed environment
- Strict undefined variables
- Autoescaping enabled by default
- Loader protections against path traversal and symlink escapes outside configured template roots

Create the environment once during app startup and reuse it:

```python
from flasgo import Flasgo, Response

app = Flasgo()
app.configure_templates("templates")


@app.get("/")
def home() -> Response:
    return Response.template(
        "home.html",
        templates=app.templates,
        context={"title": "Welcome"},
    )
```

If you only need the rendered string, use the app helper:

```python
html = app.render_template("home.html", {"title": "Welcome"})
```

## Forms

Flasgo has built-in parsing for `application/x-www-form-urlencoded` and `multipart/form-data`:

```python
from flasgo import Flasgo, Request

app = Flasgo()


@app.post("/signup")
async def signup(request: Request) -> dict[str, object]:
    form = await request.form()
    avatar = form.file("avatar")
    return {
        "email": form.get("email"),
        "interests": form.getlist("interests"),
        "avatar_name": avatar.filename if avatar else None,
    }
```

`await request.form()` returns a `FormData` object with `get`, `getlist`, `file`, and `filelist`.

When request parsing fails, Flasgo returns actionable `400` responses. For example, invalid JSON from `await request.json()` tells the caller to send valid JSON with `Content-Type: application/json`, and malformed multipart requests explain that the boundary/header is missing.

## Static files

You can register static assets at app construction time or later:

```python
from flasgo import Flasgo

app = Flasgo(static_folder="static")
app.configure_static("assets", url_path="/assets", cache_max_age=86400)
```

Static responses use safe path normalization, block dotfiles and directory escapes, and include `ETag` and
`Last-Modified` headers for cache validation. `GET` bodies stream in bounded 64 KiB chunks through worker threads;
`HEAD` returns the same metadata without opening or reading the file. Publicly cacheable responses do not emit
framework-managed CSRF or session cookies.

## Testing

Flasgo ships with an official test client:

```python
from flasgo import Flasgo

# Testing example only. For browser-facing production apps keep CSRF enabled.
app = Flasgo(settings={"CSRF_ENABLED": False})
client = app.test_client()

response = client.post("/api/login", json={"username": "alice"})
assert response.status_code == 200
```

The client supports cookies, `json=`, `data=`, multipart `files=`, `follow_redirects=True`, and async requests via
`await client.arequest(...)`. Pass `headers=[("x-version", "1"), ("x-version", "2")]` when a test must preserve
repeated wire headers. Use the client as a context manager for lifespan and WebSocket tests:

```python
with app.test_client() as client:
    with client.websocket_connect("/rooms/1") as websocket:
        websocket.send_json({"message": "hello"})
        assert websocket.receive_json()["echo"]["message"] == "hello"
```

## Flask migration guide

See [MIGRATING_FROM_FLASK.md](MIGRATING_FROM_FLASK.md) for the canonical Flask to Flasgo migration guide, including official examples for templates, JSON routes, redirects, forms, static files, testing, and ASGI deployment.

## Django-like settings

```python
from flasgo import Flasgo

app = Flasgo(
    settings={
        "SECRET_KEY": "replace-in-production",
        "ALLOWED_HOSTS": {"api.example.com"},
        "CSRF_ENABLED": True,
    }
)
```

You can also pass a Python module path string (`"myproject.settings"`), and Flasgo will load uppercase settings attributes.

## Auth and permissions

```python
from flasgo import Flasgo, HasScope, IsAuthenticated, User, bearer_token_backend

app = Flasgo()


def validate_token(token: str):
    if token == "token-123":
        return User(id="alice", is_authenticated=True, scopes=frozenset({"admin"}))
    return None


app.register_auth_backend("bearer", bearer_token_backend(validate_token))


@app.get("/admin")
@app.authorize(IsAuthenticated(), HasScope("admin"), backend="bearer")
def admin():
    return "ok"
```

Auth behavior:

- Unauthenticated requests are denied with `401 Unauthorized`.
- Authenticated requests without permission are denied with `403 Forbidden`.
- `405 Method Not Allowed` responses include an `Allow` header so clients can retry with a supported method.
- `HasScope(...)` permissions are emitted as sorted OpenAPI security scopes (or roles for non-OAuth schemes).

Custom backends can declare a local OpenAPI 3.2 Security Scheme Object at registration. The metadata describes the
credentials accepted by the application-owned backend; it does not implement an OAuth authorization server:

```python
app.register_auth_backend(
    "deviceOAuth",
    bearer_token_backend(validate_token),
    openapi_scheme={
        "type": "oauth2",
        "oauth2MetadataUrl": "https://identity.example.com/.well-known/oauth-authorization-server",
        "flows": {
            "deviceAuthorization": {
                "deviceAuthorizationUrl": "https://identity.example.com/device",
                "tokenUrl": "https://identity.example.com/token",
                "scopes": {"read": "Read account data"},
            }
        },
    },
)
```

Flasgo validates and copies this metadata when the backend is registered. OAuth and OpenID URLs must use HTTPS,
`deprecated` and JSON-safe `x-` extensions are supported, and external Security Scheme references are intentionally
rejected to avoid downstream dereferencing and name-resolution hazards.

`bearer_token_backend(..., scheme="Token")` advertises the configured case-normalized HTTP authentication scheme.
Prefixes that are not valid HTTP authentication-scheme tokens remain usable at runtime but receive no automatic
OpenAPI security metadata; supply an accurate local `openapi_scheme` explicitly if the backend has a standard contract.

For a self-contained HS256 bearer backend, install `flasgo[jwt]` and register the strict helper:

```python
import os

from flasgo import HasScope, IsAuthenticated, jwt_backend

app.register_auth_backend(
    "jwtAuth",
    jwt_backend(
        os.environ["JWT_SECRET"],  # at least 32 bytes
        issuer="https://identity.example.com",
        audience="billing-api",
    ),
)


@app.get("/admin")
@app.authorize(IsAuthenticated(), HasScope("admin"), backend="jwtAuth")
def admin():
    return {"ok": True}
```

The helper accepts HS256 only and requires `iss`, `aud`, `exp`, `iat`, and `sub`. Prefer short-lived tokens in the
`Authorization: Bearer` header; never put tokens in query strings. Authorized routes automatically reference the
registered JWT bearer scheme in OpenAPI.

## SSRF protection helpers (CWE-918)

For outbound URLs from user input, resolve a pinned connection target before fetching:

```python
from flasgo import Flasgo

app = Flasgo(
    settings={
        "SSRF_ALLOWED_SCHEMES": {"https"},
        "SSRF_ALLOWED_HOSTS": {"api.example.com"},
    }
)

target = app.resolve_outbound_url("https://api.example.com/data")
```

By default, Flasgo blocks unsafe schemes, embedded credentials, localhost/private network targets, and unresolved
hosts. `SSRF_ALLOW_PRIVATE_NETWORKS=True` permits only RFC 1918 IPv4 and unique-local IPv6 destinations; loopback,
link-local, multicast, reserved, and unspecified addresses remain blocked. Connect to `target.url` and send
`target.host_header` as the HTTP `Host` header when your HTTP client supports it.

## Automatic API docs

Flasgo can expose:

- OpenAPI JSON (default path: `/openapi.json`)
- Swagger UI (default path: `/docs`)

Docs are disabled by default for safer production posture. Enable and customize with settings:

```python
import hmac
import os

from flasgo import Flasgo, User, bearer_token_backend

docs_token = os.environ["FLASGO_DOCS_TOKEN"]


def validate_docs_token(token: str) -> User | None:
    if hmac.compare_digest(token, docs_token):
        return User(id="docs", is_authenticated=True)
    return None


app = Flasgo(
    settings={
        "ENABLE_DOCS": True,
        "DOCS_AUTH_BACKEND": "docs",
        "DOCS_PATH": "/api-docs",
        "OPENAPI_PATH": "/api/openapi.json",
        "API_TITLE": "My API",
        "API_VERSION": "1.2.3",
        "API_DESCRIPTION": "Internal service API",
        "API_SERVERS": ["https://api.example.com"],
    }
)

app.register_auth_backend("docs", bearer_token_backend(validate_docs_token))
```

Generated OpenAPI 3.2 operations document the framework error responses that apply to them: `413`/`415` on body and form
endpoints, `403` on unsafe methods while CSRF protection is enabled, `429` on rate-limited routes, and `401`/`403`
on authorized routes. The generated document declares the JSON Schema 2020-12 dialect and is validated in the test
suite. Standard operations, including `QUERY`, use Path Item fields; other valid HTTP methods use OpenAPI 3.2
`additionalOperations`. Swagger UI is pinned to an exact distribution with subresource-integrity hashes; its inline
script and style run under a rotating per-request CSP nonce. Set `DOCS_AUTH_BACKEND` to protect both documentation
endpoints with an existing authentication backend whenever they are reachable beyond a trusted development environment.
See [OPENAPI_OTEL_COMPLIANCE_REPORT.md](OPENAPI_OTEL_COMPLIANCE_REPORT.md) for the implemented conformance matrix,
security boundaries, and deployment checks.

The framework core remains intentionally small so its security and runtime behavior stay straightforward to audit.
