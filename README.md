# Flasgo
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/L1ghtn1ng/flasgo) [![PyPI version](https://img.shields.io/pypi/v/flasgo.svg)](https://pypi.org/project/flasgo/)

Flasgo is an async-first Python web framework designed as a hybrid of:
- Flask ergonomics: decorator-based routing, minimal ceremony, quick iteration.
- Django security defaults: CSRF protection, host validation, secure headers, signed sessions.

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

`app.run(...)` uses the built-in dev server and should only be used for local development.

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
- CSRF double-submit cookie defense for unsafe methods.
- Signed session cookies (HMAC-SHA256).
- No-store cache headers by default to reduce sensitive data caching (CWE-524 mitigation).
- Static file path traversal and symlink escape protections.
- Request body/head limits and read timeouts in the built-in dev server.
- Optional per-client throttling for repeated security failures (`429`).
- Per-route rate limiting with `@app.ratelimit(...)` / `@rate_limit(...)`, using the ASGI client IP by default.
- Security event logging for host/CSRF/authz denials.
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

The built-in limiter intentionally does not trust `X-Forwarded-For` by default because that header is client-controlled unless a trusted reverse proxy has sanitized it. In multi-process or multi-host production deployments, use a shared external limiter at the edge or a future shared-storage backend so all workers enforce the same quota.

## Developer commands

```bash
uv run ruff check .
uv run ty check
uv run pytest
```

## Codebase guide

Flasgo keeps each framework concern in a small module so new contributors can change one area without needing to understand the whole project at once:

- `flasgo/app.py`: ASGI entrypoint, request dispatch, middleware, routing integration, sessions, auth checks, rate-limit enforcement, and error handling.
- `flasgo/routing.py`: Flask-style path parsing and route matching.
- `flasgo/request.py`: request headers, cookies, query strings, body parsing, JSON, and forms.
- `flasgo/response.py`: response objects, response coercion, redirects, JSON, templates, and header validation.
- `flasgo/security.py`: security configuration, CSRF, allowed hosts, secure cookies, and default security headers.
- `flasgo/ratelimit.py`: route decorator metadata and the in-process sliding-window limiter.
- `flasgo/auth.py`: users, auth backends, permissions, and bearer-token helpers.
- `flasgo/session.py`: signed session serialization.
- `flasgo/staticfiles.py`: static file resolution and safe file serving.
- `flasgo/templating.py`: Jinja environment setup and template loading protections.
- `flasgo/testing.py`: synchronous and async ASGI test client.

When adding a feature, prefer the existing pattern: keep public decorators on `Flasgo`, keep standalone helpers importable from `flasgo`, add focused tests beside related behavior, and run the three developer commands above before handing off.

## API surface (initial)

- CLI: `flasgo run app.py --reload`, `flasgo run package.module:app --reload`
- `Flasgo.route`, `Flasgo.get`, `Flasgo.post`, `Flasgo.put`, `Flasgo.patch`, `Flasgo.delete`
- `Flasgo.before_request`, `Flasgo.after_request`, `Flasgo.errorhandler`
- `Flasgo.register_auth_backend`, `Flasgo.authorize`
- `Flasgo.ratelimit`, `rate_limit`
- `Flasgo.configure_templates`, `Flasgo.render_template`
- `Flasgo.configure_static`, `Flasgo.test_client`
- `Flasgo.openapi_spec`
- Auth helpers: `bearer_token_backend`, `extract_bearer_token`
- Templating helpers: `JinjaTemplates`, `render_template`, `Response.template`
- Request helpers: `await request.form()`, `UploadedFile`
- Response helpers: `redirect`, `Response.redirect`
- Flask-style path params: `<name>`, `<int:name>`, `<float:name>`, `<path:name>`
- Optional OpenAPI spec + Swagger UI docs (disabled by default)
- Response coercion:
  - `str` / `bytes`
  - `dict` / `list` (JSON)
  - `(body, status)` / `(body, status, headers)`
  - `Response`

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

Static responses use safe path normalization, block dotfiles and directory escapes, and include `ETag` and `Last-Modified` headers for cache validation.

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

The client supports cookies, `json=`, `data=`, multipart `files=`, `follow_redirects=True`, and async requests via `await client.arequest(...)`.

## Flask migration guide

See [MIGRATING_FROM_FLASK.md](MIGRATING_FROM_FLASK.md) for the canonical Flask to Flasgo migration guide, including official examples for templates, JSON routes, redirects, forms, static files, testing, and ASGI deployment.

## Django-like settings

```python
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

By default, Flasgo blocks unsafe schemes, embedded credentials, localhost/private network targets, and unresolved hosts. Connect to `target.url` and send `target.host_header` as the HTTP `Host` header when your HTTP client supports it.

## Automatic API docs

Flasgo can expose:

- OpenAPI JSON (default path: `/openapi.json`)
- Swagger UI (default path: `/docs`)

Docs are disabled by default for safer production posture. Enable and customize with settings:

```python
app = Flasgo(
    settings={
        "ENABLE_DOCS": True,
        "DOCS_PATH": "/api-docs",
        "OPENAPI_PATH": "/api/openapi.json",
        "API_TITLE": "My API",
        "API_VERSION": "1.2.3",
        "API_DESCRIPTION": "Internal service API",
    }
)
```

This is the initial framework baseline; it is intentionally small so the core can evolve quickly.
