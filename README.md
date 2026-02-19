# Fango

Fango is an async-first Python web framework designed as a hybrid of:
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

## Quick start

```bash
uv venv
uv sync --group dev
```

Create `app.py`:

```python
from fango import Fango

app = Fango()


@app.get("/")
async def home():
    return {"framework": "fango", "status": "ok"}


@app.post("/notes/<int:note_id>")
async def update_note(note_id: int):
    return {"updated": note_id}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
```

Run:

```bash
uv run python app.py
```

## Development run (recommended)

Uses `uvicorn` with reload while building locally:

```bash
uv run uvicorn app:app --reload --host 127.0.0.1 --port 8000
```

`app.run(...)` uses the built-in dev server and should only be used for local development.

## Production deployment

Use a production ASGI server process and configure secrets with environment variables:

```python
import os
from fango import Fango

app = Fango(
    settings={
        "DEBUG": False,
        "SECRET_KEY": os.environ["FANGO_SECRET_KEY"],
        "ALLOWED_HOSTS": {"api.example.com"},
        "CSRF_ENABLED": True,
        "SESSION_COOKIE_SECURE": True,
        "CSRF_COOKIE_SECURE": True,
    }
)
```

Run with workers:

```bash
export FANGO_SECRET_KEY="$(openssl rand -hex 32)"
uv run uvicorn app:app --host 0.0.0.0 --port 8000 --workers 4
```

Put a reverse proxy/load balancer in front (Caddy, Cloudflare, etc.) for TLS termination and network controls.

## Security defaults

- Host header allowlist (`localhost`, `127.0.0.1` by default).
- CSRF double-submit cookie defense for unsafe methods.
- Signed session cookies (HMAC-SHA256).
- No-store cache headers by default to reduce sensitive data caching (CWE-524 mitigation).
- Request body/head limits and read timeouts in the built-in dev server.
- Optional per-client throttling for repeated security failures (`429`).
- Security event logging for host/CSRF/authz denials.
- Hardened headers (`CSP`, `HSTS`, `X-Frame-Options`, `Referrer-Policy`, etc.).

## Developer commands

```bash
uv run ruff check .
uv run ty check
uv run pytest
```

## API surface (initial)

- `Fango.route`, `Fango.get`, `Fango.post`, `Fango.put`, `Fango.patch`, `Fango.delete`
- `Fango.before_request`, `Fango.after_request`, `Fango.errorhandler`
- `Fango.register_auth_backend`, `Fango.authorize`
- Auth helpers: `bearer_token_backend`, `extract_bearer_token`
- Flask-style path params: `<name>`, `<int:name>`, `<float:name>`, `<path:name>`
- Optional OpenAPI spec + Swagger UI docs (disabled by default)
- Response coercion:
  - `str` / `bytes`
  - `dict` / `list` (JSON)
  - `(body, status)` / `(body, status, headers)`
  - `Response`

## Flask-style globals

```python
from fango import Fango, jsonify, request

app = Fango()


@app.get("/inspect")
def inspect():
    return jsonify({"method": request.method, "path": request.path})
```

## Django-like settings

```python
app = Fango(
    settings={
        "SECRET_KEY": "replace-in-production",
        "ALLOWED_HOSTS": {"api.example.com"},
        "CSRF_ENABLED": True,
    }
)
```

You can also pass a Python module path string (`"myproject.settings"`), and Fango will load uppercase settings attributes.

## Auth and permissions

```python
from fango import Fango, HasScope, IsAuthenticated, User, bearer_token_backend

app = Fango()


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

## SSRF protection helpers (CWE-918)

For outbound URLs from user input, validate before fetching:

```python
from fango import Fango

app = Fango(
    settings={
        "SSRF_ALLOWED_SCHEMES": {"https"},
        "SSRF_ALLOWED_HOSTS": {"api.example.com"},
    }
)

safe_url = app.validate_outbound_url("https://api.example.com/data")
```

By default, Fango blocks unsafe schemes, embedded credentials, localhost/private network targets, and unresolved hosts.

## Automatic API docs

Fango can expose:

- OpenAPI JSON (default path: `/openapi.json`)
- Swagger UI (default path: `/docs`)

Docs are disabled by default for safer production posture. Enable and customize with settings:

```python
app = Fango(
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
