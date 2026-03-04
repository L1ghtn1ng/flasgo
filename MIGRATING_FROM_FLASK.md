# Flask to Flasgo migration guide

Flasgo keeps Flask-style routing and a small API surface, but it runs as ASGI and ships with stricter security defaults. This guide shows the canonical migration path for the most common patterns.

## Key differences

- Route decorators stay familiar: `@app.get(...)`, `@app.post(...)`, and Flask-style converters such as `<int:user_id>`.
- Route handlers can be sync or async.
- `request.form` becomes `await request.form()`.
- `await request.json()` and `await request.text()` raise `400` responses with fix-oriented messages when the body is malformed.
- `redirect(...)` and `jsonify(...)` are available as first-party helpers.
- The built-in dev server supports `reload=True`, but production should run on an ASGI server such as `uvicorn`.
- Security defaults are stricter than Flask defaults: host validation, CSRF protection, secure headers, signed sessions, SSRF guard helpers, and no-store caching for non-static responses.

## HTML template route

Flask:

```python
from flask import Flask, render_template

app = Flask(__name__)


@app.get("/")
def home():
    return render_template("home.html", title="Dashboard")
```

Flasgo:

```python
import os

from flasgo import Flasgo, Response

app = Flasgo(
    settings={
        "DEBUG": False,
        "SECRET_KEY": os.environ["FLASGO_SECRET_KEY"],
        "ALLOWED_HOSTS": {"app.example.com"},
        "CSRF_ENABLED": True,
        "SESSION_COOKIE_SECURE": True,
        "CSRF_COOKIE_SECURE": True,
    }
)
app.configure_templates("templates")


@app.get("/")
def home() -> Response:
    return Response.template(
        "home.html",
        templates=app.templates,
        context={"title": "Dashboard"},
    )
```

## JSON API route

Flask:

```python
from flask import Flask, jsonify

app = Flask(__name__)


@app.get("/api/health")
def health():
    return jsonify({"ok": True, "service": "billing"})
```

Flasgo:

```python
import os

from flasgo import Flasgo, jsonify

app = Flasgo(
    settings={
        "DEBUG": False,
        "SECRET_KEY": os.environ["FLASGO_SECRET_KEY"],
        "ALLOWED_HOSTS": {"api.example.com"},
        "CSRF_ENABLED": False,
    }
)


@app.get("/api/health")
async def health():
    return jsonify({"ok": True, "service": "billing"})
```

## redirect

Flask:

```python
from flask import Flask, redirect, url_for

app = Flask(__name__)


@app.post("/login")
def login():
    return redirect(url_for("dashboard"))


@app.get("/dashboard")
def dashboard():
    return "ok"
```

Flasgo:

```python
import os

from flasgo import Flasgo, redirect

app = Flasgo(
    settings={
        "DEBUG": False,
        "SECRET_KEY": os.environ["FLASGO_SECRET_KEY"],
        "ALLOWED_HOSTS": {"app.example.com"},
        "CSRF_ENABLED": True,
        "SESSION_COOKIE_SECURE": True,
        "CSRF_COOKIE_SECURE": True,
    }
)


@app.post("/login")
def login():
    return redirect("/dashboard")


@app.get("/dashboard")
def dashboard():
    return "ok"
```

## form POST handling

Flask:

```python
from flask import Flask, request

app = Flask(__name__)


@app.post("/signup")
def signup():
    email = request.form["email"]
    interests = request.form.getlist("interests")
    avatar = request.files.get("avatar")
    return {
        "email": email,
        "interests": interests,
        "avatar_name": avatar.filename if avatar else None,
    }
```

Flasgo:

```python
import os

from flasgo import Flasgo, Request

app = Flasgo(
    settings={
        "DEBUG": False,
        "SECRET_KEY": os.environ["FLASGO_SECRET_KEY"],
        "ALLOWED_HOSTS": {"app.example.com"},
        "CSRF_ENABLED": True,
        "SESSION_COOKIE_SECURE": True,
        "CSRF_COOKIE_SECURE": True,
    }
)


@app.post("/signup")
async def signup(request: Request) -> dict[str, object]:
    form = await request.form()
    avatar = form.file("avatar")
    return {
        "email": form["email"],
        "interests": form.getlist("interests"),
        "avatar_name": avatar.filename if avatar else None,
    }
```

Notes:

- Flasgo parses `application/x-www-form-urlencoded` and `multipart/form-data`.
- `FormData.file(...)` returns an `UploadedFile` with `filename`, `content_type`, `body`, `size`, and `text()`.
- With CSRF enabled, browser form posts should include the Flasgo CSRF token flow.
- Unsupported methods return `405 Method Not Allowed` plus an `Allow` header listing the accepted methods.

## static files

Flask:

```python
from flask import Flask

app = Flask(__name__, static_folder="static")
```

Flasgo:

```python
import os

from flasgo import Flasgo

app = Flasgo(
    static_folder="static",
    settings={
        "DEBUG": False,
        "SECRET_KEY": os.environ["FLASGO_SECRET_KEY"],
        "ALLOWED_HOSTS": {"app.example.com"},
        "CSRF_ENABLED": True,
        "SESSION_COOKIE_SECURE": True,
        "CSRF_COOKIE_SECURE": True,
    }
)
app.configure_static("assets", url_path="/assets", cache_max_age=86400)
```

Flasgo static serving includes path normalization, blocks directory traversal and dotfiles, prevents symlink escape outside the configured root, and emits `ETag` and `Last-Modified` headers.

## testing

Flask:

```python
from flask import Flask

app = Flask(__name__)


def test_ping():
    client = app.test_client()
    response = client.get("/ping")
    assert response.status_code == 200
```

Flasgo:

```python
from flasgo import Flasgo

# Testing example only. For browser-facing production apps keep CSRF enabled.
app = Flasgo(settings={"CSRF_ENABLED": False})


@app.get("/ping")
def ping():
    return {"pong": "ok"}


def test_ping():
    client = app.test_client()
    response = client.get("/ping")
    assert response.status_code == 200
    assert response.json() == {"pong": "ok"}
```

The official client supports:

- Cookie persistence across requests
- `json=...`
- `data=...`
- Multipart `files=...`
- `follow_redirects=True`
- `await client.arequest(...)`

## ASGI deployment

Flask:

```bash
flask --app app run --debug
```

Flasgo development:

```bash
export FLASGO_SECRET_KEY="$(openssl rand -hex 32)"
uv run flasgo run app.py --reload
```

Equivalent Python entrypoint:

```python
import os

from flasgo import Flasgo

app = Flasgo(
    settings={
        "DEBUG": True,
        "SECRET_KEY": os.environ["FLASGO_SECRET_KEY"],
        "ALLOWED_HOSTS": {"127.0.0.1", "localhost"},
        "CSRF_ENABLED": True,
        "SESSION_COOKIE_SECURE": False,
        "CSRF_COOKIE_SECURE": False,
    }
)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, reload=True)
```

Flasgo production:

```bash
export FLASGO_SECRET_KEY="$(openssl rand -hex 32)"
uv run uvicorn app:app --host 0.0.0.0 --port 8000 --workers 4
```

For production, run behind a real ASGI server and keep Flasgo security settings aligned with your deployment boundary:

- Set `DEBUG=False`
- Use a strong `SECRET_KEY`
- Set explicit `ALLOWED_HOSTS`
- Keep `CSRF_ENABLED=True` for browser-facing apps
- Enable secure cookies over HTTPS
