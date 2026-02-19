from __future__ import annotations

import logging

import pytest
from fango import (
    Fango,
    HasScope,
    IsAuthenticated,
    Request,
    Response,
    User,
    bearer_token_backend,
    current_user,
    jsonify,
    request,
)
from fango.app import session
from fango.security import SecurityConfig
from fango.testing import TestClient


def _extract_cookie(set_cookie_header: str, name: str) -> str | None:
    for line in set_cookie_header.split("\n"):
        raw = line.strip()
        if raw.startswith(f"{name}="):
            return raw.split(";", 1)[0].split("=", 1)[1]
    return None


def test_async_route_and_json_response() -> None:
    app = Fango()

    @app.get("/ping")
    async def ping() -> dict[str, str]:
        return {"pong": "ok"}

    client = TestClient(app)
    response = client.get("/ping")

    assert response.status_code == 200
    assert response.json() == {"pong": "ok"}


def test_flask_style_route_params() -> None:
    app = Fango()

    @app.get("/users/<int:user_id>")
    def user(user_id: int) -> tuple[dict[str, int], int]:
        return {"user_id": user_id}, 201

    client = TestClient(app)
    response = client.get("/users/42")

    assert response.status_code == 201
    assert response.json() == {"user_id": 42}


def test_method_not_allowed() -> None:
    app = Fango(security=SecurityConfig(csrf_enabled=False))

    @app.get("/hello")
    def hello() -> str:
        return "hi"

    client = TestClient(app)
    response = client.post("/hello")

    assert response.status_code == 405


def test_invalid_host_is_rejected() -> None:
    app = Fango(security=SecurityConfig(csrf_enabled=False))

    @app.get("/")
    def home() -> str:
        return "ok"

    client = TestClient(app)
    response = client.get("/", headers={"host": "evil.example"})

    assert response.status_code == 400


def test_security_headers_applied() -> None:
    app = Fango()

    @app.get("/")
    def home() -> str:
        return "ok"

    client = TestClient(app)
    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "content-security-policy" in response.headers
    assert response.headers["cache-control"] == "no-store, no-cache, must-revalidate, max-age=0"
    assert response.headers["pragma"] == "no-cache"
    assert response.headers["expires"] == "0"


def test_csrf_rejects_missing_token_on_post() -> None:
    app = Fango()

    @app.post("/submit")
    def submit() -> str:
        return "ok"

    client = TestClient(app)
    response = client.post("/submit")

    assert response.status_code == 403


def test_csrf_accepts_double_submit_token() -> None:
    app = Fango()

    @app.get("/seed")
    def seed() -> str:
        return "seed"

    @app.post("/submit")
    def submit() -> str:
        return "ok"

    client = TestClient(app)
    seed_response = client.get("/seed")
    csrf_token = _extract_cookie(seed_response.headers.get("set-cookie", ""), "fango-csrf")
    assert csrf_token is not None

    response = client.post(
        "/submit",
        headers={
            "cookie": f"fango-csrf={csrf_token}",
            "x-csrf-token": csrf_token,
            "origin": "http://localhost",
        },
    )
    assert response.status_code == 200


def test_signed_session_cookie_round_trip() -> None:
    app = Fango()

    @app.get("/counter")
    def counter() -> dict[str, int]:
        current = session()
        count = int(current.get("count", 0)) + 1
        current["count"] = count
        return {"count": count}

    client = TestClient(app)

    first = client.get("/counter")
    assert first.json() == {"count": 1}
    session_cookie = _extract_cookie(first.headers.get("set-cookie", ""), "fango-session")
    assert session_cookie is not None

    second = client.get("/counter", headers={"cookie": f"fango-session={session_cookie}"})
    assert second.json() == {"count": 2}


def test_flask_style_request_proxy_and_jsonify() -> None:
    app = Fango()

    @app.get("/inspect")
    def inspect_request() -> Response:
        return jsonify({"method": request.method, "path": request.path})

    client = TestClient(app)
    response = client.get("/inspect")

    assert response.status_code == 200
    assert response.json() == {"method": "GET", "path": "/inspect"}


def test_settings_mapping_applies_security_config() -> None:
    app = Fango(settings={"CSRF_ENABLED": False, "ALLOWED_HOSTS": {"api.local"}})

    @app.post("/submit")
    def submit() -> str:
        return "ok"

    client = TestClient(app)
    denied = client.post("/submit")
    assert denied.status_code == 400

    allowed = client.post("/submit", headers={"host": "api.local"})
    assert allowed.status_code == 200
    assert app.settings.CSRF_ENABLED is False


def test_auth_and_current_user_context_with_permissions() -> None:
    app = Fango()

    def header_backend(req: Request) -> User | None:
        user_id = req.headers.get("x-user")
        if not user_id:
            return None
        scopes_header = req.headers.get("x-scopes", "")
        scopes = frozenset(part.strip() for part in scopes_header.split(",") if part.strip())
        return User(id=user_id, is_authenticated=True, scopes=scopes)

    app.register_auth_backend("headers", header_backend)

    @app.get("/whoami")
    @app.authorize(IsAuthenticated(), backend="headers")
    def whoami() -> Response:
        return jsonify({"id": current_user.id})

    @app.get("/admin")
    @app.authorize(IsAuthenticated(), HasScope("admin"), backend="headers")
    def admin() -> str:
        return "ok"

    client = TestClient(app)

    denied = client.get("/whoami")
    assert denied.status_code == 401

    allowed = client.get("/whoami", headers={"x-user": "alice"})
    assert allowed.status_code == 200
    assert allowed.json() == {"id": "alice"}

    no_scope = client.get("/admin", headers={"x-user": "bob", "x-scopes": "read"})
    assert no_scope.status_code == 403

    with_scope = client.get("/admin", headers={"x-user": "carol", "x-scopes": "admin,read"})
    assert with_scope.status_code == 200


def test_default_secret_is_not_predictable_literal() -> None:
    app = Fango()
    assert app.security.secret_key != "dev-insecure-secret-change-this"
    assert len(app.security.secret_key) >= 32


def test_short_secret_rejected_when_debug_false() -> None:
    with pytest.raises(ValueError):
        Fango(settings={"DEBUG": False, "SECRET_KEY": "short"})


def test_csrf_rejects_mismatched_origin() -> None:
    app = Fango()

    @app.get("/seed")
    def seed() -> str:
        return "seed"

    @app.post("/submit")
    def submit() -> str:
        return "ok"

    client = TestClient(app)
    seed_response = client.get("/seed")
    csrf_token = _extract_cookie(seed_response.headers.get("set-cookie", ""), "fango-csrf")
    assert csrf_token is not None

    response = client.post(
        "/submit",
        headers={
            "cookie": f"fango-csrf={csrf_token}",
            "x-csrf-token": csrf_token,
            "origin": "http://evil.local",
        },
    )
    assert response.status_code == 403


def test_invalid_response_header_is_blocked() -> None:
    app = Fango(security=SecurityConfig(csrf_enabled=False))

    @app.get("/bad")
    def bad() -> tuple[str, int, dict[str, str]]:
        return "ok", 200, {"x-test": "safe\r\ninjected: nope"}

    client = TestClient(app)
    response = client.get("/bad")
    assert response.status_code == 500


def test_cache_weakening_header_is_overridden() -> None:
    app = Fango(security=SecurityConfig(csrf_enabled=False))

    @app.get("/public")
    def public() -> tuple[str, int, dict[str, str]]:
        return "ok", 200, {"cache-control": "public, max-age=3600"}

    client = TestClient(app)
    response = client.get("/public")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, no-cache, must-revalidate, max-age=0"


def test_cache_enforcement_can_be_disabled_explicitly() -> None:
    app = Fango(
        security=SecurityConfig(
            csrf_enabled=False,
            enforce_no_store_cache=False,
        )
    )

    @app.get("/public")
    def public() -> tuple[str, int, dict[str, str]]:
        return "ok", 200, {"cache-control": "public, max-age=3600"}

    client = TestClient(app)
    response = client.get("/public")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "public, max-age=3600"


def test_request_body_limit_returns_413() -> None:
    app = Fango(settings={"CSRF_ENABLED": False, "MAX_REQUEST_BODY_BYTES": 4})

    @app.post("/echo")
    async def echo(request: Request) -> dict[str, int]:
        data = await request.body()
        return {"size": len(data)}

    client = TestClient(app)
    response = client.post("/echo", body=b"12345")
    assert response.status_code == 413


def test_security_failures_are_rate_limited() -> None:
    app = Fango(
        settings={
            "CSRF_ENABLED": False,
            "SECURITY_FAILURE_RATE_LIMIT": 2,
            "SECURITY_FAILURE_WINDOW_SECONDS": 60,
        }
    )

    @app.get("/private")
    @app.authorize(IsAuthenticated())
    def private() -> str:
        return "ok"

    client = TestClient(app)
    first = client.get("/private")
    second = client.get("/private")
    third = client.get("/private")
    assert first.status_code == 401
    assert second.status_code == 401
    assert third.status_code == 429


def test_security_event_logging_for_bad_host(caplog: pytest.LogCaptureFixture) -> None:
    app = Fango(settings={"CSRF_ENABLED": False, "LOG_SECURITY_EVENTS": True})

    @app.get("/")
    def home() -> str:
        return "ok"

    client = TestClient(app)
    with caplog.at_level(logging.WARNING, logger="fango.security"):
        response = client.get("/", headers={"host": "evil.example"})

    assert response.status_code == 400
    assert any("host-check-failed" in msg for msg in caplog.messages)


def test_bearer_token_backend_helper() -> None:
    app = Fango(settings={"CSRF_ENABLED": False})

    def validate_token(token: str) -> User | None:
        if token != "token-123":
            return None
        return User(id="alice", is_authenticated=True, scopes=frozenset({"read"}))

    app.register_auth_backend("bearer", bearer_token_backend(validate_token))

    @app.get("/me")
    @app.authorize(IsAuthenticated(), backend="bearer")
    def me() -> Response:
        return jsonify({"id": current_user.id})

    client = TestClient(app)

    missing = client.get("/me")
    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"

    invalid = client.get("/me", headers={"authorization": "Bearer wrong"})
    assert invalid.status_code == 401
    assert invalid.headers["www-authenticate"] == "Bearer"

    valid = client.get("/me", headers={"authorization": "Bearer token-123"})
    assert valid.status_code == 200
    assert valid.json() == {"id": "alice"}


def test_auth_backend_exception_fails_closed() -> None:
    app = Fango(settings={"CSRF_ENABLED": False})

    def broken_backend(req: Request) -> User | None:
        _ = req
        raise RuntimeError("backend exploded")

    app.register_auth_backend("broken", broken_backend)

    @app.get("/private")
    @app.authorize(IsAuthenticated(), backend="broken")
    def private() -> str:
        return "ok"

    client = TestClient(app)
    response = client.get("/private")
    assert response.status_code == 401


def test_register_auth_backend_rejects_empty_name() -> None:
    app = Fango()
    with pytest.raises(ValueError):
        app.register_auth_backend("   ", lambda req: None)


def test_authorize_rejects_empty_backend_name() -> None:
    app = Fango()
    with pytest.raises(ValueError):
        app.authorize(IsAuthenticated(), backend="  ")
