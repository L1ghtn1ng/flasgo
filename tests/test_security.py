from __future__ import annotations

import dataclasses
from typing import Annotated, Any, cast

import pytest
from flasgo import (
    Body,
    Flasgo,
    Request,
    Response,
    is_safe_redirect_target,
)
from flasgo.security import build_set_cookie
from flasgo.testing import TestClient


@dataclasses.dataclass
class _ValidationBodyModel:
    name: str


def _multipart_body(boundary: str, parts: int) -> bytes:
    chunk = b"--" + boundary.encode() + b'\r\nContent-Disposition: form-data; name="f"\r\n\r\nx\r\n'
    return chunk * parts + b"--" + boundary.encode() + b"--\r\n"


def test_multipart_part_count_is_capped() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False, "MAX_MULTIPART_PARTS": 10})

    @app.post("/upload")
    async def upload(request: Request) -> dict[str, int]:
        form = await request.form()
        return {"fields": len(form)}

    client = TestClient(app)
    response = client.post(
        "/upload",
        body=_multipart_body("b", 50),
        headers={"content-type": "multipart/form-data; boundary=b"},
    )
    assert response.status_code == 413
    assert "MAX_MULTIPART_PARTS" in response.text


def test_multipart_at_part_limit_is_accepted() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False, "MAX_MULTIPART_PARTS": 5})

    @app.post("/upload")
    async def upload(request: Request) -> dict[str, int]:
        form = await request.form()
        return {"fields": len(form)}

    client = TestClient(app)
    response = client.post(
        "/upload",
        body=_multipart_body("b", 5),
        headers={"content-type": "multipart/form-data; boundary=b"},
    )
    assert response.status_code == 200
    assert response.json() == {"fields": 1}


def test_multipart_payload_boundary_substrings_are_not_counted_as_parts() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False, "MAX_MULTIPART_PARTS": 1})
    payload = b"prefix--boundary-suffix" * 10
    body = (
        b"--boundary\r\n"
        b'Content-Disposition: form-data; name="doc"; filename="doc.bin"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n" + payload + b"\r\n--boundary--\r\n"
    )

    @app.post("/upload")
    async def upload(request: Request) -> dict[str, int]:
        form = await request.form()
        uploaded = form.file("doc")
        return {"size": uploaded.size if uploaded is not None else 0}

    response = TestClient(app).post(
        "/upload",
        body=body,
        headers={"content-type": "multipart/form-data; boundary=boundary"},
    )
    assert response.status_code == 200
    assert response.json() == {"size": len(payload)}


def test_multipart_field_count_is_capped() -> None:
    boundary = "b"
    parts = []
    for index in range(5):
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="f{index}"\r\n\r\nx\r\n'.encode())
    body = b"".join(parts) + b"--b--\r\n"
    app = Flasgo(settings={"CSRF_ENABLED": False, "MAX_FORM_FIELDS": 3})

    @app.post("/upload")
    async def upload(request: Request) -> dict[str, int]:
        form = await request.form()
        return {"fields": len(form)}

    client = TestClient(app)
    response = client.post(
        "/upload",
        body=body,
        headers={"content-type": "multipart/form-data; boundary=b"},
    )
    assert response.status_code == 413
    assert "MAX_FORM_FIELDS" in response.text


def test_urlencoded_form_field_count_is_capped() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False, "MAX_FORM_FIELDS": 3})

    @app.post("/form")
    async def form(request: Request) -> dict[str, int]:
        data = await request.form()
        return {"fields": len(data)}

    client = TestClient(app)
    response = client.post(
        "/form",
        body=b"a=1&b=2&c=3&d=4",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 413
    assert "MAX_FORM_FIELDS" in response.text


def test_query_string_field_count_is_capped() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False, "MAX_FORM_FIELDS": 3})

    @app.get("/q")
    def query(request: Request) -> dict[str, int]:
        return {"fields": len(request.query_params)}

    client = TestClient(app)
    response = client.get("/q?a=1&b=2&c=3&d=4")
    assert response.status_code == 413


def test_json_deep_nesting_returns_400() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.post("/json")
    async def parse_json(request: Request) -> dict[str, object]:
        payload = await request.json()
        return {"payload": str(type(payload))}

    client = TestClient(app)
    response = client.post(
        "/json",
        body=b"[" * 200_000,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 400


def test_json_oversized_integer_returns_400() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.post("/json")
    async def parse_json(request: Request) -> dict[str, object]:
        payload = await request.json()
        return {"payload": str(type(payload))}

    client = TestClient(app)
    response = client.post(
        "/json",
        body=b"9" * 5_000,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 400


def test_json_rejects_non_finite_constants() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.post("/json")
    async def parse_json(request: Request) -> dict[str, object]:
        payload = await request.json()
        return {"payload": str(type(payload))}

    client = TestClient(app)
    for constant in (b'{"v": NaN}', b'{"v": Infinity}', b'{"v": -Infinity}'):
        response = client.post("/json", body=constant, headers={"content-type": "application/json"})
        assert response.status_code == 400


def test_response_json_rejects_non_finite_floats() -> None:
    with pytest.raises(ValueError):
        Response.json({"v": float("nan")})
    with pytest.raises(ValueError):
        Response.json({"v": float("inf")})


def test_uploaded_filename_is_sanitized() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})
    boundary = "b"
    body = (
        b"--b\r\n"
        b'Content-Disposition: form-data; name="doc"; filename="../../etc/passwd"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n"
        b"data\r\n--b--\r\n"
    )

    @app.post("/upload")
    async def upload(request: Request) -> dict[str, str | None]:
        form = await request.form()
        upload_file = form.file("doc")
        return {"filename": upload_file.filename if upload_file else None}

    client = TestClient(app)
    response = client.post(
        "/upload",
        body=body,
        headers={"content-type": f"multipart/form-data; boundary={boundary}"},
    )
    assert response.status_code == 200
    assert response.json() == {"filename": "passwd"}


def test_uploaded_filename_strips_nul_backslash_and_dots() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.post("/upload")
    async def upload(request: Request) -> dict[str, str | None]:
        form = await request.form()
        upload_file = form.file("doc")
        return {"filename": upload_file.filename if upload_file else None}

    body = (
        b"--b\r\n"
        b'Content-Disposition: form-data; name="doc"; filename="..\\..\\evil.txt"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n"
        b"data\r\n--b--\r\n"
    )
    client = TestClient(app)
    response = client.post(
        "/upload",
        body=body,
        headers={"content-type": "multipart/form-data; boundary=b"},
    )
    assert response.status_code == 200
    assert response.json() == {"filename": "evil.txt"}

    exposed_dot_body = (
        b"--b\r\n"
        b'Content-Disposition: form-data; name="doc"; filename=".. .htaccess"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n"
        b"data\r\n--b--\r\n"
    )
    exposed_dot_response = client.post(
        "/upload",
        body=exposed_dot_body,
        headers={"content-type": "multipart/form-data; boundary=b"},
    )
    assert exposed_dot_response.status_code == 200
    assert exposed_dot_response.json() == {"filename": "htaccess"}


def test_short_secret_rejected_even_in_debug_mode() -> None:
    with pytest.raises(ValueError, match="32 characters"):
        Flasgo(settings={"DEBUG": True, "SECRET_KEY": "short"})


def test_session_cookie_same_site_is_validated_at_startup() -> None:
    with pytest.raises(ValueError, match="SESSION_COOKIE_SAME_SITE"):
        Flasgo(settings={"SESSION_COOKIE_SAME_SITE": "Lax; Domain=evil.example"})
    with pytest.raises(ValueError, match="SESSION_COOKIE_SAME_SITE"):
        Flasgo(settings={"SESSION_COOKIE_SAME_SITE": "None", "SESSION_COOKIE_SECURE": False})


def test_build_set_cookie_validates_path_and_same_site() -> None:
    with pytest.raises(ValueError, match="cookie path"):
        build_set_cookie("k", "v", path="/x; Domain=evil.example")
    with pytest.raises(ValueError, match="SameSite"):
        build_set_cookie("k", "v", same_site="Lax; Domain=evil.example")
    with pytest.raises(ValueError, match="SameSite=None"):
        build_set_cookie("k", "v", same_site="None", secure=False)
    assert "SameSite=Strict" in build_set_cookie("k", "v", same_site="strict")


def test_response_set_cookie_and_delete_cookie() -> None:
    response = Response.text("ok")
    response.set_cookie("prefs", "dark", max_age=60)
    response.delete_cookie("old")
    assert len(response.cookies) == 2
    assert response.cookies[0].startswith("prefs=dark")
    assert "Max-Age=60" in response.cookies[0]
    assert response.cookies[1].startswith("old=")
    assert "Max-Age=0" in response.cookies[1]


def test_error_handler_for_http_exception_is_invoked() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.errorhandler(ValueError)
    def handle_value_error(request: Request, exc: Exception) -> Response:
        return Response.json({"handled": "value-error"}, status_code=599)

    @app.get("/boom")
    def boom() -> str:
        raise ValueError("broken")
        return "unreachable"

    client = TestClient(app)
    response = client.get("/boom")
    assert response.status_code == 599
    assert response.json() == {"handled": "value-error"}


def test_raising_error_handler_falls_back_to_safe_500() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.errorhandler(ValueError)
    def handle_value_error(request: Request, exc: Exception) -> Response:
        raise RuntimeError("handler is broken")

    @app.get("/boom")
    def boom() -> str:
        raise ValueError("broken")
        return "unreachable"

    client = TestClient(app)
    response = client.get("/boom")
    assert response.status_code == 500
    assert "x-content-type-options" in response.headers
    assert response.headers["cache-control"] == "no-store, no-cache, must-revalidate, max-age=0"
    assert "handler is broken" not in response.text


def test_http_exception_handler_registration_is_honored() -> None:
    from flasgo import HTTPException

    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.errorhandler(HTTPException)
    def handle_http(request: Request, exc: Exception) -> Response:
        return Response.json({"handled": True}, status_code=200)

    @app.get("/teapot")
    def teapot() -> str:
        raise HTTPException(418)
        return "unreachable"

    client = TestClient(app)
    response = client.get("/teapot")
    assert response.status_code == 200
    assert response.json() == {"handled": True}


def test_int_converter_oversized_digits_returns_404() -> None:
    app = Flasgo()

    @app.get("/users/<int:user_id>")
    def user(user_id: int) -> dict[str, int]:
        return {"user_id": user_id}

    client = TestClient(app)
    response = client.get("/users/" + "9" * 5_000)
    assert response.status_code == 404


def test_int_converter_rejects_unicode_digits() -> None:
    app = Flasgo()

    @app.get("/users/<int:user_id>")
    def user(user_id: int) -> dict[str, int]:
        return {"user_id": user_id}

    client = TestClient(app)
    response = client.get("/users/%D9%A4%D9%A2")
    assert response.status_code == 404


def test_dataclass_response_excludes_private_fields() -> None:
    @dataclasses.dataclass
    class ProfileOut:
        display_name: str
        _password_hash: str = "nested-secret"

    @dataclasses.dataclass
    class UserOut:
        name: str
        profile: ProfileOut
        _password_hash: str = "secret"

    app = Flasgo()

    @app.get("/user")
    def user() -> UserOut:
        return UserOut(name="alice", profile=ProfileOut(display_name="Alice"))

    client = TestClient(app)
    response = client.get("/user")
    assert response.status_code == 200
    assert response.json() == {"name": "alice", "profile": {"display_name": "Alice"}}


def test_validation_location_sanitizes_attacker_keys() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.post("/widgets")
    def create(payload: Annotated[_ValidationBodyModel, Body()]) -> dict[str, str]:
        return {"name": payload.name}

    client = TestClient(app)
    evil_key = "x\n" + "a" * 100
    response = client.post("/widgets", json={"name": "a", evil_key: 1})
    assert response.status_code == 422
    body = cast(dict[str, Any], response.json())
    errors = cast(list[dict[str, Any]], body["errors"])
    assert errors[0]["location"] == ["body", "x?" + "a" * 62 + "..."]
    assert errors[0]["code"] == "unknown_field"


def test_is_safe_redirect_target() -> None:
    assert is_safe_redirect_target("/dashboard")
    assert is_safe_redirect_target("?page=2")
    assert is_safe_redirect_target("/a/b?c=d#e")
    assert not is_safe_redirect_target("https://evil.example/phish")
    assert not is_safe_redirect_target("//evil.example/phish")
    assert not is_safe_redirect_target(r"\\evil.example/phish")
    assert not is_safe_redirect_target(r"/\evil.example/phish")
    assert not is_safe_redirect_target("javascript:alert(1)")
    assert not is_safe_redirect_target("//[")
    assert not is_safe_redirect_target("http://[")
    assert not is_safe_redirect_target("")
    assert not is_safe_redirect_target("/ok\r\nInjected: yes")


def test_metrics_auth_failures_are_throttled() -> None:
    app = Flasgo(
        settings={
            "METRICS_ENABLED": True,
            "METRICS_BEARER_TOKEN": "x" * 32,
            "SECURITY_FAILURE_RATE_LIMIT": 3,
        }
    )
    client = TestClient(app)
    statuses = [client.get("/metrics", headers={"authorization": "Bearer wrong"}).status_code for _ in range(6)]
    assert 401 in statuses
    assert 429 in statuses


def test_telemetry_redacted_query_string_bounds_keys() -> None:
    from flasgo.telemetry import _redacted_query_string

    secret_key = "k" * 500
    result = _redacted_query_string(f"?{secret_key}&token=abc123&empty=".encode()[1:])
    fields = result.split(b"&")
    assert len(fields[0]) <= 64
    assert b"token=REDACTED" in fields
    assert b"empty=" in fields
    assert secret_key.encode() not in result


def test_security_failures_without_client_ip_are_not_throttled() -> None:
    async def receive() -> dict[str, object]:
        return {"type": "http.disconnect"}

    app = Flasgo(settings={"SECURITY_FAILURE_RATE_LIMIT": 1})
    req = Request(scope={"type": "http", "headers": []}, receive=receive)
    assert req.client_ip is None
    for _ in range(200):
        assert app._register_security_failure(req) is False
    assert app._security_failure_is_limited(req) is False
