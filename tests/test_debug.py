from __future__ import annotations

from flasgo import Flasgo
from flasgo.testing import TestClient
from jinja2.exceptions import TemplateNotFound, TemplateSyntaxError


def test_render_template_debug_error_returns_none_when_debug_disabled() -> None:
    app = Flasgo(settings={"DEBUG": False, "CSRF_ENABLED": False})

    @app.get("/test")
    def test_route() -> str:
        raise TemplateSyntaxError("syntax error", name="test.html", lineno=1)

    client = TestClient(app)
    response = client.get("/test")
    assert response.status_code == 500


def test_render_template_debug_error_returns_none_for_non_template_error() -> None:
    app = Flasgo(settings={"DEBUG": True, "CSRF_ENABLED": False})

    @app.get("/test")
    def test_route() -> str:
        raise ValueError("some error")

    client = TestClient(app)
    response = client.get("/test")
    assert response.status_code == 500


def test_render_template_debug_error_returns_response_for_template_error() -> None:
    app = Flasgo(settings={"DEBUG": True, "CSRF_ENABLED": False})

    @app.post("/test")
    def test_route() -> str:
        raise TemplateSyntaxError("syntax error", name="test.html", lineno=5)

    client = TestClient(app)
    response = client.post("/test")
    assert response.status_code == 500
    assert "text/html" in response.headers["content-type"]
    assert "TemplateSyntaxError" in response.text


def test_render_template_debug_error_includes_error_details() -> None:
    app = Flasgo(settings={"DEBUG": True, "CSRF_ENABLED": False})

    @app.get("/page")
    def test_route() -> str:
        raise TemplateNotFound("missing.html")

    client = TestClient(app)
    response = client.get("/page")
    assert response.status_code == 500
    assert "TemplateNotFound" in response.text
    assert "missing.html" in response.text


def test_render_template_debug_error_escapes_reflected_values() -> None:
    app = Flasgo(settings={"DEBUG": True, "CSRF_ENABLED": False})

    @app.get("/<path:payload>")
    def test_route(payload: str) -> str:
        _ = payload
        raise TemplateSyntaxError("<script>alert(1)</script>", name="<img src=x onerror=alert(1)>", lineno=1)

    client = TestClient(app)
    response = client.get("/%3Csvg%20onload=alert(1)%3E")

    assert response.status_code == 500
    assert "<script>alert(1)</script>" not in response.text
    assert "<img src=x onerror=alert(1)>" not in response.text
    assert "<svg onload=alert(1)>" not in response.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in response.text


def test_handle_debug_css_returns_none_when_debug_disabled() -> None:
    app = Flasgo(settings={"DEBUG": False, "CSRF_ENABLED": False})

    @app.get("/test")
    def test_route() -> str:
        return "ok"

    client = TestClient(app)
    response = client.get("/__flasgo_debug__/debug_error.css")
    assert response.status_code == 404


def test_handle_debug_css_returns_css_for_valid_request() -> None:
    app = Flasgo(settings={"DEBUG": True, "CSRF_ENABLED": False})

    @app.get("/test")
    def test_route() -> str:
        return "ok"

    client = TestClient(app)
    response = client.get("/__flasgo_debug__/debug_error.css")
    assert response.status_code == 200
    assert "text/css" in response.headers["content-type"]
    assert b"." in response.body
