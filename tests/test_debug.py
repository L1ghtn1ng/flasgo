from __future__ import annotations

from unittest.mock import MagicMock

from flasgo.debug import Debug
from flasgo.request import Request
from jinja2.exceptions import TemplateNotFound, TemplateSyntaxError


def _make_request(method: str = "GET", path: str = "/") -> Request:
    scope = {"method": method, "path": path, "headers": []}
    req = Request(scope=scope, receive=MagicMock())
    return req


def test_render_template_debug_error_returns_none_when_debug_disabled() -> None:
    req = _make_request()
    exc = TemplateSyntaxError("syntax error", name="test.html", lineno=1)
    result = Debug.render_template_debug_error(req, exc, debug=False)
    assert result is None


def test_render_template_debug_error_returns_none_for_non_template_error() -> None:
    req = _make_request()
    exc = ValueError("some error")
    result = Debug.render_template_debug_error(req, exc, debug=True)
    assert result is None


def test_render_template_debug_error_returns_response_for_template_error() -> None:
    req = _make_request(method="POST", path="/test")
    exc = TemplateSyntaxError("syntax error", name="test.html", lineno=5)
    result = Debug.render_template_debug_error(req, exc, debug=True)
    assert result is not None
    assert result.status_code == 500
    assert "text/html" in result.headers["content-type"]
    assert "TemplateSyntaxError" in result.body.decode()


def test_render_template_debug_error_includes_error_details() -> None:
    req = _make_request(method="GET", path="/page")
    exc = TemplateNotFound("missing.html")
    result = Debug.render_template_debug_error(req, exc, debug=True)
    assert result is not None
    body = result.body.decode()
    assert "TemplateNotFound" in body
    assert "missing.html" in body


def test_handle_debug_css_returns_none_when_debug_disabled() -> None:
    req = _make_request(path="/__flasgo_debug__/debug_error.css")
    result = Debug.handle_debug_css(req, debug=False)
    assert result is None


def test_handle_debug_css_returns_none_for_non_debug_path() -> None:
    req = _make_request(path="/other")
    result = Debug.handle_debug_css(req, debug=True)
    assert result is None


def test_handle_debug_css_returns_405_for_non_get_method() -> None:
    req = _make_request(method="POST", path="/__flasgo_debug__/debug_error.css")
    result = Debug.handle_debug_css(req, debug=True)
    assert result is not None
    assert result.status_code == 405


def test_handle_debug_css_returns_css_for_valid_request() -> None:
    req = _make_request(method="GET", path="/__flasgo_debug__/debug_error.css")
    result = Debug.handle_debug_css(req, debug=True)
    assert result is not None
    assert result.status_code == 200
    assert "text/css" in result.headers["content-type"]
    assert b"." in result.body
