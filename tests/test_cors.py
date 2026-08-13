from __future__ import annotations

from typing import Any

import pytest
from flasgo import CORSConfig, Flasgo, IsAuthenticated, Request, Response
from flasgo.security import SecurityConfig


def _preflight(
    app: Flasgo,
    path: str,
    *,
    origin: str = "https://app.example.com",
    method: str = "POST",
    headers: str | None = None,
):
    request_headers = {
        "origin": origin,
        "access-control-request-method": method,
    }
    if headers is not None:
        request_headers["access-control-request-headers"] = headers
    return app.test_client().request("OPTIONS", path, headers=request_headers)


def test_cors_is_disabled_by_default_without_changing_options_dispatch() -> None:
    app = Flasgo(security=SecurityConfig(csrf_enabled=False))

    @app.post("/widgets")
    def create_widget() -> str:
        return "created"

    response = _preflight(app, "/widgets")

    assert response.status_code == 405
    assert "access-control-allow-origin" not in response.headers


def test_cors_disabled_application_matches_each_ordinary_request_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = Flasgo(security=SecurityConfig(csrf_enabled=False))

    @app.get("/widgets")
    def widgets() -> str:
        return "widgets"

    match_calls = 0
    match_route = app._match_route

    def counted_match(path: str, method: str):
        nonlocal match_calls
        match_calls += 1
        return match_route(path, method)

    monkeypatch.setattr(app, "_match_route", counted_match)

    response = app.test_client().get("/widgets")

    assert response.status_code == 200
    assert match_calls == 1


def test_allowed_simple_request_gets_cors_headers_and_merges_vary() -> None:
    app = Flasgo(
        security=SecurityConfig(csrf_enabled=False),
        cors=CORSConfig(
            allow_origins={"https://app.example.com"},
            expose_headers={"X-Request-ID", "X-Result"},
            allow_credentials=True,
        ),
    )

    @app.get("/widgets")
    def widgets() -> Response:
        return Response.json(
            {"ok": True},
            headers={
                "vary": "Accept-Encoding",
                "access-control-allow-origin": "https://evil.example",
                "x-result": "ready",
            },
        )

    response = app.test_client().get("/widgets", headers={"origin": "https://app.example.com"})

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://app.example.com"
    assert response.headers["access-control-allow-credentials"] == "true"
    assert response.headers["access-control-expose-headers"] == "x-request-id, x-result"
    assert response.headers["vary"] == "Accept-Encoding, Origin"


def test_disallowed_or_duplicate_origins_are_not_reflected() -> None:
    app = Flasgo(
        security=SecurityConfig(csrf_enabled=False),
        cors=CORSConfig(allow_origins={"https://app.example.com"}),
    )

    @app.get("/data")
    def data() -> Response:
        return Response.json({"ok": True}, headers={"access-control-allow-origin": "*"})

    disallowed = app.test_client().get("/data", headers={"origin": "https://evil.example"})
    duplicate = app.test_client().get(
        "/data",
        headers=[("origin", "https://app.example.com"), ("origin", "https://evil.example")],
    )

    assert "access-control-allow-origin" not in disallowed.headers
    assert "access-control-allow-origin" not in duplicate.headers
    assert disallowed.headers["vary"] == "Origin"


def test_wildcard_origin_is_supported_only_without_credentials() -> None:
    app = Flasgo(
        security=SecurityConfig(csrf_enabled=False),
        cors=CORSConfig(allow_origins={"*"}),
    )

    @app.get("/public")
    def public() -> str:
        return "public"

    response = app.test_client().get("/public", headers={"origin": "https://any.example"})

    assert response.headers["access-control-allow-origin"] == "*"
    assert "access-control-allow-credentials" not in response.headers


def test_successful_preflight_is_route_aware_and_skips_application_code() -> None:
    policy = CORSConfig(
        allow_origins={"https://app.example.com"},
        allow_methods={"POST"},
        allow_headers={"Content-Type", "X-API-Key"},
        allow_credentials=True,
        max_age=300,
    )
    app = Flasgo(cors=policy)
    before_calls = 0
    endpoint_calls = 0

    @app.before_request
    def before(_request: Request) -> None:
        nonlocal before_calls
        before_calls += 1

    @app.post("/widgets")
    def create_widget() -> str:
        nonlocal endpoint_calls
        endpoint_calls += 1
        return "created"

    response = _preflight(app, "/widgets", headers="X-API-Key, Content-Type")

    assert response.status_code == 204
    assert response.body == b""
    assert response.headers["access-control-allow-origin"] == "https://app.example.com"
    assert response.headers["access-control-allow-credentials"] == "true"
    assert response.headers["access-control-allow-methods"] == "POST"
    assert response.headers["access-control-allow-headers"] == "content-type, x-api-key"
    assert response.headers["access-control-max-age"] == "300"
    assert response.headers["vary"] == "Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
    assert "set-cookie" not in response.headers
    assert "cache-control" not in response.headers
    assert "content-type" not in response.headers
    assert before_calls == 0
    assert endpoint_calls == 0


def test_preflight_denies_unregistered_methods_and_unlisted_headers() -> None:
    app = Flasgo(
        security=SecurityConfig(csrf_enabled=False),
        cors=CORSConfig(
            allow_origins={"https://app.example.com"},
            allow_methods={"GET", "POST"},
            allow_headers={"content-type"},
        ),
    )

    @app.get("/widgets")
    def widgets() -> str:
        return "widgets"

    unregistered = _preflight(app, "/widgets", method="POST")
    unlisted_header = _preflight(app, "/widgets", method="GET", headers="authorization")

    assert unregistered.status_code == 403
    assert "access-control-allow-origin" not in unregistered.headers
    assert unlisted_header.status_code == 403
    assert unlisted_header.headers["access-control-allow-origin"] == "https://app.example.com"
    assert "access-control-allow-methods" not in unlisted_header.headers


def test_zero_max_age_explicitly_disables_preflight_caching() -> None:
    app = Flasgo(
        cors=CORSConfig(
            allow_origins={"https://app.example.com"},
            allow_methods={"POST"},
            max_age=0,
        )
    )

    @app.post("/widgets")
    def widgets() -> str:
        return "widgets"

    response = _preflight(app, "/widgets")

    assert response.status_code == 204
    assert response.headers["access-control-max-age"] == "0"


def test_malformed_preflight_is_rejected_only_on_cors_managed_paths() -> None:
    app = Flasgo(
        security=SecurityConfig(csrf_enabled=False),
        cors=CORSConfig(allow_origins={"https://app.example.com"}, allow_methods={"POST"}),
    )

    @app.post("/managed")
    def managed() -> str:
        return "ok"

    response = app.test_client().request(
        "OPTIONS",
        "/managed",
        headers=[
            ("origin", "https://app.example.com"),
            ("origin", "https://other.example"),
            ("access-control-request-method", "POST"),
        ],
    )

    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers


def test_route_override_can_disable_global_cors() -> None:
    app = Flasgo(
        security=SecurityConfig(csrf_enabled=False),
        cors=CORSConfig(allow_origins={"https://app.example.com"}),
    )

    @app.get("/private", cors=False)
    def private() -> str:
        return "private"

    response = app.test_client().get("/private", headers={"origin": "https://app.example.com"})
    preflight = _preflight(app, "/private", method="GET")

    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers
    assert preflight.status_code == 405


def test_route_specific_policies_are_not_owned_by_shared_callable() -> None:
    first_policy = CORSConfig(allow_origins={"https://one.example"})
    second_policy = CORSConfig(allow_origins={"https://two.example"})
    app = Flasgo(security=SecurityConfig(csrf_enabled=False))

    def shared() -> str:
        return "shared"

    app.add_route("/one", shared, cors=first_policy)
    app.add_route("/two", shared, cors=second_policy)

    first = app.test_client().get("/one", headers={"origin": "https://one.example"})
    second = app.test_client().get("/two", headers={"origin": "https://two.example"})
    crossed = app.test_client().get("/two", headers={"origin": "https://one.example"})

    assert first.headers["access-control-allow-origin"] == "https://one.example"
    assert second.headers["access-control-allow-origin"] == "https://two.example"
    assert "access-control-allow-origin" not in crossed.headers


def test_cors_headers_cover_csrf_and_endpoint_error_responses() -> None:
    policy = CORSConfig(
        allow_origins={"https://app.example.com"},
        allow_methods={"POST"},
    )
    app = Flasgo(cors=policy)

    @app.post("/csrf")
    def csrf() -> str:
        return "unreachable"

    @app.post("/error")
    def error() -> str:
        raise RuntimeError("failure")

    csrf_response = app.test_client().post("/csrf", headers={"origin": "https://app.example.com"})

    app_without_csrf = Flasgo(security=SecurityConfig(csrf_enabled=False), cors=policy)
    app_without_csrf.add_route("/error", error, methods={"POST"})
    error_response = app_without_csrf.test_client().post(
        "/error",
        headers={"origin": "https://app.example.com"},
    )

    assert csrf_response.status_code == 403
    assert csrf_response.headers["access-control-allow-origin"] == "https://app.example.com"
    assert error_response.status_code == 500
    assert error_response.headers["access-control-allow-origin"] == "https://app.example.com"


def test_cors_headers_cover_authorization_failures() -> None:
    app = Flasgo(cors=CORSConfig(allow_origins={"https://app.example.com"}))

    @app.get("/private")
    @app.authorize(IsAuthenticated())
    def private() -> str:
        return "private"

    response = app.test_client().get("/private", headers={"origin": "https://app.example.com"})

    assert response.status_code == 401
    assert response.headers["access-control-allow-origin"] == "https://app.example.com"


def test_actual_method_must_be_allowed_even_when_request_is_simple() -> None:
    app = Flasgo(
        security=SecurityConfig(csrf_enabled=False),
        cors=CORSConfig(allow_origins={"https://app.example.com"}, allow_methods={"GET"}),
    )

    @app.post("/submit")
    def submit() -> str:
        return "submitted"

    response = app.test_client().post("/submit", headers={"origin": "https://app.example.com"})

    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


def test_internal_docs_do_not_inherit_application_cors() -> None:
    app = Flasgo(
        settings={"ENABLE_DOCS": True, "CSRF_ENABLED": False},
        cors=CORSConfig(allow_origins={"https://app.example.com"}),
    )

    @app.get("/<path:rest>")
    def catch_all(rest: str) -> str:
        return rest

    response = app.test_client().get("/openapi.json", headers={"origin": "https://app.example.com"})
    preflight = _preflight(app, "/openapi.json", method="GET")

    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers
    assert preflight.status_code == 405
    assert "access-control-allow-origin" not in preflight.headers


@pytest.mark.parametrize(
    ("kwargs", "error_type", "match"),
    [
        ({"allow_origins": set()}, ValueError, "at least one"),
        ({"allow_origins": "https://app.example.com"}, TypeError, "collection"),
        ({"allow_origins": {"null"}}, ValueError, "exact ASCII"),
        ({"allow_origins": {"https://app.example.com/"}}, ValueError, "without paths"),
        ({"allow_origins": {"https://app.example.com", "*"}}, ValueError, "only"),
        ({"allow_origins": {"*"}, "allow_credentials": True}, ValueError, "credentials"),
        ({"allow_origins": {"https://app.example.com"}, "allow_headers": {"*"}}, ValueError, "wildcards"),
        ({"allow_origins": {"https://app.example.com"}, "allow_methods": {"*"}}, ValueError, "does not support"),
        ({"allow_origins": {"https://app.example.com"}, "expose_headers": {"set-cookie"}}, ValueError, "Set-Cookie"),
        ({"allow_origins": {"https://app.example.com,evil.example"}}, ValueError, "exact ASCII"),
        ({"allow_origins": {"https://app.example.com"}, "max_age": 86_401}, ValueError, "86400"),
    ],
)
def test_cors_configuration_rejects_unsafe_or_ambiguous_values(
    kwargs: dict[str, Any],
    error_type: type[Exception],
    match: str,
) -> None:
    with pytest.raises(error_type, match=match):
        CORSConfig(**kwargs)


def test_cors_configuration_normalizes_origins_methods_and_headers() -> None:
    config = CORSConfig(
        allow_origins={"HTTPS://APP.EXAMPLE.COM:443", "http://[::1]:80"},
        allow_methods={"get", "post"},
        allow_headers={"Content-Type"},
        expose_headers={"X-Request-ID"},
    )

    assert config.allow_origins == frozenset({"https://app.example.com", "http://[::1]"})
    assert config.allow_methods == frozenset({"GET", "HEAD", "POST"})
    assert config.allow_headers == frozenset({"content-type"})
    assert config.expose_headers == frozenset({"x-request-id"})


def test_cors_matches_equivalent_ipv6_origin_serializations() -> None:
    config = CORSConfig(
        allow_origins={"https://[2001:0DB8:0000:0000:0000:0000:0000:0001]"},
    )
    app = Flasgo(security=SecurityConfig(csrf_enabled=False), cors=config)

    @app.get("/data")
    def data() -> str:
        return "data"

    response = app.test_client().get("/data", headers={"origin": "https://[2001:db8::1]"})

    assert config.allow_origins == frozenset({"https://[2001:db8::1]"})
    assert response.headers["access-control-allow-origin"] == "https://[2001:db8::1]"
