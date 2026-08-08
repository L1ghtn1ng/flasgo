from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Annotated, Any, cast

import pytest
from flasgo import (
    AuthResult,
    Body,
    Cookie,
    Depends,
    Flasgo,
    Form,
    HasScope,
    Header,
    IsAuthenticated,
    Query,
    Request,
    User,
    bearer_token_backend,
)
from flasgo.testing import TestClient
from openapi_spec_validator import OpenAPIV32SpecValidator, validate


@dataclass
class WidgetPayload:
    name: str


def _required_page(page: Annotated[int, Query(alias="page")]) -> int:
    return page


def _string_page(page: Annotated[str, Query(alias="page")]) -> str:
    return page


def test_openapi_json_contains_registered_routes() -> None:
    app = Flasgo(settings={"ENABLE_DOCS": True})

    @app.get("/users/<int:user_id>")
    def get_user(user_id: int, expand: bool = False) -> dict[str, str]:
        """Get user.

        Return a user payload.
        """
        _ = expand
        return {"id": str(user_id)}

    client = TestClient(app)
    response = client.get("/openapi.json")

    assert response.status_code == 200
    spec = cast(dict[str, Any], response.json())
    assert spec["openapi"] == "3.2.0"
    path_item = cast(dict[str, Any], spec["paths"]["/users/{user_id}"]["get"])
    params = {param["name"]: param for param in path_item["parameters"]}
    assert params["user_id"]["in"] == "path"
    assert params["user_id"]["schema"]["type"] == "integer"
    assert params["expand"]["in"] == "query"
    assert params["expand"]["required"] is False
    assert path_item["summary"] == "Get user."


def test_openapi_optional_annotations_use_null_type() -> None:
    app = Flasgo(settings={"ENABLE_DOCS": True})

    @app.get("/items")
    def list_items(tag: str | None = None) -> dict[str, str]:
        _ = tag
        return {"ok": "true"}

    client = TestClient(app)
    spec = cast(dict[str, Any], client.get("/openapi.json").json())
    path_item = cast(dict[str, Any], spec["paths"]["/items"]["get"])
    params = {param["name"]: param for param in path_item["parameters"]}
    schema = params["tag"]["schema"]
    assert schema == {"anyOf": [{"type": "string"}, {"type": "null"}]}
    assert "nullable" not in schema


def test_docs_endpoint_serves_swagger_ui() -> None:
    app = Flasgo(settings={"ENABLE_DOCS": True})
    client = TestClient(app)

    response = client.get("/docs")
    assert response.status_code == 200
    assert "SwaggerUIBundle" in response.text
    assert "/openapi.json" in response.text
    assert "swagger-ui-dist@5.32.12" in response.text
    assert "sha384-9Q2fpS+xeS4ffJy6CagnwoUl+4ldAYhOs9pgZuEKxypVModhmZFzeMlvVsAjf7uT" in response.text
    assert "sha384-aPw2h1Un96ObRq1fD7AOgyf0r9jgkhMD51uBltHKtT0++4LsgMUkQD52RFNWcAil" in response.text
    assert response.text.count('crossorigin="anonymous"') == 2
    assert "queryConfigEnabled: false" in response.text
    assert "validatorUrl: null" in response.text
    assert "unpkg.com" in response.headers["content-security-policy"]


def test_docs_endpoint_escapes_settings_in_html_and_javascript() -> None:
    app = Flasgo(
        settings={
            "ENABLE_DOCS": True,
            "API_TITLE": "</title><img src=x onerror=alert(1)>",
            "OPENAPI_PATH": '/openapi.json";alert(1);//',
        }
    )
    client = TestClient(app)

    response = client.get("/docs")

    assert response.status_code == 200
    assert "</title><img" not in response.text
    assert "&lt;/title&gt;&lt;img src=x onerror=alert(1)&gt; Docs" in response.text
    assert 'url: "/openapi.json\\";alert(1);//"' in response.text
    assert 'url: "/openapi.json";alert(1);//"' not in response.text


def test_openapi_spec_updates_after_new_route_registration() -> None:
    app = Flasgo(settings={"ENABLE_DOCS": True})

    @app.get("/one")
    def one() -> dict[str, bool]:
        return {"ok": True}

    client = TestClient(app)
    initial = cast(dict[str, Any], client.get("/openapi.json").json())
    assert "/one" in initial["paths"]
    assert "/two" not in initial["paths"]

    @app.get("/two")
    def two() -> dict[str, bool]:
        return {"ok": True}

    updated = cast(dict[str, Any], client.get("/openapi.json").json())
    assert "/two" in updated["paths"]


def test_docs_can_be_disabled() -> None:
    app = Flasgo(settings={"ENABLE_DOCS": False})
    client = TestClient(app)

    docs_response = client.get("/docs")
    openapi_response = client.get("/openapi.json")
    assert docs_response.status_code == 404
    assert openapi_response.status_code == 404


def test_docs_default_is_disabled() -> None:
    app = Flasgo()
    client = TestClient(app)

    docs_response = client.get("/docs")
    openapi_response = client.get("/openapi.json")
    assert docs_response.status_code == 404
    assert openapi_response.status_code == 404


def test_custom_docs_paths_work() -> None:
    app = Flasgo(
        settings={
            "ENABLE_DOCS": True,
            "DOCS_PATH": "/api-docs",
            "OPENAPI_PATH": "/api/openapi.json",
        }
    )
    client = TestClient(app)

    docs_response = client.get("/api-docs")
    openapi_response = client.get("/api/openapi.json")
    assert docs_response.status_code == 200
    assert "/api/openapi.json" in docs_response.text
    assert openapi_response.status_code == 200


def test_docs_endpoint_rejects_unsafe_method() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False, "ENABLE_DOCS": True})
    client = TestClient(app)

    response = client.post("/docs")
    assert response.status_code == 405
    assert response.headers["allow"] == "GET, HEAD"
    assert "Use GET or HEAD" in response.text


def test_docs_csp_nonce_matches_inline_script_and_rotates() -> None:
    app = Flasgo(settings={"ENABLE_DOCS": True})
    client = TestClient(app)

    response = client.get("/docs")
    assert response.status_code == 200
    script_src = next(
        directive.strip()
        for directive in response.headers["content-security-policy"].split(";")
        if directive.strip().startswith("script-src")
    )
    assert "unsafe-inline" not in script_src
    header_nonce = re.search(r"'nonce-([^']+)'", script_src)
    assert header_nonce is not None
    tag_nonce = re.search(r'<script nonce="([^"]+)">', response.text)
    assert tag_nonce is not None
    assert tag_nonce.group(1) == header_nonce.group(1)
    style_src = next(
        directive.strip()
        for directive in response.headers["content-security-policy"].split(";")
        if directive.strip().startswith("style-src")
    )
    assert "unsafe-inline" not in style_src
    assert f"'nonce-{tag_nonce.group(1)}'" in style_src
    assert f'<style nonce="{tag_nonce.group(1)}">' in response.text

    rotated = re.search(r'<script nonce="([^"]+)">', client.get("/docs").text)
    assert rotated is not None
    assert rotated.group(1) != tag_nonce.group(1)


def test_openapi_documents_framework_error_statuses() -> None:
    app = Flasgo(settings={"ENABLE_DOCS": True})

    @app.post("/widgets")
    def create_widget(payload: Annotated[WidgetPayload, Body()]) -> dict[str, str]:
        return {"name": payload.name}

    @app.get("/slow")
    @app.ratelimit(1, per=60)
    def slow() -> str:
        return "ok"

    @app.get("/plain")
    def plain() -> str:
        return "ok"

    spec = app.openapi_spec()

    post_responses = spec["paths"]["/widgets"]["post"]["responses"]
    assert post_responses["413"] == {"description": "Payload Too Large"}
    assert post_responses["415"] == {"description": "Unsupported Media Type"}
    assert post_responses["422"]["description"] == "Request Validation Error"
    assert post_responses["403"] == {"description": "Forbidden"}

    limited_responses = spec["paths"]["/slow"]["get"]["responses"]
    assert limited_responses["429"] == {"description": "Too Many Requests"}
    assert "403" not in limited_responses
    assert "413" not in limited_responses

    plain_responses = spec["paths"]["/plain"]["get"]["responses"]
    assert "403" not in plain_responses
    assert "413" not in plain_responses
    assert "415" not in plain_responses
    assert "429" not in plain_responses


def test_openapi_omits_csrf_forbidden_when_csrf_disabled() -> None:
    app = Flasgo(settings={"ENABLE_DOCS": True, "CSRF_ENABLED": False})

    @app.post("/widgets")
    def create_widget(payload: Annotated[WidgetPayload, Body()]) -> dict[str, str]:
        return {"name": payload.name}

    responses = app.openapi_spec()["paths"]["/widgets"]["post"]["responses"]
    assert "403" not in responses
    assert responses["413"] == {"description": "Payload Too Large"}


def test_openapi_servers_setting_controls_root_servers() -> None:
    app = Flasgo(settings={"API_SERVERS": ["https://api.example.com", "https://staging.example.com"]})
    assert app.openapi_spec()["servers"] == [
        {"url": "https://api.example.com"},
        {"url": "https://staging.example.com"},
    ]
    assert "servers" not in Flasgo().openapi_spec()


def test_openapi_declares_json_schema_dialect() -> None:
    assert Flasgo().openapi_spec()["jsonSchemaDialect"] == "https://json-schema.org/draft/2020-12/schema"


def test_openapi_32_documents_query_and_additional_operations() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.route("/search", methods=("QUERY",))
    def query() -> dict[str, bool]:
        return {"ok": True}

    @app.route("/tunnel", methods=("CONNECT",))
    def connect() -> dict[str, bool]:
        return {"ok": True}

    spec = app.openapi_spec()
    validate(spec)
    assert spec["paths"]["/search"]["query"]["operationId"] == "query_query"
    assert spec["paths"]["/tunnel"]["additionalOperations"]["CONNECT"]["operationId"] == "connect_connect"
    assert "connect" not in spec["paths"]["/tunnel"]


def test_openapi_32_security_metadata_and_required_scopes() -> None:
    scheme: dict[str, object] = {
        "type": "oauth2",
        "deprecated": True,
        "oauth2MetadataUrl": "https://identity.example.com/.well-known/oauth-authorization-server",
        "flows": {
            "deviceAuthorization": {
                "deviceAuthorizationUrl": "https://identity.example.com/device",
                "tokenUrl": "https://identity.example.com/token",
                "scopes": {"admin": "Administer widgets", "read": "Read widgets"},
            }
        },
        "x-owner": "identity-team",
    }
    app = Flasgo()
    app.register_auth_backend(
        "deviceAuth",
        bearer_token_backend(lambda token: User(id=token, is_authenticated=True)),
        openapi_scheme=scheme,
    )

    @app.get("/private")
    @app.authorize(
        HasScope("read"),
        IsAuthenticated(),
        HasScope("admin"),
        HasScope("read"),
        backend="deviceAuth",
    )
    def private() -> dict[str, bool]:
        return {"ok": True}

    device_flow = cast(dict[str, Any], cast(dict[str, Any], scheme["flows"])["deviceAuthorization"])
    device_flow["tokenUrl"] = "https://attacker.example/token"
    scheme["deprecated"] = False

    spec = app.openapi_spec()
    validate(spec)
    emitted = spec["components"]["securitySchemes"]["deviceAuth"]
    assert emitted["deprecated"] is True
    assert emitted["flows"]["deviceAuthorization"]["tokenUrl"] == "https://identity.example.com/token"
    assert spec["paths"]["/private"]["get"]["security"] == [{"deviceAuth": ["admin", "read"]}]


def test_bearer_backend_openapi_uses_the_configured_authentication_scheme() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})
    app.register_auth_backend(
        "tokenAuth",
        bearer_token_backend(lambda token: User(id=token, is_authenticated=True), scheme="Token"),
    )

    @app.get("/private")
    @app.authorize(backend="tokenAuth")
    def private() -> str:
        return "ok"

    spec = app.openapi_spec()
    assert spec["components"]["securitySchemes"]["tokenAuth"] == {
        "type": "http",
        "scheme": "token",
    }
    client = app.test_client()
    assert client.get("/private", headers={"authorization": "Token secret"}).status_code == 200
    assert client.get("/private", headers={"authorization": "Bearer secret"}).status_code == 401


def test_bearer_backend_omits_automatic_openapi_for_non_token_schemes() -> None:
    app = Flasgo()
    app.register_auth_backend(
        "customAuth",
        bearer_token_backend(lambda token: User(id=token, is_authenticated=True), scheme="Custom Scheme"),
    )

    @app.get("/private")
    @app.authorize(backend="customAuth")
    def private() -> str:
        return "ok"

    spec = app.openapi_spec()
    assert "components" not in spec
    assert "security" not in spec["paths"]["/private"]["get"]
    assert (
        app.test_client()
        .get(
            "/private",
            headers={"authorization": "Custom Scheme secret"},
        )
        .status_code
        == 200
    )


def test_openapi_merges_duplicate_wire_parameter_requiredness() -> None:
    app = Flasgo()

    @app.get("/widgets")
    def widgets(
        page: Annotated[int, Query(alias="page")] = 1,
        *,
        dependency_page: Annotated[int, Depends(_required_page)],
    ) -> dict[str, int]:
        return {"page": page, "dependency_page": dependency_page}

    parameter = app.openapi_spec()["paths"]["/widgets"]["get"]["parameters"][0]
    assert parameter == {"name": "page", "in": "query", "required": True, "schema": {"type": "integer"}}
    assert app.test_client().get("/widgets").status_code == 422
    assert app.test_client().get("/widgets?page=2").json() == {"page": 2, "dependency_page": 2}


def test_openapi_rejects_conflicting_duplicate_wire_parameter_schemas() -> None:
    app = Flasgo()

    @app.get("/widgets")
    def widgets(
        page: Annotated[int, Query(alias="page")],
        dependency_page: Annotated[str, Depends(_string_page)],
    ) -> str:
        return f"{page}:{dependency_page}"

    with pytest.raises(ValueError, match=r"conflicting schemas.*query parameter 'page'"):
        app.openapi_spec()


@pytest.mark.parametrize(
    "scheme",
    [
        {"type": "apiKey", "name": "x-api-key", "in": "header"},
        {"type": "http", "scheme": "bearer", "bearerFormat": "opaque", "deprecated": True},
        {"type": "mutualTLS", "description": "Certificate authentication"},
        {"type": "openIdConnect", "openIdConnectUrl": "https://identity.example.com/.well-known/openid-configuration"},
        {
            "type": "oauth2",
            "oauth2MetadataUrl": "https://identity.example.com/.well-known/oauth-authorization-server",
            "flows": {
                "clientCredentials": {
                    "tokenUrl": "https://identity.example.com/token",
                    "scopes": {},
                }
            },
        },
    ],
)
def test_openapi_accepts_supported_local_security_scheme_types(scheme: dict[str, object]) -> None:
    app = Flasgo()
    app.register_auth_backend("customAuth", lambda request: None, openapi_scheme=scheme)

    @app.get("/private")
    @app.authorize(backend="customAuth")
    def private() -> str:
        return "ok"

    validate(app.openapi_spec(), cls=OpenAPIV32SpecValidator)


@pytest.mark.parametrize(
    ("name", "scheme", "message"),
    [
        ("bad/name", {"type": "http", "scheme": "bearer"}, "scheme names"),
        ("external", {"$ref": "https://identity.example/scheme"}, "local Security Scheme Object"),
        ("invalid-http", {"type": "http", "scheme": "bad scheme"}, "HTTP token"),
        ("basic", {"type": "http", "scheme": "basic", "bearerFormat": "JWT"}, "bearerFormat"),
        (
            "oauth",
            {"type": "oauth2", "oauth2MetadataUrl": "http://identity.example/metadata", "flows": {}},
            "HTTPS",
        ),
        (
            "credentials",
            {"type": "openIdConnect", "openIdConnectUrl": "https://user:secret@identity.example/config"},
            "embedded credentials",
        ),
        (
            "device",
            {
                "type": "oauth2",
                "flows": {
                    "deviceAuthorization": {
                        "deviceAuthorizationUrl": "https://identity.example/device",
                        "scopes": {},
                    }
                },
            },
            "tokenUrl",
        ),
        ("unknown", {"type": "mutualTLS", "remote": True}, "unsupported fields"),
        ("nonfinite", {"type": "mutualTLS", "x-score": float("nan")}, "finite JSON-compatible"),
    ],
)
def test_openapi_security_metadata_rejects_unsafe_or_invalid_values(
    name: str,
    scheme: dict[str, object],
    message: str,
) -> None:
    app = Flasgo()
    with pytest.raises(ValueError, match=message):
        app.register_auth_backend(name, lambda request: None, openapi_scheme=scheme)
    assert name.strip() not in app._auth_backends


def test_docs_can_require_a_registered_auth_backend() -> None:
    app = Flasgo(settings={"ENABLE_DOCS": True, "DOCS_AUTH_BACKEND": "docs"})

    def docs_backend(request: Request) -> AuthResult:
        if request.headers.get("x-docs-token") == "allowed":
            return AuthResult(user=User(id="docs", is_authenticated=True))
        return AuthResult(challenge="Docs")

    app.register_auth_backend("docs", docs_backend)
    client = app.test_client()
    for path in ("/docs", "/openapi.json"):
        denied = client.get(path)
        assert denied.status_code == 401
        assert denied.headers["www-authenticate"] == "Docs"
        assert client.get(path, headers={"x-docs-token": "allowed"}).status_code == 200


def test_docs_auth_backend_failures_are_bounded() -> None:
    missing = Flasgo(settings={"ENABLE_DOCS": True, "DOCS_AUTH_BACKEND": "missing"})
    assert missing.test_client().get("/docs").status_code == 500

    failing = Flasgo(settings={"ENABLE_DOCS": True, "DOCS_AUTH_BACKEND": "failing"})

    def failing_backend(_request: Request) -> None:
        raise RuntimeError("credential detail must not escape")

    failing.register_auth_backend("failing", failing_backend)
    response = failing.test_client().get("/openapi.json")
    assert response.status_code == 500
    assert "credential detail" not in response.text


def test_docs_authentication_is_throttled_before_repeating_backend_work() -> None:
    calls = 0
    app = Flasgo(
        settings={
            "ENABLE_DOCS": True,
            "DOCS_AUTH_BACKEND": "docs",
            "SECURITY_FAILURE_RATE_LIMIT": 1,
        }
    )

    def docs_backend(_request: Request) -> AuthResult:
        nonlocal calls
        calls += 1
        return AuthResult(challenge="Docs")

    app.register_auth_backend("docs", docs_backend)
    client = app.test_client()

    assert client.get("/docs").status_code == 401
    assert client.get("/docs").status_code == 429
    assert calls == 1


def test_docs_auth_backend_setting_rejects_blank_names() -> None:
    with pytest.raises(ValueError, match="DOCS_AUTH_BACKEND"):
        Flasgo(settings={"DOCS_AUTH_BACKEND": " "})


def test_openapi_rejects_blank_server_urls() -> None:
    with pytest.raises(ValueError, match="API_SERVERS"):
        Flasgo(settings={"API_SERVERS": ["  "]})


def test_comprehensive_openapi_document_passes_validator() -> None:
    app = Flasgo(settings={"API_SERVERS": ["https://api.example.com"]})
    app.register_auth_backend(
        "bearer",
        bearer_token_backend(lambda token: User(id=token, is_authenticated=True)),
    )

    @app.post("/widgets/<int:widget_id>")
    @app.ratelimit(2, per=60)
    @app.authorize(backend="bearer")
    def create_widget(
        widget_id: int,
        payload: Annotated[WidgetPayload, Body()],
        verbose: Annotated[bool, Query()] = False,
        trace_id: Annotated[str, Header(alias="x-trace-id")] = "none",
        session_id: Annotated[str, Cookie(alias="session-id")] = "none",
    ) -> WidgetPayload:
        _ = widget_id, verbose, trace_id, session_id
        return payload

    @app.post("/search")
    def search(payload: Annotated[WidgetPayload, Form()]) -> dict[str, str]:
        return {"name": payload.name}

    @app.get("/health")
    def health() -> str:
        return "ok"

    spec = app.openapi_spec()
    validate(spec, cls=OpenAPIV32SpecValidator)
    assert len(spec["paths"]) == 3
