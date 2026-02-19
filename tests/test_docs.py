from __future__ import annotations

from typing import Any, cast

from fango import Fango
from fango.testing import TestClient


def test_openapi_json_contains_registered_routes() -> None:
    app = Fango(settings={"ENABLE_DOCS": True})

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
    assert spec["openapi"] == "3.1.0"
    path_item = cast(dict[str, Any], spec["paths"]["/users/{user_id}"]["get"])
    params = {param["name"]: param for param in path_item["parameters"]}
    assert params["user_id"]["in"] == "path"
    assert params["user_id"]["schema"]["type"] == "integer"
    assert params["expand"]["in"] == "query"
    assert params["expand"]["required"] is False
    assert path_item["summary"] == "Get user."


def test_docs_endpoint_serves_swagger_ui() -> None:
    app = Fango(settings={"ENABLE_DOCS": True})
    client = TestClient(app)

    response = client.get("/docs")
    assert response.status_code == 200
    assert "SwaggerUIBundle" in response.text
    assert "/openapi.json" in response.text
    assert "unpkg.com/swagger-ui-dist" in response.text
    assert "unpkg.com" in response.headers["content-security-policy"]


def test_openapi_spec_updates_after_new_route_registration() -> None:
    app = Fango(settings={"ENABLE_DOCS": True})

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
    app = Fango(settings={"ENABLE_DOCS": False})
    client = TestClient(app)

    docs_response = client.get("/docs")
    openapi_response = client.get("/openapi.json")
    assert docs_response.status_code == 404
    assert openapi_response.status_code == 404


def test_docs_default_is_disabled() -> None:
    app = Fango()
    client = TestClient(app)

    docs_response = client.get("/docs")
    openapi_response = client.get("/openapi.json")
    assert docs_response.status_code == 404
    assert openapi_response.status_code == 404


def test_custom_docs_paths_work() -> None:
    app = Fango(
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
    app = Fango(settings={"CSRF_ENABLED": False, "ENABLE_DOCS": True})
    client = TestClient(app)

    response = client.post("/docs")
    assert response.status_code == 405
