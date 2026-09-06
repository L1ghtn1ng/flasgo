from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import pytest
from flasgo import EventSourceResponse, Flasgo, NDJSONResponse, Response


@dataclass
class PublicUser:
    id: int
    display_name: str
    _private: str = "hidden"


@dataclass
class PublicTeam:
    members: list[PublicUser]
    count: int = field(init=False, default=1)


def test_response_contract_filters_nested_data_and_matches_openapi() -> None:
    app = Flasgo()

    @app.get("/", response_model=PublicTeam)
    def team() -> dict:
        return {
            "members": [{"id": 1, "display_name": "A", "password_hash": "secret", "_private": "secret"}],
            "internal": True,
        }

    assert app.test_client().get("/").json() == {"members": [{"id": 1, "display_name": "A"}], "count": 1}
    schema = app.openapi_spec()["components"]["schemas"]["PublicUser"]
    assert set(schema["properties"]) == {"id", "display_name"}


def test_invalid_output_is_server_error_without_reflecting_values() -> None:
    app = Flasgo()
    app.get("/", response_model=PublicUser)(lambda: {"id": "secret", "display_name": "A"})
    response = app.test_client().get("/")
    assert response.status_code == 500
    assert "secret" not in response.text


def test_response_contract_cannot_be_bypassed_with_raw_response() -> None:
    app = Flasgo()
    app.get("/", response_model=PublicUser)(lambda: Response.json({"password_hash": "secret"}))
    assert app.test_client().get("/").status_code == 500


def test_contract_keeps_tuple_status_and_headers_and_untyped_behavior() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})
    app.post("/", response_model=PublicUser)(
        lambda: ({"id": 1, "display_name": "A", "secret": True}, 201, {"x-result": "created"})
    )
    response = app.test_client().post("/")
    assert response.status_code == 201
    assert response.headers["x-result"] == "created"
    assert response.json() == {"id": 1, "display_name": "A"}
    app.get("/untyped")(lambda: {"application_key": "preserved"})
    assert app.test_client().get("/untyped").json() == {"application_key": "preserved"}


def test_recursive_output_is_bounded() -> None:
    app = Flasgo(settings={"MAX_VALIDATION_DEPTH": 5})
    value = {}
    value["self"] = value
    app.get("/", response_model=dict)(lambda: value)
    assert app.test_client().get("/").status_code == 500


def test_response_contract_rejects_unsupported_nested_types_at_registration() -> None:
    class Unsupported:
        pass

    @dataclass
    class Model:
        nested: Unsupported

    with pytest.raises(TypeError, match="Unsupported response model"):
        Flasgo().get("/", response_model=Model)(dict)


@pytest.mark.parametrize(
    "model",
    [
        dict[int, str],
        Mapping[int, str],
        dict[bool, str],
        dict[float, str],
        list[dict[int, str]],
        dict[str, dict[int, str]],
    ],
)
def test_mapping_key_models_fail_before_route_registration(model: object) -> None:
    app = Flasgo()
    with pytest.raises(TypeError, match="mappings must use str or Any keys"):
        app.get("/", response_model=model)(dict)
    assert app._routes == []


def test_dataclass_mapping_key_models_fail_at_registration() -> None:
    @dataclass
    class Model:
        labels: Mapping[int, str]

    with pytest.raises(TypeError, match="mappings must use str or Any keys"):
        Flasgo().get("/", response_model=Model)(dict)


@pytest.mark.parametrize("model", [dict[str, PublicUser], Mapping[str, PublicUser], dict[Any, PublicUser]])
def test_supported_mapping_models_project_values_and_reject_non_string_output_keys(model: object) -> None:
    app = Flasgo()
    value = {"id": 1, "display_name": "A", "password_hash": "secret"}
    app.get("/", response_model=model)(lambda: {"user": value})
    invalid_output: dict[Any, Any] = {1: value}
    app.get("/invalid", response_model=model)(lambda: invalid_output)
    assert app.test_client().get("/").json() == {"user": {"id": 1, "display_name": "A"}}
    assert app.test_client().get("/invalid").status_code == 500


@pytest.mark.parametrize("response_type", [EventSourceResponse, NDJSONResponse])
def test_stream_mapping_model_is_rejected_before_source_consumption(response_type: type) -> None:
    async def source():
        pytest.fail("Invalid model must be rejected before consuming items")
        yield {}

    with pytest.raises(TypeError, match="mappings must use str or Any keys"):
        response_type(source(), item_model=dict[int, str])
