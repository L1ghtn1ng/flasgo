from dataclasses import dataclass, field

from flasgo import Flasgo, Response


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
    import pytest

    class Unsupported:
        pass

    @dataclass
    class Model:
        nested: Unsupported

    with pytest.raises(TypeError, match="Unsupported response model"):
        Flasgo().get("/", response_model=Model)(dict)
