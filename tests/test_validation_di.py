from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Annotated, Any, Literal, cast

import pytest
from flasgo import (
    Body,
    Cookie,
    Depends,
    Flasgo,
    Form,
    FormValidationError,
    Header,
    Query,
    Response,
    UploadedFile,
)
from flasgo.validation import SchemaRegistry


@dataclass(slots=True)
class CreateWidget:
    name: str
    quantity: int


@dataclass
class RecursiveA:
    child: RecursiveA | RecursiveB


@dataclass
class RecursiveB:
    child: RecursiveA | RecursiveB
    enabled: bool = True


@dataclass(slots=True)
class UploadForm:
    title: str
    attachment: UploadedFile


@dataclass(slots=True)
class OptionalUploadCollectionForm:
    files: list[UploadedFile] | None = None


@dataclass(slots=True)
class WidgetResponse:
    name: str
    quantity: int


@dataclass(slots=True)
class ComputedInput:
    value: int
    doubled: int = field(init=False)

    def __post_init__(self) -> None:
        self.doubled = self.value * 2


@dataclass(slots=True)
class LiteralForm:
    level: Literal[1, 2]
    enabled: Literal[True, False]


class NumericLevel(Enum):
    LOW = 1
    HIGH = 2


class BooleanChoice(Enum):
    DISABLED = False
    ENABLED = True


@dataclass(slots=True)
class EnumForm:
    enabled: BooleanChoice


class UnknownAnnotation:
    pass


_DI_CALLS = 0


def _page_size(limit: Annotated[int, Query()] = 10) -> int:
    global _DI_CALLS
    _DI_CALLS += 1
    return limit


def _pagination(size: Annotated[int, Depends(_page_size)]) -> str:
    return f"page:{size}"


def _openapi_page_size(limit: Annotated[int, Query(alias="page-size")] = 20) -> int:
    return limit


def _cycle_provider(value: str) -> str:
    return value


_cycle_provider.__annotations__["value"] = Annotated[str, Depends(_cycle_provider)]


def _body_provider(payload: Annotated[CreateWidget, Body()]) -> str:
    return payload.name


def _client_version(x_client_version: Annotated[int, Header()] = 1) -> int:
    return x_client_version


def test_annotated_body_query_and_dataclass_response() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.post("/widgets")
    def create_widget(
        payload: Annotated[CreateWidget, Body()],
        dry_run: Annotated[bool, Query(alias="dry-run")] = False,
    ) -> dict[str, object]:
        return {"widget": payload.name, "quantity": payload.quantity, "dry_run": dry_run}

    client = app.test_client()
    response = client.post(
        "/widgets?dry-run=true",
        json={"name": "bolts", "quantity": 4},
    )
    assert response.status_code == 200
    assert response.json() == {"widget": "bolts", "quantity": 4, "dry_run": True}

    invalid = client.post(
        "/widgets?dry-run=sometimes",
        json={"name": "bolts", "quantity": "many", "unknown": True},
    )
    assert invalid.status_code == 422
    payload = cast(dict[str, Any], invalid.json())
    errors = cast(list[dict[str, Any]], payload["errors"])
    locations = {tuple(issue["location"]) for issue in errors}
    assert locations == {("query", "dry-run"), ("body", "quantity"), ("body", "unknown")}

    @app.get("/widget-response")
    def widget_response() -> WidgetResponse:
        return WidgetResponse(name="bolts", quantity=4)

    assert client.get("/widget-response").json() == {"name": "bolts", "quantity": 4}


def test_body_and_form_enforce_content_type() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.post("/json")
    def json_endpoint(payload: Annotated[CreateWidget, Body()]) -> str:
        return payload.name

    @app.post("/form")
    def form_endpoint(payload: Annotated[UploadForm, Form()]) -> str:
        return payload.title

    client = app.test_client()
    assert client.post("/json", data={"name": "wrong"}).status_code == 415
    assert client.post("/form", json={"title": "wrong"}).status_code == 415
    missing_json = client.post("/json")
    assert missing_json.status_code == 422
    assert missing_json.json() == {
        "error": "validation_error",
        "detail": "Request validation failed.",
        "errors": [{"location": ["body"], "code": "missing", "message": "Request body is required."}],
    }


def test_form_validation_error_preserves_safe_form_values() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.errorhandler(FormValidationError)
    def form_error(_request: object, exc: Exception) -> Response:
        assert isinstance(exc, FormValidationError)
        return Response.json(
            {
                "title": exc.form_data.get("title"),
                "field_errors": exc.errors,
                "errors": [issue.as_dict() for issue in exc.issues],
            },
            status_code=422,
        )

    @app.post("/upload")
    def upload(payload: Annotated[UploadForm, Form()]) -> dict[str, object]:
        return {"title": payload.title, "size": payload.attachment.size}

    client = app.test_client()
    invalid = client.post("/upload", data={"title": "quarterly"})
    assert invalid.status_code == 422
    assert invalid.json() == {
        "title": "quarterly",
        "field_errors": {"attachment": ["Field is required."]},
        "errors": [
            {
                "location": ["form", "attachment"],
                "code": "missing",
                "message": "Field is required.",
            }
        ],
    }

    unknown = client.post(
        "/upload",
        data={"title": "quarterly", "unexpected": "value"},
        files={"attachment": ("report.txt", b"contents", "text/plain")},
    )
    assert unknown.status_code == 422
    unknown_payload = cast(dict[str, Any], unknown.json())
    assert unknown_payload["field_errors"] == {"unexpected": ["Unknown field."]}

    valid = client.post(
        "/upload",
        data={"title": "quarterly"},
        files={"attachment": ("report.txt", b"contents", "text/plain")},
    )
    assert valid.json() == {"title": "quarterly", "size": 8}


def test_dependencies_are_nested_cached_and_validated() -> None:
    app = Flasgo()
    global _DI_CALLS
    _DI_CALLS = 0

    @app.get("/items")
    def items(
        first: Annotated[int, Depends(_page_size)],
        second: Annotated[int, Depends(_page_size)],
        label: Annotated[str, Depends(_pagination)],
    ) -> dict[str, object]:
        return {"first": first, "second": second, "label": label}

    response = app.test_client().get("/items?limit=25")
    assert response.json() == {"first": 25, "second": 25, "label": "page:25"}
    assert _DI_CALLS == 1


def test_dependency_cycles_and_multiple_body_models_fail_at_registration() -> None:
    app = Flasgo()

    with pytest.raises(TypeError, match="Dependency cycle"):

        @app.get("/cycle")
        def cycle(value: Annotated[str, Depends(_cycle_provider)]) -> str:
            return value

    with pytest.raises(TypeError, match=r"multiple Body\(\)/Form\(\) inputs"):

        @app.post("/two-bodies")
        def two_bodies(
            payload: Annotated[CreateWidget, Body()],
            name: Annotated[str, Depends(_body_provider)],
        ) -> str:
            return payload.name + name


def test_openapi_uses_models_dependencies_forms_and_validation_contract() -> None:
    app = Flasgo(settings={"ENABLE_DOCS": True})

    @app.post("/widgets")
    def create_widget(
        payload: Annotated[CreateWidget, Body()],
        limit: Annotated[int, Depends(_openapi_page_size)],
    ) -> dict[str, object]:
        return {"limit": limit, "name": payload.name}

    spec = app.openapi_spec()
    operation = spec["paths"]["/widgets"]["post"]
    assert operation["parameters"] == [
        {
            "name": "page-size",
            "in": "query",
            "required": False,
            "schema": {"type": "integer"},
        }
    ]
    assert operation["requestBody"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/CreateWidget"
    }
    assert operation["responses"]["422"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/RequestValidationError"
    }
    assert spec["components"]["schemas"]["CreateWidget"]["required"] == ["name", "quantity"]

    form_app = Flasgo(settings={"ENABLE_DOCS": True})

    @form_app.post("/upload")
    def upload(payload: Annotated[UploadForm, Form()]) -> str:
        return payload.title

    form_content = form_app.openapi_spec()["paths"]["/upload"]["post"]["requestBody"]["content"]
    assert set(form_content) == {"multipart/form-data"}


def test_one_endpoint_registered_on_different_paths_keeps_route_specific_plans() -> None:
    app = Flasgo(settings={"ENABLE_DOCS": True})

    def shared(user_id: int | None = None, item_id: int | None = None) -> dict[str, int | None]:
        return {"user_id": user_id, "item_id": item_id}

    app.add_route("/users/<int:user_id>", shared)
    app.add_route("/items/<int:item_id>", shared)

    client = app.test_client()
    assert client.get("/users/7").json() == {"user_id": 7, "item_id": None}
    assert client.get("/items/9").json() == {"user_id": None, "item_id": 9}

    spec = app.openapi_spec()
    user_parameters = {item["name"]: item for item in spec["paths"]["/users/{user_id}"]["get"]["parameters"]}
    item_parameters = {item["name"]: item for item in spec["paths"]["/items/{item_id}"]["get"]["parameters"]}
    assert user_parameters["user_id"]["in"] == "path"
    assert user_parameters["item_id"]["in"] == "query"
    assert item_parameters["item_id"]["in"] == "path"
    assert item_parameters["user_id"]["in"] == "query"


def test_unresolved_local_return_annotation_does_not_block_route_registration() -> None:
    app = Flasgo(settings={"ENABLE_DOCS": True})

    def build_endpoint():
        class LocalResult(dict[str, int]):
            pass

        def endpoint(value: Annotated[int, Query()]) -> LocalResult:
            return LocalResult(value=value)

        return endpoint

    app.add_route("/local-result", build_endpoint())

    response = app.test_client().get("/local-result?value=7")
    assert response.status_code == 200
    assert response.json() == {"value": 7}
    parameter = app.openapi_spec()["paths"]["/local-result"]["get"]["parameters"][0]
    assert parameter["schema"] == {"type": "integer"}

    def build_unresolved_body_endpoint():
        class LocalPayload:
            pass

        def endpoint(payload: Annotated[LocalPayload, Body()]) -> str:
            return str(payload)

        return endpoint

    with pytest.raises(TypeError, match="marked annotation"):
        app.add_route("/local-body", build_unresolved_body_endpoint(), methods=("POST",))


def test_optional_uploaded_file_collection_preserves_submitted_files() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False, "ENABLE_DOCS": True})

    @app.post("/optional-files")
    def optional_files(payload: Annotated[OptionalUploadCollectionForm, Form()]) -> dict[str, object]:
        return {
            "names": [item.filename for item in payload.files or []],
            "sizes": [item.size for item in payload.files or []],
        }

    response = app.test_client().post(
        "/optional-files",
        files={"files": ("report.txt", b"contents", "text/plain")},
    )
    assert response.status_code == 200
    assert response.json() == {"names": ["report.txt"], "sizes": [8]}
    content = app.openapi_spec()["paths"]["/optional-files"]["post"]["requestBody"]["content"]
    assert set(content) == {"multipart/form-data"}


def test_fixed_tuple_validation_and_schema_are_positional() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False, "ENABLE_DOCS": True})

    @app.post("/fixed-tuple")
    def fixed_tuple(payload: Annotated[tuple[int, str], Body()]) -> list[object]:
        return list(payload)

    @app.post("/variable-tuple")
    def variable_tuple(payload: Annotated[tuple[int, ...], Body()]) -> list[int]:
        return list(payload)

    client = app.test_client()
    assert client.post("/fixed-tuple", json=[1, "name"]).json() == [1, "name"]
    assert client.post("/fixed-tuple", json=[1, 2]).status_code == 422
    assert client.post("/fixed-tuple", json=[1]).status_code == 422
    assert client.post("/variable-tuple", json=[1, 2]).json() == [1, 2]

    fixed_schema = app.openapi_spec()["paths"]["/fixed-tuple"]["post"]["requestBody"]["content"]["application/json"][
        "schema"
    ]
    assert fixed_schema == {
        "type": "array",
        "prefixItems": [{"type": "integer"}, {"type": "string"}],
        "minItems": 2,
        "maxItems": 2,
    }
    variable_schema = app.openapi_spec()["paths"]["/variable-tuple"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]
    assert variable_schema == {"type": "array", "items": {"type": "integer"}}


def test_init_false_dataclass_fields_are_not_request_inputs() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False, "ENABLE_DOCS": True})

    @app.post("/computed")
    def computed(payload: Annotated[ComputedInput, Body()]) -> ComputedInput:
        return payload

    @app.post("/computed-form")
    def computed_form(payload: Annotated[ComputedInput, Form()]) -> ComputedInput:
        return payload

    client = app.test_client()
    assert client.post("/computed", json={"value": 4}).json() == {"value": 4, "doubled": 8}
    supplied_computed = client.post("/computed", json={"value": 4, "doubled": 99})
    assert supplied_computed.status_code == 422
    assert supplied_computed.json() == {
        "error": "validation_error",
        "detail": "Request validation failed.",
        "errors": [{"location": ["body", "doubled"], "code": "unknown_field", "message": "Unknown field."}],
    }
    spec = app.openapi_spec()
    operation = spec["paths"]["/computed"]["post"]
    request_component = operation["requestBody"]["content"]["application/json"]["schema"]["$ref"].rsplit("/", 1)[1]
    response_component = operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].rsplit("/", 1)[
        1
    ]
    request_schema = spec["components"]["schemas"][request_component]
    assert request_schema["properties"] == {"value": {"type": "integer"}}
    assert request_schema["required"] == ["value"]
    response_schema = spec["components"]["schemas"][response_component]
    assert response_schema["properties"] == {
        "value": {"type": "integer"},
        "doubled": {"type": "integer"},
    }

    assert client.post("/computed-form", data={"value": "5"}).json() == {"value": 5, "doubled": 10}
    supplied_form_computed = client.post("/computed-form", data={"value": "5", "doubled": "99"})
    assert supplied_form_computed.status_code == 422
    form_payload = cast(dict[str, Any], supplied_form_computed.json())
    assert form_payload["errors"] == [
        {"location": ["form", "doubled"], "code": "unknown_field", "message": "Unknown field."}
    ]


def test_numeric_and_boolean_literals_are_converted_from_query_and_form_text() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.get("/literal-query")
    def literal_query(
        level: Annotated[Literal[1, 2], Query()],
        enabled: Annotated[Literal[True, False], Query()],
    ) -> dict[str, object]:
        return {"level": level, "enabled": enabled}

    @app.post("/literal-form")
    def literal_form(payload: Annotated[LiteralForm, Form()]) -> dict[str, object]:
        return {"level": payload.level, "enabled": payload.enabled}

    client = app.test_client()
    assert client.get("/literal-query?level=1&enabled=true").json() == {"level": 1, "enabled": True}
    assert client.post("/literal-form", data={"level": "2", "enabled": "false"}).json() == {
        "level": 2,
        "enabled": False,
    }


def test_numeric_and_boolean_enums_are_converted_from_query_and_form_text() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.get("/enum-query")
    def enum_query(level: Annotated[NumericLevel, Query()]) -> dict[str, int]:
        return {"level": level.value}

    @app.post("/enum-form")
    def enum_form(payload: Annotated[EnumForm, Form()]) -> dict[str, bool]:
        return {"enabled": payload.enabled.value}

    client = app.test_client()
    assert client.get("/enum-query?level=2").json() == {"level": 2}
    assert client.post("/enum-form", data={"enabled": "true"}).json() == {"enabled": True}


def test_optional_collection_query_parameters_accept_supplied_values() -> None:
    app = Flasgo()

    @app.get("/optional-collection")
    def optional_collection(
        values: Annotated[list[int] | None, Query()] = None,
    ) -> dict[str, list[int] | None]:
        return {"values": values}

    client = app.test_client()
    assert client.get("/optional-collection").json() == {"values": None}
    assert client.get("/optional-collection?values=1&values=2").json() == {"values": [1, 2]}


def test_header_and_cookie_bindings_are_typed_aliased_and_documented() -> None:
    app = Flasgo(settings={"ENABLE_DOCS": True})

    @app.get("/context")
    def context(
        request_id: Annotated[str, Header(alias="x-request-token")],
        session_id: Annotated[int, Cookie(alias="session-id")],
        versions: Annotated[list[int], Header(alias="x-version")],
        client_version: Annotated[int, Depends(_client_version)],
    ) -> dict[str, object]:
        return {
            "request_id": request_id,
            "session_id": session_id,
            "versions": versions,
            "client_version": client_version,
        }

    client = app.test_client()
    response = client.get(
        "/context",
        headers={
            "x-request-token": "request-7",
            "x-version": "3",
            "x-client-version": "4",
            "cookie": "session-id=12",
        },
    )
    assert response.json() == {
        "request_id": "request-7",
        "session_id": 12,
        "versions": [3],
        "client_version": 4,
    }
    repeated = client.get(
        "/context",
        headers=[
            ("x-request-token", "request-8"),
            ("x-version", "3"),
            ("x-version", "5"),
            ("cookie", "session-id=13"),
        ],
    )
    assert cast(dict[str, Any], repeated.json())["versions"] == [3, 5]
    serialized = client.get(
        "/context",
        headers={
            "x-request-token": "request-9",
            "x-version": "3, 5",
            "cookie": "session-id=14",
        },
    )
    assert cast(dict[str, Any], serialized.json())["versions"] == [3, 5]

    parameters = app.openapi_spec()["paths"]["/context"]["get"]["parameters"]
    assert parameters == [
        {"name": "x-request-token", "in": "header", "required": True, "schema": {"type": "string"}},
        {"name": "session-id", "in": "cookie", "required": True, "schema": {"type": "integer"}},
        {
            "name": "x-version",
            "in": "header",
            "required": True,
            "schema": {"type": "array", "items": {"type": "integer"}},
        },
        {"name": "x-client-version", "in": "header", "required": False, "schema": {"type": "integer"}},
    ]
    assert "422" in app.openapi_spec()["paths"]["/context"]["get"]["responses"]


def test_header_and_cookie_bindings_reject_missing_invalid_and_duplicate_values() -> None:
    app = Flasgo()

    @app.get("/context")
    def context(
        count: Annotated[int, Header(alias="x-count")],
        session: Annotated[str, Cookie()],
    ) -> str:
        return f"{count}:{session}"

    missing = app.test_client().get("/context")
    assert missing.status_code == 422
    missing_payload = cast(dict[str, Any], missing.json())
    assert missing_payload["errors"] == [
        {"location": ["header", "x-count"], "code": "missing", "message": "Field is required."},
        {"location": ["cookie", "session"], "code": "missing", "message": "Field is required."},
    ]

    invalid = app.test_client().get("/context", headers={"x-count": "many", "cookie": "session=ok"})
    assert invalid.status_code == 422
    invalid_payload = cast(dict[str, Any], invalid.json())
    assert cast(list[dict[str, Any]], invalid_payload["errors"])[0]["location"] == ["header", "x-count"]
    assert "many" not in invalid.text

    duplicate_header = app.test_client().get(
        "/context",
        headers=[("x-count", "2"), ("x-count", "3"), ("cookie", "session=ok")],
    )
    assert duplicate_header.status_code == 422
    duplicate_header_payload = cast(dict[str, Any], duplicate_header.json())
    assert duplicate_header_payload["errors"] == [
        {"location": ["header", "x-count"], "code": "multiple_values", "message": "Expected one value."}
    ]

    duplicate_cookie = app.test_client().get(
        "/context",
        headers={"x-count": "2", "cookie": "session=first; session=second"},
    )
    assert duplicate_cookie.status_code == 422
    duplicate_payload = cast(dict[str, Any], duplicate_cookie.json())
    assert duplicate_payload["errors"] == [
        {"location": ["cookie", "session"], "code": "multiple_values", "message": "Expected one cookie value."}
    ]


@pytest.mark.parametrize("name", ["Accept", "Content-Type", "Authorization", "Cookie"])
def test_header_binding_rejects_openapi_reserved_names(name: str) -> None:
    with pytest.raises(ValueError, match="reserved by OpenAPI"):
        Header(alias=name)


def test_parameter_aliases_reject_unsafe_wire_names() -> None:
    for marker in (Header(alias="x-safe"), Cookie(alias="safe-cookie")):
        assert marker.alias is not None
    for factory in (Header, Cookie):
        with pytest.raises(ValueError, match="HTTP token"):
            factory(alias="bad\r\nname")


def test_cookie_binding_rejects_collection_annotations() -> None:
    app = Flasgo()

    with pytest.raises(TypeError, match="must be scalar"):

        @app.get("/cookies")
        def cookies(values: Annotated[list[str], Cookie()]) -> str:
            return str(values)


def test_schema_registry_uses_truthful_fallback_and_heterogeneous_literal_schema() -> None:
    app = Flasgo(settings={"ENABLE_DOCS": True})

    @app.get("/schemas")
    def schemas(value: Annotated[Literal["one", 2], Query()]) -> str:
        return str(value)

    operation = app.openapi_spec()["paths"]["/schemas"]["get"]
    assert operation["parameters"][0]["schema"] == {"enum": ["one", 2]}
    assert SchemaRegistry().schema_for(UnknownAnnotation) == {}


def test_recursive_union_validation_stops_at_the_configured_work_budget() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False, "MAX_VALIDATION_WORK": 40})

    @app.post("/recursive")
    def recursive(payload: Annotated[RecursiveA | RecursiveB, Body()]) -> str:
        return str(payload)

    value: object = "invalid"
    for _ in range(16):
        value = {"child": value}
    response = app.test_client().post("/recursive", json=value)

    assert response.status_code == 422
    payload = cast(dict[str, Any], response.json())
    errors = cast(list[dict[str, Any]], payload["errors"])
    assert len(errors) == 1
    assert errors[0]["code"] == "validation_limit"
    assert errors[0]["message"] == "Request validation exceeded the configured work limit."
    assert cast(list[str], errors[0]["location"])[0] == "body"


def test_validation_issue_responses_are_capped() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False, "MAX_VALIDATION_ISSUES": 5})

    @app.post("/widgets")
    def widget(payload: Annotated[CreateWidget, Body()]) -> str:
        return payload.name

    response = app.test_client().post("/widgets", json={f"unknown-{index}": index for index in range(20)})

    assert response.status_code == 422
    payload = cast(dict[str, Any], response.json())
    errors = cast(list[dict[str, Any]], payload["errors"])
    assert len(errors) == 5
    assert errors[-1] == {
        "location": ["body"],
        "code": "too_many_errors",
        "message": "Additional validation errors were omitted.",
    }
