from __future__ import annotations

import re
from collections.abc import Collection, Iterable, Mapping
from typing import Any, get_args, get_origin

from .auth import HasScope
from .params import EndpointPlan, ParameterBinding, binding_wire_name, walk_bindings
from .ratelimit import endpoint_rate_limits
from .response import Response
from .routing import Route
from .validation import SchemaRegistry, contains_uploaded_file

_PARAM_PATTERN = re.compile(r"<(?:(?P<converter>[a-zA-Z_]\w*):)?(?P<name>[a-zA-Z_]\w*)>")
_FIXED_PATH_ITEM_METHODS = frozenset({"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "QUERY", "TRACE"})


def build_openapi_spec(
    *,
    routes: list[Route],
    route_auth: Mapping[object, object],
    auth_schemes: Mapping[str, dict[str, Any]],
    title: str,
    version: str,
    description: str = "",
    servers: Iterable[str] = (),
    csrf_enabled: bool = False,
    csrf_safe_methods: Collection[str] = ("GET", "HEAD", "OPTIONS", "TRACE"),
) -> dict[str, Any]:
    paths: dict[str, dict[str, Any]] = {}
    operation_ids: set[str] = set()
    registry = SchemaRegistry()
    used_security_schemes: set[str] = set()
    safe_methods = {method.upper() for method in csrf_safe_methods}

    for route in routes:
        openapi_path = _to_openapi_path(route.raw_path)
        route_item = paths.setdefault(openapi_path, {})
        plan = route.endpoint_plan
        for method in sorted(route.methods):
            if method == "HEAD" and "GET" in route.methods:
                continue
            operation, security_name = _build_operation(
                route,
                plan=plan,
                method=method,
                known_operation_ids=operation_ids,
                registry=registry,
                route_auth=route_auth,
                auth_schemes=auth_schemes,
                csrf_enabled=csrf_enabled,
                csrf_safe_methods=safe_methods,
            )
            if method in _FIXED_PATH_ITEM_METHODS:
                route_item[method.lower()] = operation
            else:
                route_item.setdefault("additionalOperations", {})[method] = operation
            if security_name is not None:
                used_security_schemes.add(security_name)

    document: dict[str, Any] = {
        "openapi": "3.2.0",
        "jsonSchemaDialect": "https://json-schema.org/draft/2020-12/schema",
        "info": {"title": title, "version": version, "description": description},
        "paths": paths,
    }
    server_entries = [{"url": url} for url in servers]
    if server_entries:
        document["servers"] = server_entries
    components: dict[str, Any] = {}
    if registry.schemas:
        components["schemas"] = registry.schemas
    if used_security_schemes:
        components["securitySchemes"] = {name: auth_schemes[name] for name in sorted(used_security_schemes)}
    if components:
        document["components"] = components
    return document


def _build_operation(
    route: Route,
    *,
    plan: EndpointPlan,
    method: str,
    known_operation_ids: set[str],
    registry: SchemaRegistry,
    route_auth: Mapping[object, object],
    auth_schemes: Mapping[str, dict[str, Any]],
    csrf_enabled: bool,
    csrf_safe_methods: Collection[str],
) -> tuple[dict[str, Any], str | None]:
    parameters = _path_parameters(route.raw_path)
    bindings = walk_bindings(plan)
    parameters.extend(_bound_parameters(bindings, registry=registry))

    operation_id = _operation_id(route, method=method, known_operation_ids=known_operation_ids)
    summary, description = _summary_and_description(route.endpoint.__doc__)
    operation: dict[str, Any] = {
        "operationId": operation_id,
        "responses": {
            "200": {
                "description": "Successful Response",
                "content": _response_content(plan.return_annotation, registry=registry),
            }
        },
    }
    body_binding = next((item for item in bindings if item.source in {"body", "form"}), None)
    if body_binding is not None:
        operation["requestBody"] = _request_body(body_binding, registry=registry)
        operation["responses"]["413"] = {"description": "Payload Too Large"}
        operation["responses"]["415"] = {"description": "Unsupported Media Type"}
    if parameters:
        operation["parameters"] = parameters
    if any(item.source in {"query", "header", "cookie", "body", "form"} for item in bindings):
        operation["responses"]["422"] = {
            "description": "Request Validation Error",
            "content": {
                "application/json": {
                    "schema": _validation_error_schema(registry),
                }
            },
        }
    if summary:
        operation["summary"] = summary
    if description:
        operation["description"] = description

    if csrf_enabled and method.upper() not in csrf_safe_methods:
        operation["responses"].setdefault("403", {"description": "Forbidden"})
    if endpoint_rate_limits(route.endpoint):
        operation["responses"]["429"] = {"description": "Too Many Requests"}

    security_name: str | None = None
    auth = route_auth.get(route.endpoint)
    backend_name = getattr(auth, "backend", None)
    if isinstance(backend_name, str):
        operation["responses"].setdefault("401", {"description": "Unauthorized"})
        operation["responses"].setdefault("403", {"description": "Forbidden"})
        if backend_name in auth_schemes:
            permissions = getattr(auth, "permissions", ())
            required_scopes = sorted(
                {permission.scope for permission in permissions if isinstance(permission, HasScope)}
            )
            operation["security"] = [{backend_name: required_scopes}]
            security_name = backend_name
    return operation, security_name


def _bound_parameters(
    bindings: tuple[ParameterBinding, ...],
    *,
    registry: SchemaRegistry,
) -> list[dict[str, Any]]:
    parameters: list[dict[str, Any]] = []
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    for binding in bindings:
        if binding.source not in {"query", "header", "cookie"}:
            continue
        name = binding_wire_name(binding)
        identity = (binding.source, name.lower() if binding.source == "header" else name)
        schema = registry.schema_for(binding.annotation)
        existing = seen.get(identity)
        if existing is not None:
            if existing["schema"] != schema:
                raise ValueError(
                    f"OpenAPI has conflicting schemas for duplicate {binding.source} parameter {name!r} "
                    "across the endpoint dependency graph."
                )
            existing["required"] = bool(existing["required"] or binding.required)
            continue
        parameter = {
            "name": name,
            "in": binding.source,
            "required": binding.required,
            "schema": schema,
        }
        seen[identity] = parameter
        parameters.append(parameter)
    return parameters


def _request_body(binding: ParameterBinding, *, registry: SchemaRegistry) -> dict[str, Any]:
    schema = registry.schema_for(binding.annotation, input_model=True)
    if binding.source == "body":
        content = {"application/json": {"schema": schema}}
    else:
        content = {"multipart/form-data": {"schema": schema}}
        if not contains_uploaded_file(binding.annotation):
            content["application/x-www-form-urlencoded"] = {"schema": schema}
    return {"required": binding.required, "content": content}


def _response_content(annotation: object, *, registry: SchemaRegistry) -> dict[str, Any]:
    annotation = _strip_response_tuple(annotation)
    if annotation is Response or annotation is str:
        return {"text/plain": {"schema": {"type": "string"}}}
    if annotation is bytes:
        return {"application/octet-stream": {"schema": {"type": "string", "format": "binary"}}}
    return {"application/json": {"schema": registry.schema_for(annotation)}}


def _validation_error_schema(registry: SchemaRegistry) -> dict[str, Any]:
    name = registry.validation_error_name
    if name is None:
        base = "RequestValidationError"
        name = base
        index = 2
        while name in registry.schemas:
            name = f"{base}{index}"
            index += 1
        registry.validation_error_name = name
    registry.schemas.setdefault(
        name,
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["error", "detail", "errors"],
            "properties": {
                "error": {"type": "string", "const": "validation_error"},
                "detail": {"type": "string"},
                "errors": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["location", "code", "message"],
                        "properties": {
                            "location": {
                                "type": "array",
                                "items": {"anyOf": [{"type": "string"}, {"type": "integer"}]},
                            },
                            "code": {"type": "string"},
                            "message": {"type": "string"},
                        },
                    },
                },
            },
        },
    )
    return {"$ref": f"#/components/schemas/{name}"}


def _operation_id(route: Route, *, method: str, known_operation_ids: set[str]) -> str:
    endpoint_name = getattr(route.endpoint, "__name__", route.endpoint.__class__.__name__)
    base = f"{route.name or endpoint_name}_{method.lower()}"
    candidate = base
    suffix = 1
    while candidate in known_operation_ids:
        suffix += 1
        candidate = f"{base}_{suffix}"
    known_operation_ids.add(candidate)
    return candidate


def _summary_and_description(doc: str | None) -> tuple[str | None, str | None]:
    if doc is None:
        return None, None
    lines = [line.strip() for line in doc.strip().splitlines() if line.strip()]
    if not lines:
        return None, None
    return lines[0], "\n".join(lines[1:]) if len(lines) > 1 else None


def _to_openapi_path(path: str) -> str:
    return _PARAM_PATTERN.sub(lambda match: "{" + match.group("name") + "}", path)


def _path_parameters(path: str) -> list[dict[str, Any]]:
    parameters: list[dict[str, Any]] = []
    for match in _PARAM_PATTERN.finditer(path):
        converter = match.group("converter") or "str"
        schema = (
            {"type": "integer"}
            if converter == "int"
            else {"type": "number"}
            if converter == "float"
            else {"type": "string"}
        )
        parameters.append({"name": match.group("name"), "in": "path", "required": True, "schema": schema})
    return parameters


def _strip_response_tuple(annotation: object) -> object:
    if get_origin(annotation) is tuple:
        args = get_args(annotation)
        if args:
            return args[0]
    return annotation
