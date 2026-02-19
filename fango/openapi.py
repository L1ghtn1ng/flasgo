from __future__ import annotations

import inspect
import re
import types
from collections.abc import Mapping
from typing import Any, Literal, Union, get_args, get_origin

from .response import Response
from .routing import Route

_PARAM_PATTERN = re.compile(r"<(?:(?P<converter>[a-zA-Z_]\w*):)?(?P<name>[a-zA-Z_]\w*)>")


def build_openapi_spec(
    *,
    routes: list[Route],
    title: str,
    version: str,
    description: str = "",
) -> dict[str, Any]:
    paths: dict[str, dict[str, Any]] = {}
    operation_ids: set[str] = set()

    for route in routes:
        openapi_path = _to_openapi_path(route.raw_path)
        route_item = paths.setdefault(openapi_path, {})
        for method in sorted(route.methods):
            method_lower = method.lower()
            if method == "HEAD" and "GET" in route.methods:
                continue
            operation = _build_operation(route, method=method, known_operation_ids=operation_ids)
            route_item[method_lower] = operation

    return {
        "openapi": "3.1.0",
        "info": {
            "title": title,
            "version": version,
            "description": description,
        },
        "paths": paths,
    }


def _build_operation(
    route: Route,
    *,
    method: str,
    known_operation_ids: set[str],
) -> dict[str, Any]:
    signature = inspect.signature(route.endpoint)
    path_params, path_param_names = _path_parameters(route.raw_path)
    query_params = _query_parameters(signature, path_param_names=path_param_names)
    parameters = [*path_params, *query_params]

    operation_id = _operation_id(route, method=method, known_operation_ids=known_operation_ids)
    summary, description = _summary_and_description(route.endpoint.__doc__)
    response_schema = _response_schema(signature.return_annotation)

    operation: dict[str, Any] = {
        "operationId": operation_id,
        "responses": {
            "200": {
                "description": "Successful Response",
                "content": response_schema,
            }
        },
    }
    if parameters:
        operation["parameters"] = parameters
    if summary:
        operation["summary"] = summary
    if description:
        operation["description"] = description
    return operation


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
    summary = lines[0]
    description = "\n".join(lines[1:]) if len(lines) > 1 else None
    return summary, description


def _to_openapi_path(path: str) -> str:
    return _PARAM_PATTERN.sub(lambda match: "{" + match.group("name") + "}", path)


def _path_parameters(path: str) -> tuple[list[dict[str, Any]], set[str]]:
    params: list[dict[str, Any]] = []
    names: set[str] = set()
    for match in _PARAM_PATTERN.finditer(path):
        converter = match.group("converter") or "str"
        name = match.group("name")
        names.add(name)
        params.append(
            {
                "name": name,
                "in": "path",
                "required": True,
                "schema": _converter_schema(converter),
            }
        )
    return params, names


def _converter_schema(converter: str) -> dict[str, Any]:
    if converter == "int":
        return {"type": "integer"}
    if converter == "float":
        return {"type": "number"}
    return {"type": "string"}


def _query_parameters(
    signature: inspect.Signature,
    *,
    path_param_names: set[str],
) -> list[dict[str, Any]]:
    params: list[dict[str, Any]] = []
    for param in signature.parameters.values():
        if param.name in path_param_names or param.name == "request":
            continue
        if param.kind in (inspect.Parameter.VAR_KEYWORD, inspect.Parameter.VAR_POSITIONAL):
            continue
        params.append(
            {
                "name": param.name,
                "in": "query",
                "required": param.default is inspect.Parameter.empty,
                "schema": _annotation_schema(param.annotation),
            }
        )
    return params


def _response_schema(annotation: object) -> dict[str, Any]:
    ann = _strip_response_tuple(annotation)
    if ann is Response:
        return {"text/plain": {"schema": {"type": "string"}}}
    if ann is str:
        return {"text/plain": {"schema": {"type": "string"}}}
    if ann is bytes:
        return {"application/octet-stream": {"schema": {"type": "string", "format": "binary"}}}
    return {"application/json": {"schema": _annotation_schema(ann)}}


def _strip_response_tuple(annotation: object) -> object:
    origin = get_origin(annotation)
    if origin is tuple:
        args = get_args(annotation)
        if args:
            return args[0]
    return annotation


def _annotation_schema(annotation: object) -> dict[str, Any]:
    if annotation in (inspect.Signature.empty, Any, object):
        return {"type": "string"}
    if annotation is str:
        return {"type": "string"}
    if annotation is int:
        return {"type": "integer"}
    if annotation is float:
        return {"type": "number"}
    if annotation is bool:
        return {"type": "boolean"}
    if annotation is bytes:
        return {"type": "string", "format": "binary"}
    if annotation is None:
        return {"type": "null"}

    origin = get_origin(annotation)
    args = get_args(annotation)

    if origin in (list, set, tuple):
        item_schema = _annotation_schema(args[0]) if args else {"type": "string"}
        return {"type": "array", "items": item_schema}
    if origin in (dict, Mapping):
        return {"type": "object"}
    if origin is Literal:
        if not args:
            return {"type": "string"}
        enum_values = list(args)
        schema: dict[str, Any] = {"enum": enum_values}
        if isinstance(enum_values[0], bool):
            schema["type"] = "boolean"
        elif isinstance(enum_values[0], int):
            schema["type"] = "integer"
        elif isinstance(enum_values[0], float):
            schema["type"] = "number"
        else:
            schema["type"] = "string"
        return schema
    if origin in (Union, types.UnionType):
        union_members = [arg for arg in args if arg is not type(None)]
        if len(union_members) == 1:
            schema = _annotation_schema(union_members[0])
            schema["nullable"] = True
            return schema
        return {"anyOf": [_annotation_schema(arg) for arg in union_members]}
    return {"type": "string"}
