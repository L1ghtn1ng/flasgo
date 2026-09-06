from __future__ import annotations

import inspect
import types
from collections.abc import Mapping
from dataclasses import MISSING, fields, is_dataclass
from datetime import date, datetime
from enum import Enum
from typing import Annotated, Any, Literal, Union, get_args, get_origin
from uuid import UUID

from .params import _contains_forward_ref
from .request import Request
from .response import Response, ResponseValue, to_response
from .validation import (
    RequestValidationError,
    ValidationBudget,
    _model_hints,
    to_jsonable,
    validate_value,
)


class ResponseValidationError(Exception):
    """Application output did not satisfy its declared public response contract."""

    def __init__(self) -> None:
        super().__init__("Response does not satisfy the declared response model.")


def validate_response_model(model: object, *, _seen: set[type[Any]] | None = None) -> None:
    if _contains_forward_ref(model) or isinstance(model, str):
        raise TypeError("Response models must use resolved Python types.")
    if get_origin(model) is Annotated:
        validate_response_model(get_args(model)[0], _seen=_seen)
        return
    if is_dataclass(model) and isinstance(model, type):
        seen = _seen if _seen is not None else set()
        if model in seen:
            return
        seen.add(model)
        hints = _model_hints(model)
        for field in fields(model):
            if not field.name.startswith("_"):
                validate_response_model(hints.get(field.name, field.type), _seen=seen)
        return
    if model in {
        Any,
        object,
        str,
        int,
        float,
        bool,
        dict,
        list,
        tuple,
        set,
        frozenset,
        None,
        type(None),
        date,
        datetime,
        UUID,
    }:
        return
    if isinstance(model, type) and issubclass(model, Enum):
        for member in model:
            validate_response_model(type(member.value), _seen=_seen)
        return
    origin = get_origin(model)
    if origin is Literal:
        for value in get_args(model):
            validate_response_model(type(value), _seen=_seen)
        return
    if origin in {list, tuple, set, frozenset, dict, Mapping, Union, types.UnionType}:
        for member in get_args(model):
            if member is not Ellipsis:
                validate_response_model(member, _seen=_seen)
        return
    raise TypeError("Unsupported response model; use JSON types or a dataclass.")


def response_budget(request: Request) -> ValidationBudget:
    return ValidationBudget(
        max_depth=request.scope["max_validation_depth"],
        max_work=request.scope["max_validation_work"],
        max_issues=request.scope["max_validation_issues"],
    )


def project_response(model: object, value: object, budget: ValidationBudget) -> Any:
    try:
        return _project(model, value, budget, 0)
    except Exception as exc:
        raise ResponseValidationError() from exc


def contract_response(value: ResponseValue, model: object, request: Request) -> Response:
    if isinstance(value, Response):
        raise ResponseValidationError()
    body = value
    status = 200
    headers = None
    if isinstance(value, tuple) and len(value) in {2, 3}:
        body, status = value[:2]
        headers = value[2] if len(value) == 3 else None
    payload = project_response(model, body, response_budget(request))
    response = Response.json(payload)
    return to_response((response, status, headers))


def _project(model: object, value: object, budget: ValidationBudget, depth: int) -> Any:
    budget.consume(location=("response",), depth=depth)
    if get_origin(model) is Annotated:
        model = get_args(model)[0]
    if is_dataclass(model) and isinstance(model, type):
        if not isinstance(value, Mapping) and not (is_dataclass(value) and not isinstance(value, type)):
            raise ResponseValidationError()
        hints = _model_hints(model)
        result = {}
        for field in fields(model):
            if field.name.startswith("_"):
                continue
            field_value = (
                value.get(field.name, MISSING) if isinstance(value, Mapping) else getattr(value, field.name, MISSING)
            )
            if field_value is MISSING:
                if field.default is not MISSING:
                    field_value = field.default
                elif field.default_factory is not MISSING:
                    field_value = field.default_factory()
                else:
                    raise ResponseValidationError()
            result[field.name] = _project(hints.get(field.name, field.type), field_value, budget, depth + 1)
        return result
    origin = get_origin(model)
    args = get_args(model)
    if origin in {Union, types.UnionType}:
        for member in args:
            try:
                return _project(member, value, budget, depth + 1)
            except RequestValidationError as exc:
                if any(issue.code == "validation_limit" for issue in exc.issues):
                    raise
            except ResponseValidationError:
                pass
        raise ResponseValidationError()
    if origin in {list, tuple, set, frozenset} or model in {list, tuple, set, frozenset}:
        if not isinstance(value, list | tuple | set | frozenset):
            raise ResponseValidationError()
        if origin is tuple and args and args[-1] is not Ellipsis:
            if len(value) != len(args):
                raise ResponseValidationError()
            return [_project(item_type, item, budget, depth + 1) for item_type, item in zip(args, value, strict=True)]
        member = args[0] if args else Any
        return [_project(member, item, budget, depth + 1) for item in value]
    if origin in {dict, Mapping} or model is dict:
        if not isinstance(value, Mapping):
            raise ResponseValidationError()
        key_type, item_type = args if args else (str, Any)
        result = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ResponseValidationError()
            validate_value(key_type, key, location=("response",), budget=budget)
            result[key] = _project(item_type, item, budget, depth + 1)
        return result
    if model in {Any, object, inspect.Signature.empty}:
        if is_dataclass(value) and not isinstance(value, type):
            return _project(type(value), value, budget, depth + 1)
        if isinstance(value, Mapping):
            return _project(dict[str, Any], value, budget, depth + 1)
        if isinstance(value, list | tuple | set | frozenset):
            return _project(list[Any], value, budget, depth + 1)
        if isinstance(value, Enum):
            return _project(Any, value.value, budget, depth + 1)
        if value is None or isinstance(value, str | bool | int | float):
            model = type(value)
        else:
            raise ResponseValidationError()
    return to_jsonable(validate_value(model, value, location=("response",), budget=budget))
