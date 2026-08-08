from __future__ import annotations

import inspect
from collections.abc import Sequence
from typing import Any

from .params import Cookie, Depends, EndpointPlan, Header, ParameterBinding, binding_wire_name
from .request import Request
from .validation import (
    FormValidationError,
    RequestValidationError,
    ValidationBudget,
    ValidationIssue,
    extend_validation_issues,
    is_collection_annotation,
    validate_form_model,
    validate_text_values,
    validate_value,
)


async def resolve_endpoint_arguments(
    plan: EndpointPlan,
    request: Request,
    path_params: dict[str, Any],
) -> dict[str, Any]:
    cache: dict[int, object] = {}
    body_cache: dict[str, object] = {}
    budget = ValidationBudget(
        max_depth=_scope_limit(request, "max_validation_depth", 64),
        max_work=_scope_limit(request, "max_validation_work", 10_000),
        max_issues=_scope_limit(request, "max_validation_issues", 100),
    )
    return await _resolve_plan(
        plan,
        request=request,
        path_params=path_params,
        cache=cache,
        body_cache=body_cache,
        budget=budget,
    )


async def _resolve_plan(
    plan: EndpointPlan,
    *,
    request: Request,
    path_params: dict[str, Any],
    cache: dict[int, object],
    body_cache: dict[str, object],
    budget: ValidationBudget,
) -> dict[str, Any]:
    resolved: dict[str, Any] = {}
    issues: list[ValidationIssue] = []
    for binding in plan.bindings:
        try:
            if binding.source == "request":
                value = request
            elif binding.source == "path":
                value = validate_value(
                    binding.annotation,
                    path_params[binding.name],
                    location=("path", binding.name),
                    budget=budget,
                )
            elif binding.source == "query":
                key = binding_wire_name(binding)
                values = request.query_params.get(key, [])
                if not values:
                    if not binding.required:
                        value = binding.default
                    else:
                        raise RequestValidationError(
                            (ValidationIssue(("query", key), "missing", "Field is required."),)
                        )
                else:
                    value = validate_text_values(binding.annotation, values, location=("query", key), budget=budget)
            elif binding.source == "header":
                marker = binding.marker
                assert isinstance(marker, Header)
                key = binding_wire_name(binding)
                values = request.header_values(key)
                if is_collection_annotation(binding.annotation):
                    values = tuple(item.strip(" \t") for value in values for item in value.split(","))
                value = _resolve_text_binding(binding, values, location=("header", key), budget=budget)
            elif binding.source == "cookie":
                marker = binding.marker
                assert isinstance(marker, Cookie)
                key = binding_wire_name(binding)
                values = request.cookie_values(key)
                if len(values) > 1:
                    raise RequestValidationError(
                        (ValidationIssue(("cookie", key), "multiple_values", "Expected one cookie value."),)
                    )
                value = _resolve_text_binding(binding, values, location=("cookie", key), budget=budget)
            elif binding.source == "body":
                value = await _resolve_body(binding, request, body_cache, budget)
            elif binding.source == "form":
                value = await _resolve_form(binding, request, body_cache, budget)
            elif binding.source == "dependency" and binding.dependency is not None:
                marker = binding.marker
                assert isinstance(marker, Depends)
                cache_key = id(marker.provider)
                if marker.use_cache and cache_key in cache:
                    value = cache[cache_key]
                else:
                    arguments = await _resolve_plan(
                        binding.dependency,
                        request=request,
                        path_params=path_params,
                        cache=cache,
                        body_cache=body_cache,
                        budget=budget,
                    )
                    result = marker.provider(**arguments)
                    value = await result if inspect.isawaitable(result) else result
                    if marker.use_cache:
                        cache[cache_key] = value
                value = validate_value(
                    binding.annotation,
                    value,
                    location=("dependency", binding.name),
                    budget=budget,
                )
            else:
                raise RuntimeError(f"Unknown endpoint binding source: {binding.source}")
            resolved[binding.name] = value
        except FormValidationError:
            raise
        except RequestValidationError as exc:
            if any(issue.code == "validation_limit" for issue in exc.issues):
                raise
            extend_validation_issues(issues, exc.issues, location=("request",), budget=budget)
            if issues[-1].code == "too_many_errors":
                break
    if issues:
        raise RequestValidationError(issues)
    return resolved


def _resolve_text_binding(
    binding: ParameterBinding,
    values: Sequence[str],
    *,
    location: tuple[str, str],
    budget: ValidationBudget,
) -> object:
    if not values:
        if not binding.required:
            return binding.default
        raise RequestValidationError((ValidationIssue(location, "missing", "Field is required."),))
    return validate_text_values(binding.annotation, values, location=location, budget=budget)


async def _resolve_body(
    binding: ParameterBinding,
    request: Request,
    cache: dict[str, object],
    budget: ValidationBudget,
) -> object:
    if "body" in cache:
        return cache["body"]
    if not await request.body():
        if not binding.required:
            return binding.default
        raise RequestValidationError((ValidationIssue(("body",), "missing", "Request body is required."),))
    content_type = request.content_type
    if content_type != "application/json" and not content_type.endswith("+json"):
        from .exceptions import HTTPException

        raise HTTPException(415, "Body() requires Content-Type: application/json.")
    payload = await request.json()
    value = validate_value(binding.annotation, payload, location=("body",), budget=budget)
    cache["body"] = value
    return value


async def _resolve_form(
    binding: ParameterBinding,
    request: Request,
    cache: dict[str, object],
    budget: ValidationBudget,
) -> object:
    if "form" in cache:
        return cache["form"]
    if not await request.body():
        if not binding.required:
            return binding.default
        from .request import FormData

        raise FormValidationError(
            (ValidationIssue(("form",), "missing", "Form data is required."),),
            FormData(),
        )
    if request.content_type not in {"application/x-www-form-urlencoded", "multipart/form-data"}:
        from .exceptions import HTTPException

        raise HTTPException(415, "Form() requires URL-encoded or multipart form data.")
    form = await request.form()
    value = validate_form_model(binding.annotation, form, budget=budget)
    cache["form"] = value
    return value


def _scope_limit(request: Request, name: str, default: int) -> int:
    value = request.scope.get(name)
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else default
