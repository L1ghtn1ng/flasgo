from __future__ import annotations

import inspect
from collections.abc import Mapping, Sequence
from contextlib import AsyncExitStack, asynccontextmanager, contextmanager
from types import TracebackType
from typing import Any

from .params import (
    Cookie,
    Depends,
    EndpointPlan,
    Header,
    ParameterBinding,
    Provider,
    _validate_dependency_scopes,
    binding_wire_name,
    compile_endpoint_plan,
)
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


class _DependencyStack(AsyncExitStack):
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        if await super().__aexit__(exc_type, exc, traceback):
            raise RuntimeError("Dependency providers must not suppress application exceptions.")
        return False


class DependencyContext:
    """Own request resources and a snapshot of context-local testing overrides."""

    def __init__(self, overrides: Mapping[Provider, Provider] | None = None) -> None:
        self.function_stack = _DependencyStack()
        self.request_stack = _DependencyStack()
        self.overrides = dict(overrides or {})
        self.resolving: set[tuple[int, str]] = set()

    async def enter(self, result: Any, marker: Depends) -> Any:
        stack = self.function_stack if marker.scope == "function" else self.request_stack
        if inspect.isasyncgen(result):
            return await stack.enter_async_context(asynccontextmanager(lambda: result)())
        if inspect.isgenerator(result):
            return stack.enter_context(contextmanager(lambda: result)())
        return await result if inspect.isawaitable(result) else result

    async def close_request(self, exc: BaseException | None = None) -> None:
        await self.request_stack.__aexit__(type(exc) if exc else None, exc, exc.__traceback__ if exc else None)


async def resolve_endpoint_arguments(
    plan: EndpointPlan,
    request: Request,
    path_params: dict[str, Any],
) -> dict[str, Any]:
    cache: dict[tuple[int, str], object] = {}
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
    cache: dict[tuple[int, str], object],
    body_cache: dict[str, object],
    budget: ValidationBudget,
) -> dict[str, Any]:
    resolved: dict[str, Any] = {}
    issues: list[ValidationIssue] = []
    for index, binding in enumerate((*plan.dependencies, *plan.bindings)):
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
                context = request.scope.get("flasgo.dependencies")
                if not isinstance(context, DependencyContext):
                    raise RuntimeError(
                        "Dependency resolution requires a DependencyContext in request.scope['flasgo.dependencies']."
                    )
                provider = context.overrides.get(marker.provider, marker.provider)
                cache_key = (id(marker.provider), marker.scope)
                if marker.use_cache and cache_key in cache:
                    value = cache[cache_key]
                else:
                    if cache_key in context.resolving:
                        raise RuntimeError("Dependency override introduces a cycle.")
                    context.resolving.add(cache_key)
                    try:
                        dependency = binding.dependency
                        if provider is not marker.provider:
                            dependency = compile_endpoint_plan(
                                provider, request.scope.get("route_template", request.path)
                            )
                        _validate_dependency_scopes(dependency, parent_scope=marker.scope)
                        arguments = await _resolve_plan(
                            dependency,
                            request=request,
                            path_params=path_params,
                            cache=cache,
                            body_cache=body_cache,
                            budget=budget,
                        )
                        result = provider(**arguments)
                        value = await context.enter(result, marker)
                        if marker.use_cache:
                            cache[cache_key] = value
                    finally:
                        context.resolving.remove(cache_key)
                value = validate_value(
                    binding.annotation,
                    value,
                    location=("dependency", binding.name),
                    budget=budget,
                )
            else:
                raise RuntimeError(f"Unknown endpoint binding source: {binding.source}")
            if index >= len(plan.dependencies):
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
