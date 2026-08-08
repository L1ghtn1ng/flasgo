from __future__ import annotations

import inspect
import re
from annotationlib import Format, ForwardRef
from collections.abc import Callable
from dataclasses import dataclass, is_dataclass
from typing import Annotated, Any, get_args, get_origin, get_type_hints

from .request import Request
from .routing import Endpoint

type Provider = Callable[..., Any]

_PATH_PARAM_PATTERN = re.compile(r"<(?:(?:[a-zA-Z_]\w*):)?(?P<name>[a-zA-Z_]\w*)>")
_WIRE_NAME_PATTERN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_RESERVED_OPENAPI_HEADERS = frozenset({"accept", "authorization", "content-type", "cookie"})


@dataclass(frozen=True, slots=True)
class Body:
    """Inject and validate one JSON request body."""


@dataclass(frozen=True, slots=True)
class Query:
    """Inject and validate one query-string value."""

    alias: str | None = None

    def __post_init__(self) -> None:
        if self.alias is not None and not self.alias:
            raise ValueError("Query aliases must not be empty.")


@dataclass(frozen=True, slots=True)
class Header:
    """Inject and validate one HTTP request header."""

    alias: str | None = None

    def __post_init__(self) -> None:
        if self.alias is not None:
            _validate_wire_name(self.alias, kind="Header")
            _reject_reserved_header(self.alias)


@dataclass(frozen=True, slots=True)
class Cookie:
    """Inject and validate one HTTP request cookie."""

    alias: str | None = None

    def __post_init__(self) -> None:
        if self.alias is not None:
            _validate_wire_name(self.alias, kind="Cookie")


@dataclass(frozen=True, slots=True)
class Form:
    """Inject and validate one URL-encoded or multipart form body."""


@dataclass(frozen=True, slots=True)
class Depends:
    """Resolve a callable dependency for one request."""

    provider: Provider
    use_cache: bool = True


type ParameterMarker = Body | Query | Header | Cookie | Form | Depends


@dataclass(frozen=True, slots=True)
class ParameterBinding:
    name: str
    annotation: object
    source: str
    default: object
    marker: ParameterMarker | None = None
    dependency: EndpointPlan | None = None

    @property
    def required(self) -> bool:
        return self.default is inspect.Parameter.empty


@dataclass(frozen=True, slots=True)
class EndpointPlan:
    endpoint: Provider
    bindings: tuple[ParameterBinding, ...]
    return_annotation: object = inspect.Signature.empty


def compile_endpoint_plan(endpoint: Endpoint, route_path: str) -> EndpointPlan:
    """Compile one endpoint and its dependency graph into a stable binding plan."""

    path_names = {match.group("name") for match in _PATH_PARAM_PATTERN.finditer(route_path)}
    plan = _compile_callable(endpoint, path_names=path_names, stack=())
    body_sources = _body_sources(plan, seen=set())
    if len(body_sources) > 1:
        endpoint_name = _callable_name(endpoint)
        raise TypeError(
            f"Endpoint {endpoint_name!r} declares multiple Body()/Form() inputs across its dependency graph. "
            "Use one request-body model and pass its value to dependencies explicitly."
        )
    return plan


def _compile_callable(
    endpoint: Provider,
    *,
    path_names: set[str],
    stack: tuple[Provider, ...],
) -> EndpointPlan:
    if any(endpoint is item for item in stack):
        chain = " -> ".join(getattr(item, "__name__", repr(item)) for item in (*stack, endpoint))
        raise TypeError(f"Dependency cycle detected: {chain}")

    signature = inspect.signature(endpoint)
    try:
        hints = get_type_hints(endpoint, include_extras=True)
    except (NameError, TypeError) as exc:
        try:
            hints = get_type_hints(endpoint, include_extras=True, format=Format.FORWARDREF)
        except (NameError, TypeError) as fallback_exc:
            raise TypeError(f"Could not resolve annotations for {_callable_name(endpoint)!r}: {fallback_exc}") from exc

    bindings: list[ParameterBinding] = []
    for parameter in signature.parameters.values():
        if parameter.kind in {inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.VAR_POSITIONAL}:
            raise TypeError(
                f"Endpoint parameter {parameter.name!r} on {_callable_name(endpoint)!r} must be keyword-compatible."
            )
        if parameter.kind is inspect.Parameter.VAR_KEYWORD:
            continue
        if isinstance(parameter.default, (Body, Query, Header, Cookie, Form, Depends)):
            raise TypeError(
                f"Parameter {parameter.name!r} on {_callable_name(endpoint)!r} uses a marker as its default. "
                "Use Annotated[T, Marker()] so static type checking remains correct."
            )

        annotation = hints.get(parameter.name, parameter.annotation)
        annotation, marker = _split_marker(annotation, endpoint=endpoint, parameter=parameter.name)
        if marker is not None and _contains_forward_ref(annotation):
            raise TypeError(
                f"Could not resolve the marked annotation for parameter {parameter.name!r} "
                f"on {_callable_name(endpoint)!r}."
            )
        default = parameter.default

        if parameter.name in path_names:
            if marker is not None:
                raise TypeError(f"Path parameter {parameter.name!r} cannot also use {type(marker).__name__}().")
            bindings.append(ParameterBinding(parameter.name, annotation, "path", default))
            continue
        if annotation is Request and marker is not None:
            raise TypeError(f"Request parameter {parameter.name!r} cannot use {type(marker).__name__}().")
        if (annotation is Request or parameter.name == "request") and marker is None:
            bindings.append(ParameterBinding(parameter.name, Request, "request", default))
            continue
        if isinstance(marker, Depends):
            dependency = _compile_callable(marker.provider, path_names=path_names, stack=(*stack, endpoint))
            bindings.append(
                ParameterBinding(
                    parameter.name,
                    annotation,
                    "dependency",
                    default,
                    marker=marker,
                    dependency=dependency,
                )
            )
            continue
        if isinstance(marker, Body):
            bindings.append(ParameterBinding(parameter.name, annotation, "body", default, marker=marker))
            continue
        if isinstance(marker, Header):
            name = marker.alias or parameter.name.replace("_", "-")
            _validate_wire_name(name, kind="Header")
            _reject_reserved_header(name)
            bindings.append(ParameterBinding(parameter.name, annotation, "header", default, marker=marker))
            continue
        if isinstance(marker, Cookie):
            name = marker.alias or parameter.name
            _validate_wire_name(name, kind="Cookie")
            if _contains_collection(annotation):
                raise TypeError(
                    f"Cookie parameter {parameter.name!r} on {_callable_name(endpoint)!r} must be scalar. "
                    "Duplicate cookie names are rejected as ambiguous."
                )
            bindings.append(ParameterBinding(parameter.name, annotation, "cookie", default, marker=marker))
            continue
        if isinstance(marker, Form):
            if not is_dataclass(annotation) or not isinstance(annotation, type):
                raise TypeError(
                    f"Form parameter {parameter.name!r} on {_callable_name(endpoint)!r} must use a dataclass model."
                )
            bindings.append(ParameterBinding(parameter.name, annotation, "form", default, marker=marker))
            continue

        query = marker if isinstance(marker, Query) else Query()
        bindings.append(ParameterBinding(parameter.name, annotation, "query", default, marker=query))

    return EndpointPlan(
        endpoint=endpoint,
        bindings=tuple(bindings),
        return_annotation=hints.get("return", signature.return_annotation),
    )


def _split_marker(annotation: object, *, endpoint: Provider, parameter: str) -> tuple[object, ParameterMarker | None]:
    if get_origin(annotation) is not Annotated:
        return annotation, None
    args = get_args(annotation)
    markers = [item for item in args[1:] if isinstance(item, (Body, Query, Header, Cookie, Form, Depends))]
    if len(markers) > 1:
        raise TypeError(f"Parameter {parameter!r} on {_callable_name(endpoint)!r} has more than one Flasgo marker.")
    return args[0], markers[0] if markers else None


def _contains_forward_ref(annotation: object) -> bool:
    return isinstance(annotation, ForwardRef) or any(_contains_forward_ref(item) for item in get_args(annotation))


def _body_sources(plan: EndpointPlan, *, seen: set[int]) -> set[tuple[int, str, str]]:
    endpoint_id = id(plan.endpoint)
    if endpoint_id in seen:
        return set()
    seen.add(endpoint_id)
    sources: set[tuple[int, str, str]] = set()
    for binding in plan.bindings:
        if binding.source in {"body", "form"}:
            sources.add((endpoint_id, binding.source, binding.name))
        elif binding.dependency is not None:
            sources.update(_body_sources(binding.dependency, seen=seen))
    return sources


def walk_bindings(plan: EndpointPlan) -> tuple[ParameterBinding, ...]:
    """Return all unique bindings in an endpoint dependency graph."""

    collected: list[ParameterBinding] = []
    seen: set[int] = set()

    def visit(current: EndpointPlan) -> None:
        endpoint_id = id(current.endpoint)
        if endpoint_id in seen:
            return
        seen.add(endpoint_id)
        for binding in current.bindings:
            collected.append(binding)
            if binding.dependency is not None:
                visit(binding.dependency)

    visit(plan)
    return tuple(collected)


def _callable_name(value: Provider) -> str:
    return str(getattr(value, "__name__", value.__class__.__name__))


def binding_wire_name(binding: ParameterBinding) -> str:
    """Return the external name used by a query, header, or cookie binding."""

    marker = binding.marker
    if isinstance(marker, Query | Cookie):
        return marker.alias or binding.name
    if isinstance(marker, Header):
        return marker.alias or binding.name.replace("_", "-")
    return binding.name


def _validate_wire_name(value: str, *, kind: str) -> None:
    if not value or not _WIRE_NAME_PATTERN.fullmatch(value):
        raise ValueError(f"{kind} aliases must be non-empty HTTP token names without whitespace or separators.")


def _reject_reserved_header(value: str) -> None:
    if value.lower() not in _RESERVED_OPENAPI_HEADERS:
        return
    raise ValueError(
        f"Header name {value!r} is reserved by OpenAPI. Use request negotiation, Body()/Form(), "
        "an authentication backend, or Cookie() instead."
    )


def _contains_collection(annotation: object) -> bool:
    origin = get_origin(annotation)
    if origin in {list, set, tuple}:
        return True
    return any(_contains_collection(item) for item in get_args(annotation))
