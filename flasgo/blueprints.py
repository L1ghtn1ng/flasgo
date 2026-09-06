from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from functools import wraps
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import quote, urlencode

from .auth import PermissionLike
from .cors import CORSConfig
from .params import Depends
from .ratelimit import RateLimitRule, endpoint_rate_limits, rate_limit
from .registration import RouteDecorators
from .routing import _CONVERTERS, _PARAM_PATTERN, Endpoint, _validate_route

if TYPE_CHECKING:
    from .app import Flasgo


@dataclass(frozen=True, slots=True)
class _Registration:
    path: str
    endpoint: Endpoint
    methods: tuple[str, ...]
    name: str
    cors: CORSConfig | Literal[False] | None
    public: bool
    response_model: object
    dependencies: tuple[Depends, ...]


class Blueprint(RouteDecorators):
    """Reusable HTTP routes with additive permissions and dependencies.

    Registration snapshots the blueprint. Register public routes separately from
    protected groups; a child cannot remove its parent's permissions.
    """

    def __init__(
        self,
        name: str,
        *,
        url_prefix: str = "",
        permissions: Sequence[PermissionLike] = (),
        backend: str = "default",
        dependencies: Sequence[Depends] = (),
        rate_limits: Sequence[RateLimitRule] = (),
        cors: CORSConfig | Literal[False] | None = None,
    ) -> None:
        """
        Initialize a reusable group of HTTP routes with shared configuration.

        Parameters:
                name (str): A valid Python identifier used to name the blueprint.
                url_prefix (str): A literal path prefix applied to the blueprint's routes.
                permissions (Sequence[PermissionLike]): Permissions inherited by routes in the blueprint.
                backend (str): Authentication backend used for protected routes.
                dependencies (Sequence[Depends]): Dependencies inherited by routes in the blueprint.
                rate_limits (Sequence[RateLimitRule]): Rate-limit rules inherited by routes in the blueprint.
                cors (CORSConfig | Literal[False] | None): CORS configuration inherited by routes, or `False` to disable inherited
                    CORS.
        """
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ValueError("Blueprint names must be Python identifiers without dots.")
        if url_prefix:
            _validate_route(url_prefix, None)
            if url_prefix.endswith("/") or "<" in url_prefix or "?" in url_prefix or "#" in url_prefix:
                raise ValueError("Blueprint prefixes must be literal paths without a trailing slash, query or fragment.")
        if not backend.strip():
            raise ValueError("Blueprint backend must not be empty.")
        if cors is not None and cors is not False and not isinstance(cors, CORSConfig):
            raise TypeError("Blueprint cors must be a CORSConfig, False, or None.")
        if not all(isinstance(item, Depends) for item in dependencies):
            raise TypeError("Blueprint dependencies must be Depends instances.")
        if not all(isinstance(item, RateLimitRule) for item in rate_limits):
            raise TypeError("Blueprint rate_limits must be RateLimitRule instances.")
        self.name = name
        self.url_prefix = url_prefix
        self.permissions = tuple(permissions)
        self.backend = backend.strip()
        self.dependencies = tuple(dependencies)
        self.rate_limits = tuple(rate_limits)
        self.cors: CORSConfig | Literal[False] | None = cors
        self._registrations: list[_Registration | Blueprint] = []

    def add_route(
        self,
        path: str,
        endpoint: Endpoint,
        *,
        methods: Iterable[str] = ("GET",),
        name: str | None = None,
        cors: CORSConfig | Literal[False] | None = None,
        public: bool = False,
        response_model: object = None,
        dependencies: Sequence[Depends] = (),
    ) -> None:
        """
        Register an endpoint route with the blueprint.

        Parameters:
            path (str): The route path.
            endpoint (Endpoint): The callable that handles the route.
            methods (Iterable[str]): HTTP methods accepted by the route.
            name (str | None): The route name; required when the endpoint has no name.
            cors (CORSConfig | Literal[False] | None): Route-specific CORS configuration.
            public (bool): Whether the route is publicly accessible.
            response_model (object): The model used to describe or validate responses.
            dependencies (Sequence[Depends]): Dependencies applied to the route.
        """
        _validate_route(path, name)
        endpoint_name = name or getattr(endpoint, "__name__", "")
        if not endpoint_name:
            raise ValueError("Blueprint callable objects require an explicit route name.")
        self._registrations.append(
            _Registration(
                path,
                endpoint,
                tuple(methods),
                endpoint_name,
                cors,
                public,
                response_model,
                tuple(dependencies),
            )
        )

    def register_blueprint(self, blueprint: Blueprint) -> None:
        """
        Register a nested blueprint.

        Parameters:
                blueprint (Blueprint): The blueprint to register.
        """
        if not isinstance(blueprint, Blueprint):
            raise TypeError("Expected a Blueprint.")
        if blueprint._contains(self):
            raise ValueError("Blueprint registration must not contain cycles.")
        self._registrations.append(blueprint)

    def _contains(self, target: Blueprint) -> bool:
        """Determine whether this blueprint contains the target blueprint, directly or through nested registrations.

        Parameters:
                target (Blueprint): The blueprint to search for.

        Returns:
                bool: `true` if the target is this blueprint or a nested blueprint, `false` otherwise.
        """
        return self is target or any(item._contains(target) for item in self._registrations if isinstance(item, Blueprint))

    def _register(
        self,
        app: Flasgo,
        *,
        prefix: str = "",
        namespace: str = "",
        permissions: tuple[PermissionLike, ...] = (),
        backend: str | None = None,
        dependencies: tuple[Depends, ...] = (),
        rate_limits: tuple[RateLimitRule, ...] = (),
        cors: CORSConfig | Literal[False] | None = None,
    ) -> None:
        """
        Register this blueprint and its nested blueprints with an application.

        Parameters:
                app (Flasgo): The application receiving the routes.
                prefix (str): URL prefix inherited from parent blueprints.
                namespace (str): Route-name namespace inherited from parent blueprints.
                permissions (tuple[PermissionLike, ...]): Permissions inherited from parent blueprints.
                backend (str | None): Authentication backend inherited from parent blueprints.
                dependencies (tuple[Depends, ...]): Dependencies inherited from parent blueprints.
                rate_limits (tuple[RateLimitRule, ...]): Rate-limit rules inherited from parent blueprints.
                cors (CORSConfig | Literal[False] | None): CORS configuration inherited from parent blueprints.
        """
        if permissions and self.permissions and backend != self.backend:
            raise ValueError("Nested protected blueprints must use the same authentication backend.")
        backend = backend if permissions else self.backend
        permissions = (*permissions, *self.permissions)
        dependencies = (*dependencies, *self.dependencies)
        rate_limits = (*rate_limits, *self.rate_limits)
        cors = self.cors if self.cors is not None else cors
        prefix += self.url_prefix
        namespace += self.name + "."
        for item in self._registrations:
            if isinstance(item, Blueprint):
                item._register(
                    app,
                    prefix=prefix,
                    namespace=namespace,
                    permissions=permissions,
                    backend=backend,
                    dependencies=dependencies,
                    rate_limits=rate_limits,
                    cors=cors,
                )
                continue
            endpoint = _copy_endpoint(item.endpoint)
            original_auth = app._route_auth.get(item.endpoint)
            effective_permissions = permissions
            effective_backend = backend
            if original_auth is not None:
                if permissions and original_auth.backend != backend:
                    raise ValueError("A protected blueprint route cannot change its authentication backend.")
                effective_permissions = (*permissions, *original_auth.permissions)
                effective_backend = original_auth.backend
            if item.public and effective_permissions:
                raise ValueError("A protected blueprint route cannot declare public=True.")
            if effective_permissions:
                app.authorize(*effective_permissions, backend=effective_backend or "default")(endpoint)
            for rule in (*endpoint_rate_limits(item.endpoint), *rate_limits):
                rate_limit(rule.requests, per=rule.window_seconds, scope=rule.scope, key_func=rule.key_func)(endpoint)
            app.add_route(
                prefix + item.path,
                endpoint,
                methods=item.methods,
                name=namespace + item.name,
                cors=item.cors if item.cors is not None else cors,
                public=item.public,
                response_model=item.response_model,
                dependencies=(*dependencies, *item.dependencies),
            )


def _copy_endpoint(endpoint: Endpoint) -> Endpoint:
    """
    Create a callable wrapper that preserves an endpoint's metadata while forwarding keyword arguments to it.

    Parameters:
        endpoint (Endpoint): The endpoint to wrap.

    Returns:
        Endpoint: A wrapped endpoint retaining the original endpoint's metadata.
    """

    @wraps(endpoint, updated=())
    def registered(**kwargs: Any) -> Any:
        return endpoint(**kwargs)

    return registered


def build_url(path: str, values: dict[str, Any]) -> str:
    """
    Build a safe relative URL by substituting validated route parameters and encoding remaining values as query parameters.

    Parameters:
        path (str): Route path containing optional parameter placeholders.
        values (dict[str, Any]): Values for route parameters and query parameters.

    Returns:
        str: The resulting relative URL.

    Raises:
        ValueError: If a required parameter is missing, invalid, or unsafe, or if the resulting URL is not a safe relative URL.
    """
    values = dict(values)

    def substitute(match: re.Match[str]) -> str:
        """
        Substitute a validated URL parameter in a route path.

        Parameters:
            match (re.Match[str]): The matched route parameter.

        Returns:
            str: The URL-encoded parameter value.

        Raises:
            ValueError: If the parameter is missing, invalid, or contains unsafe path components.
        """
        name = match.group("name")
        if name not in values:
            raise ValueError(f"Missing URL parameter: {name}")
        value = values.pop(name)
        converter = match.group("converter") or "str"
        text = str(value)
        pattern, cast = _CONVERTERS[converter]
        if not re.fullmatch(pattern, text):
            raise ValueError(f"Invalid URL parameter: {name}")
        cast(text)
        if any(part in {".", ".."} for part in text.split("/")) or "\\" in text:
            raise ValueError(f"Unsafe URL parameter: {name}")
        return quote(text, safe="/" if converter == "path" else "")

    result = _PARAM_PATTERN.sub(substitute, path)
    if result.startswith("//") or "\\" in result or "?" in result or "#" in result:
        raise ValueError("Route cannot be reversed to a safe relative URL.")
    return result + ("?" + urlencode(values, doseq=True) if values else "")
