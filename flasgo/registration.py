from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from typing import Literal

from .cors import CORSConfig
from .params import Depends
from .routing import Endpoint


class RouteDecorators:
    """Shared HTTP registration API for applications and blueprints."""

    def add_route(
        self,
        path: str,
        endpoint: Endpoint,
        *,
        methods: Iterable[str] = ("GET",),
        name: str | None = None,
        cors: CORSConfig | Literal[False] | None = None,
        response_model: object = None,
        dependencies: Sequence[Depends] = (),
    ) -> None:
        raise NotImplementedError

    def route(
        self,
        path: str,
        *,
        methods: Iterable[str] = ("GET",),
        name: str | None = None,
        cors: CORSConfig | Literal[False] | None = None,
        response_model: object = None,
        dependencies: Sequence[Depends] = (),
    ) -> Callable[[Endpoint], Endpoint]:
        def decorator(func: Endpoint) -> Endpoint:
            self.add_route(
                path,
                func,
                methods=methods,
                name=name,
                cors=cors,
                response_model=response_model,
                dependencies=dependencies,
            )
            return func

        return decorator

    def get(
        self,
        path: str,
        *,
        name: str | None = None,
        cors: CORSConfig | Literal[False] | None = None,
        response_model: object = None,
        dependencies: Sequence[Depends] = (),
    ) -> Callable[[Endpoint], Endpoint]:
        return self.route(
            path,
            methods=("GET",),
            name=name,
            cors=cors,
            response_model=response_model,
            dependencies=dependencies,
        )

    def post(
        self,
        path: str,
        *,
        name: str | None = None,
        cors: CORSConfig | Literal[False] | None = None,
        response_model: object = None,
        dependencies: Sequence[Depends] = (),
    ) -> Callable[[Endpoint], Endpoint]:
        return self.route(
            path,
            methods=("POST",),
            name=name,
            cors=cors,
            response_model=response_model,
            dependencies=dependencies,
        )

    def put(
        self,
        path: str,
        *,
        name: str | None = None,
        cors: CORSConfig | Literal[False] | None = None,
        response_model: object = None,
        dependencies: Sequence[Depends] = (),
    ) -> Callable[[Endpoint], Endpoint]:
        return self.route(
            path,
            methods=("PUT",),
            name=name,
            cors=cors,
            response_model=response_model,
            dependencies=dependencies,
        )

    def patch(
        self,
        path: str,
        *,
        name: str | None = None,
        cors: CORSConfig | Literal[False] | None = None,
        response_model: object = None,
        dependencies: Sequence[Depends] = (),
    ) -> Callable[[Endpoint], Endpoint]:
        return self.route(
            path,
            methods=("PATCH",),
            name=name,
            cors=cors,
            response_model=response_model,
            dependencies=dependencies,
        )

    def delete(
        self,
        path: str,
        *,
        name: str | None = None,
        cors: CORSConfig | Literal[False] | None = None,
        response_model: object = None,
        dependencies: Sequence[Depends] = (),
    ) -> Callable[[Endpoint], Endpoint]:
        return self.route(
            path,
            methods=("DELETE",),
            name=name,
            cors=cors,
            response_model=response_model,
            dependencies=dependencies,
        )
