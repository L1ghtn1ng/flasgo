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
        public: bool = False,
        response_model: object = None,
        dependencies: Sequence[Depends] = (),
    ) -> None:
        """
        Register an HTTP endpoint with the configured application or blueprint.
        
        Parameters:
            path: The URL path for the endpoint.
            endpoint: The callable that handles matching requests.
            methods: HTTP methods accepted by the endpoint.
            name: Optional name assigned to the route.
            cors: CORS configuration, or `False` to disable CORS.
            public: Whether the endpoint is accessible without authentication.
            response_model: Optional model used to describe or validate responses.
            dependencies: Dependencies applied to the endpoint.
        
        Raises:
            NotImplementedError: When the method has not been implemented by a subclass.
        """
        raise NotImplementedError

    def route(
        self,
        path: str,
        *,
        methods: Iterable[str] = ("GET",),
        name: str | None = None,
        cors: CORSConfig | Literal[False] | None = None,
        public: bool = False,
        response_model: object = None,
        dependencies: Sequence[Depends] = (),
    ) -> Callable[[Endpoint], Endpoint]:
        """
        Create a decorator that registers an endpoint for the specified route.
        
        Parameters:
        	path (str): URL path for the route
        	methods (Iterable[str]): HTTP methods accepted by the route
        	name (str | None): Optional route name
        	cors (CORSConfig | Literal[False] | None): CORS configuration, or `False` to disable CORS
        	public (bool): Whether the route is publicly accessible
        	response_model (object): Optional model used to describe or validate the response
        	dependencies (Sequence[Depends]): Dependencies applied to the route
        
        Returns:
        	Callable[[Endpoint], Endpoint]: A decorator that registers an endpoint and returns it unchanged
        """
        def decorator(func: Endpoint) -> Endpoint:
            self.add_route(
                path,
                func,
                methods=methods,
                name=name,
                cors=cors,
                public=public,
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
        public: bool = False,
        response_model: object = None,
        dependencies: Sequence[Depends] = (),
    ) -> Callable[[Endpoint], Endpoint]:
        """
        Create a decorator that registers an endpoint for HTTP GET requests.
        
        Parameters:
            path (str): URL path for the route.
            name (str | None): Optional route name.
            cors (CORSConfig | Literal[False] | None): CORS configuration for the route.
            public (bool): Whether the route is publicly accessible.
            response_model (object): Optional model used to serialize responses.
            dependencies (Sequence[Depends]): Dependencies applied to the route.
        
        Returns:
            Callable[[Endpoint], Endpoint]: A decorator for registering the endpoint.
        """
        return self.route(
            path,
            methods=("GET",),
            name=name,
            cors=cors,
            public=public,
            response_model=response_model,
            dependencies=dependencies,
        )

    def post(
        self,
        path: str,
        *,
        name: str | None = None,
        cors: CORSConfig | Literal[False] | None = None,
        public: bool = False,
        response_model: object = None,
        dependencies: Sequence[Depends] = (),
    ) -> Callable[[Endpoint], Endpoint]:
        """
        Create a decorator that registers an endpoint for POST requests.
        
        Parameters:
            path (str): The URL path for the endpoint.
            name (str | None): An optional route name.
            cors (CORSConfig | Literal[False] | None): CORS configuration for the route.
            public (bool): Whether the route is publicly accessible.
            response_model (object): The model used to serialize the response.
            dependencies (Sequence[Depends]): Dependencies required by the route.
        
        Returns:
            Callable[[Endpoint], Endpoint]: A decorator that registers the endpoint and returns it.
        """
        return self.route(
            path,
            methods=("POST",),
            name=name,
            cors=cors,
            public=public,
            response_model=response_model,
            dependencies=dependencies,
        )

    def put(
        self,
        path: str,
        *,
        name: str | None = None,
        cors: CORSConfig | Literal[False] | None = None,
        public: bool = False,
        response_model: object = None,
        dependencies: Sequence[Depends] = (),
    ) -> Callable[[Endpoint], Endpoint]:
        """
        Create a decorator that registers an endpoint for a PUT route.
        
        Parameters:
            path (str): The route path.
            name (str | None): The optional route name.
            cors (CORSConfig | Literal[False] | None): The CORS configuration, or `False` to disable CORS.
            public (bool): Whether the route is publicly accessible.
            response_model (object): The model used to serialize the response.
            dependencies (Sequence[Depends]): Dependencies applied to the route.
        
        Returns:
            Callable[[Endpoint], Endpoint]: A decorator that registers an endpoint for the PUT route.
        """
        return self.route(
            path,
            methods=("PUT",),
            name=name,
            cors=cors,
            public=public,
            response_model=response_model,
            dependencies=dependencies,
        )

    def patch(
        self,
        path: str,
        *,
        name: str | None = None,
        cors: CORSConfig | Literal[False] | None = None,
        public: bool = False,
        response_model: object = None,
        dependencies: Sequence[Depends] = (),
    ) -> Callable[[Endpoint], Endpoint]:
        """
        Create a decorator that registers an endpoint for PATCH requests.
        
        Parameters:
            path (str): URL path for the endpoint.
            name (str | None): Optional route name.
            cors (CORSConfig | Literal[False] | None): CORS configuration for the route.
            public (bool): Whether the route is publicly accessible.
            response_model (object): Optional response model.
            dependencies (Sequence[Depends]): Dependencies applied to the route.
        
        Returns:
            Callable[[Endpoint], Endpoint]: A decorator that registers and returns the endpoint.
        """
        return self.route(
            path,
            methods=("PATCH",),
            name=name,
            cors=cors,
            public=public,
            response_model=response_model,
            dependencies=dependencies,
        )

    def delete(
        self,
        path: str,
        *,
        name: str | None = None,
        cors: CORSConfig | Literal[False] | None = None,
        public: bool = False,
        response_model: object = None,
        dependencies: Sequence[Depends] = (),
    ) -> Callable[[Endpoint], Endpoint]:
        """
        Create a decorator that registers an endpoint for DELETE requests.
        
        Parameters:
        	path (str): URL path for the route.
        	name (str | None): Optional route name.
        	cors (CORSConfig | Literal[False] | None): CORS configuration for the route.
        	public (bool): Whether the route is publicly accessible.
        	response_model (object): Optional model used to describe or validate responses.
        	dependencies (Sequence[Depends]): Dependencies applied to the route.
        
        Returns:
        	Callable[[Endpoint], Endpoint]: A decorator that registers and returns the endpoint.
        """
        return self.route(
            path,
            methods=("DELETE",),
            name=name,
            cors=cors,
            public=public,
            response_model=response_model,
            dependencies=dependencies,
        )
