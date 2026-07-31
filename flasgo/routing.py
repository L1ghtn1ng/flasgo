from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from .response import ResponseValue

Endpoint = Callable[..., ResponseValue | Awaitable[ResponseValue]]
WebSocketEndpoint = Callable[..., Awaitable[None] | None]

_CONVERTERS: dict[str, tuple[str, Callable[[str], Any]]] = {
    "str": (r"[^/]+", str),
    "int": (r"\d+", int),
    "float": (r"\d+(?:\.\d+)?", float),
    "path": (r".+", str),
}

_PARAM_PATTERN = re.compile(r"<(?:(?P<converter>[a-zA-Z_]\w*):)?(?P<name>[a-zA-Z_]\w*)>")


@dataclass(slots=True, frozen=True)
class MatchResult:
    endpoint: Endpoint
    params: dict[str, Any]
    route_path: str
    name: str | None


@dataclass(slots=True, frozen=True)
class WebSocketMatchResult:
    endpoint: WebSocketEndpoint
    params: dict[str, Any]
    route_path: str
    name: str | None


@dataclass(slots=True)
class Route:
    raw_path: str
    methods: frozenset[str]
    endpoint: Endpoint
    name: str | None = None
    _regex: re.Pattern[str] | None = None
    _casts: dict[str, Callable[[str], Any]] | None = None

    def __post_init__(self) -> None:
        _validate_route(self.raw_path, self.name)
        self._regex, self._casts = _compile_path(self.raw_path)

    def match(self, path: str, method: str) -> MatchResult | None:
        if method.upper() not in self.methods:
            return None
        params = _match_path(path, self._regex, self._casts)
        if params is None:
            return None
        return MatchResult(endpoint=self.endpoint, params=params, route_path=self.raw_path, name=self.name)

    def path_matches(self, path: str) -> bool:
        return self._regex is not None and self._regex.fullmatch(path) is not None


@dataclass(slots=True)
class WebSocketRoute:
    raw_path: str
    endpoint: WebSocketEndpoint
    name: str | None = None
    _regex: re.Pattern[str] | None = None
    _casts: dict[str, Callable[[str], Any]] | None = None

    def __post_init__(self) -> None:
        _validate_route(self.raw_path, self.name)
        self._regex, self._casts = _compile_path(self.raw_path)

    def match(self, path: str) -> WebSocketMatchResult | None:
        params = _match_path(path, self._regex, self._casts)
        if params is None:
            return None
        return WebSocketMatchResult(
            endpoint=self.endpoint,
            params=params,
            route_path=self.raw_path,
            name=self.name,
        )


def _validate_route(path: str, name: str | None) -> None:
    if not path.startswith("/"):
        raise ValueError("Route paths must start with '/'.")
    if any(ord(char) < 32 or ord(char) == 127 for char in path):
        raise ValueError("Route paths must not contain control characters.")
    if name is not None and any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise ValueError("Route names must not contain control characters.")


def _compile_path(
    raw_path: str,
) -> tuple[re.Pattern[str], dict[str, Callable[[str], Any]]]:
    regex_chunks: list[str] = ["^"]
    casts: dict[str, Callable[[str], Any]] = {}
    cursor = 0

    for match in _PARAM_PATTERN.finditer(raw_path):
        regex_chunks.append(re.escape(raw_path[cursor : match.start()]))
        cursor = match.end()

        converter = match.group("converter") or "str"
        name = match.group("name")
        if converter not in _CONVERTERS:
            msg = f"Unknown converter '{converter}' in route: {raw_path}"
            raise ValueError(msg)
        pattern, caster = _CONVERTERS[converter]
        regex_chunks.append(f"(?P<{name}>{pattern})")
        casts[name] = caster

    regex_chunks.append(re.escape(raw_path[cursor:]))
    regex_chunks.append("$")
    return re.compile("".join(regex_chunks)), casts


def _match_path(
    path: str,
    regex: re.Pattern[str] | None,
    casts: dict[str, Callable[[str], Any]] | None,
) -> dict[str, Any] | None:
    if regex is None or casts is None:
        return None
    regex_match = regex.fullmatch(path)
    if regex_match is None:
        return None

    params: dict[str, Any] = {}
    for key, raw in regex_match.groupdict().items():
        params[key] = casts[key](raw)
    return params
