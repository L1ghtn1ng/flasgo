from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from .response import ResponseValue

Endpoint = Callable[..., ResponseValue | Awaitable[ResponseValue]]

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


@dataclass(slots=True)
class Route:
    raw_path: str
    methods: frozenset[str]
    endpoint: Endpoint
    name: str | None = None
    _regex: re.Pattern[str] | None = None
    _casts: dict[str, Callable[[str], Any]] | None = None

    def __post_init__(self) -> None:
        regex_chunks: list[str] = ["^"]
        casts: dict[str, Callable[[str], Any]] = {}
        cursor = 0

        for match in _PARAM_PATTERN.finditer(self.raw_path):
            regex_chunks.append(re.escape(self.raw_path[cursor : match.start()]))
            cursor = match.end()

            converter = match.group("converter") or "str"
            name = match.group("name")
            if converter not in _CONVERTERS:
                msg = f"Unknown converter '{converter}' in route: {self.raw_path}"
                raise ValueError(msg)
            pattern, caster = _CONVERTERS[converter]
            regex_chunks.append(f"(?P<{name}>{pattern})")
            casts[name] = caster

        regex_chunks.append(re.escape(self.raw_path[cursor:]))
        regex_chunks.append("$")

        self._regex = re.compile("".join(regex_chunks))
        self._casts = casts

    def match(self, path: str, method: str) -> MatchResult | None:
        if method.upper() not in self.methods:
            return None
        if self._regex is None or self._casts is None:
            return None

        regex_match = self._regex.match(path)
        if regex_match is None:
            return None

        params: dict[str, Any] = {}
        for key, raw in regex_match.groupdict().items():
            params[key] = self._casts[key](raw)
        return MatchResult(endpoint=self.endpoint, params=params)

    def path_matches(self, path: str) -> bool:
        if self._regex is None:
            return False
        return self._regex.match(path) is not None
