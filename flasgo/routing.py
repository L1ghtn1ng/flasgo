from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .response import ResponseValue

if TYPE_CHECKING:
    from .cors import CORSConfig
    from .params import EndpointPlan

Endpoint = Callable[..., ResponseValue | Awaitable[ResponseValue]]
WebSocketEndpoint = Callable[..., Awaitable[None] | None]

_CONVERTERS: dict[str, tuple[str, Callable[[str], Any]]] = {
    "str": (r"[^/]+", str),
    "int": (r"[0-9]+", int),
    "float": (r"[0-9]+(?:\.[0-9]+)?", float),
    "path": (r".+", str),
}

_PARAM_PATTERN = re.compile(r"<(?:(?P<converter>[a-zA-Z_]\w*):)?(?P<name>[a-zA-Z_]\w*)>")
_CONVERTER_SPECIFICITY = {"path": 0, "str": 1, "float": 2, "int": 3}


@dataclass(slots=True, frozen=True)
class MatchResult:
    endpoint: Endpoint
    endpoint_plan: EndpointPlan
    params: dict[str, Any]
    route_path: str
    name: str | None
    cors: CORSConfig | None
    methods: frozenset[str]
    response_model: object = None


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
    endpoint_plan: EndpointPlan
    name: str | None = None
    cors: CORSConfig | None = None
    public: bool = False
    response_model: object = None
    _regex: re.Pattern[str] | None = None
    _casts: dict[str, Callable[[str], Any]] | None = None

    def __post_init__(self) -> None:
        _validate_route(self.raw_path, self.name)
        self._regex, self._casts = _compile_path(self.raw_path)

    @property
    def shape(self) -> str:
        """Return the route language without parameter names."""
        return _route_shape(self.raw_path)

    @property
    def contract_shape(self) -> str:
        """Return the OpenAPI route shape without converter or parameter names."""
        return _route_contract_shape(self.raw_path)

    @property
    def parameter_names(self) -> tuple[str, ...]:
        """Return path parameter names in declaration order."""
        return _route_parameter_names(self.raw_path)

    @property
    def specificity(self) -> tuple[int, int, int]:
        """Return a stable route precedence key, with literals and narrow converters first."""
        return _route_specificity(self.raw_path)

    def match(self, path: str, method: str) -> MatchResult | None:
        """
        Match an HTTP request path and method to this route.

        Parameters:
            path (str): The request path to match.
            method (str): The HTTP method to match.

        Returns:
            MatchResult | None: Route metadata and converted path parameters when matched; `None` otherwise.
        """
        if method.upper() not in self.methods:
            return None
        params = _match_path(path, self._regex, self._casts)
        if params is None:
            return None
        return MatchResult(
            endpoint=self.endpoint,
            endpoint_plan=self.endpoint_plan,
            params=params,
            route_path=self.raw_path,
            name=self.name,
            cors=self.cors,
            methods=self.methods,
            response_model=self.response_model,
        )

    def path_matches(self, path: str) -> bool:
        # Cast-aware: a value the converter cannot cast (for example an integer above
        # the interpreter digit limit) does not match the route at all.
        """Determine whether a path matches the route and its parameter converters.

        Parameters:
                path (str): The path to check.

        Returns:
                bool: `True` if the path matches and all parameters can be converted, `False` otherwise.
        """
        return _match_path(path, self._regex, self._casts) is not None


@dataclass(slots=True)
class WebSocketRoute:
    raw_path: str
    endpoint: WebSocketEndpoint
    name: str | None = None
    public: bool = False
    _regex: re.Pattern[str] | None = None
    _casts: dict[str, Callable[[str], Any]] | None = None

    def __post_init__(self) -> None:
        _validate_route(self.raw_path, self.name)
        self._regex, self._casts = _compile_path(self.raw_path)

    @property
    def shape(self) -> str:
        """Return the route language without parameter names."""
        return _route_shape(self.raw_path)

    @property
    def contract_shape(self) -> str:
        """Return the route shape without converter or parameter names."""
        return _route_contract_shape(self.raw_path)

    @property
    def specificity(self) -> tuple[int, int, int]:
        """Return a stable route precedence key, with literals and narrow converters first."""
        return _route_specificity(self.raw_path)

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
    """Reject malformed route metadata and multiple greedy path converters."""
    if not path.startswith("/"):
        raise ValueError("Route paths must start with '/'.")
    if any(ord(char) < 32 or ord(char) == 127 for char in path):
        raise ValueError("Route paths must not contain control characters.")
    if name is not None and any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise ValueError("Route names must not contain control characters.")
    path_converters = [match for match in _PARAM_PATTERN.finditer(path) if (match.group("converter") or "str") == "path"]
    if len(path_converters) > 1:
        raise ValueError("A route may contain at most one path converter.")


def _route_shape(path: str) -> str:
    """Normalize parameter names while preserving each converter's route language."""
    return _PARAM_PATTERN.sub(lambda match: f"<{match.group('converter') or 'str'}>", path)


def _route_contract_shape(path: str) -> str:
    """Normalize all parameter declarations to one contract placeholder."""
    return _PARAM_PATTERN.sub("<>", path)


def _route_parameter_names(path: str) -> tuple[str, ...]:
    """Return parameter names in declaration order."""
    return tuple(match.group("name") for match in _PARAM_PATTERN.finditer(path))


def _route_specificity(path: str) -> tuple[int, int, int]:
    """Rank routes so literal and narrower converter matches take precedence."""
    matches = list(_PARAM_PATTERN.finditer(path))
    literal_characters = len(_PARAM_PATTERN.sub("", path))
    converter_score = sum(_CONVERTER_SPECIFICITY.get(match.group("converter") or "str", 0) for match in matches)
    return literal_characters, converter_score, -len(matches)


def routes_overlap(left: str, right: str) -> bool:
    """Check language intersection without executing potentially expensive route regexes.

    Literal characters, digits, slash, newline, and one other character form a
    complete alphabet for the built-in converters. Product-state traversal is
    bounded by the product of the two route automata sizes.
    """
    alphabet = frozenset(left + right + "0123456789/\n\x00")
    first = _route_automaton(left, alphabet)
    second = _route_automaton(right, alphabet)
    pending = [(0, 0)]
    visited = {(0, 0)}
    while pending:
        a, b = pending.pop()
        if a == len(first) - 1 and b == len(second) - 1:
            return True
        successors = [(target, b) for chars, target in first[a] if chars is None]
        successors.extend((a, target) for chars, target in second[b] if chars is None)
        successors.extend(
            (target_a, target_b)
            for chars_a, target_a in first[a]
            for chars_b, target_b in second[b]
            if chars_a is not None and chars_b is not None and chars_a & chars_b
        )
        for state in successors:
            if state not in visited:
                visited.add(state)
                pending.append(state)
    return False


def _route_automaton(path: str, alphabet: frozenset[str]) -> list[list[tuple[frozenset[str] | None, int]]]:
    """Compile literals and the four built-in converters into a small NFA."""
    edges: list[list[tuple[frozenset[str] | None, int]]] = [[]]

    def append(chars: frozenset[str], *, repeat: bool = False) -> None:
        """Append a character transition, optionally repeating at its destination state."""
        target = len(edges)
        edges[-1].append((chars, target))
        edges.append([(chars, target)] if repeat else [])

    def literal(value: str) -> None:
        """Append one exact transition for each literal character."""
        for char in value:
            append(frozenset(char))

    digits = frozenset("0123456789")
    cursor = 0
    for match in _PARAM_PATTERN.finditer(path):
        literal(path[cursor : match.start()])
        converter = match.group("converter") or "str"
        if converter in {"int", "float"}:
            append(digits, repeat=True)
            if converter == "float":
                integer_end = len(edges) - 1
                append(frozenset("."))
                append(digits, repeat=True)
                edges[integer_end].append((None, len(edges) - 1))
        else:
            append(alphabet - ({"/"} if converter == "str" else {"\n"}), repeat=True)
        cursor = match.end()
    literal(path[cursor:])
    return edges


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
        try:
            params[key] = casts[key](raw)
        except ValueError, TypeError:
            # A cast failure (for example an integer above the interpreter digit
            # limit) means the value is not a valid match, not a server error.
            return None
    return params
