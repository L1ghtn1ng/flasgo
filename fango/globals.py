from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .app import request as _get_request
from .app import session as _get_session
from .app import user as _get_user
from .response import Response


class _ContextProxy:
    def __init__(self, getter: Callable[[], Any], name: str) -> None:
        self._getter = getter
        self._name = name

    def _current(self) -> Any:
        return self._getter()

    def __getattr__(self, item: str) -> Any:
        return getattr(self._current(), item)

    def __getitem__(self, key: Any) -> Any:
        return self._current()[key]

    def __setitem__(self, key: Any, value: Any) -> None:
        self._current()[key] = value

    def __call__(self) -> Any:
        return self._current()

    def __repr__(self) -> str:
        return f"<{self._name} proxy>"


request = _ContextProxy(_get_request, "request")
session = _ContextProxy(_get_session, "session")
current_user = _ContextProxy(_get_user, "current_user")


def jsonify(
    value: Any,
    *,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> Response:
    return Response.json(value, status_code=status_code, headers=headers)
