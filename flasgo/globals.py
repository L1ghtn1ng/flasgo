from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any, cast

from .app import request as _get_request
from .app import session as _get_session
from .app import user as _get_user
from .response import Response

if TYPE_CHECKING:
    from .auth import User
    from .request import Request
    from .session import Session


class _ContextProxy[T]:
    def __init__(self, getter: Callable[[], T], name: str) -> None:
        self._getter = getter
        self._name = name

    def _current(self) -> T:
        return self._getter()

    def __getattr__(self, item: str) -> Any:
        return getattr(self._current(), item)

    def __getitem__(self, key: Any) -> Any:
        current = cast(Any, self._current())
        return current[key]

    def __setitem__(self, key: Any, value: Any) -> None:
        current = cast(Any, self._current())
        current[key] = value

    def __call__(self) -> Any:
        return self._current()

    def __repr__(self) -> str:
        return f"<{self._name} proxy>"


request: _ContextProxy[Request] = _ContextProxy(_get_request, "request")
session: _ContextProxy[Session] = _ContextProxy(_get_session, "session")
current_user: _ContextProxy[User] = _ContextProxy(_get_user, "current_user")


def jsonify(
    value: Any,
    *,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> Response:
    """Serialize a value to a JSON :class:`Response`."""

    return Response.json(value, status_code=status_code, headers=headers)


def redirect(
    location: str,
    *,
    status_code: int = 302,
    headers: dict[str, str] | None = None,
) -> Response:
    """Return a redirect :class:`Response`."""

    return Response.redirect(location, status_code=status_code, headers=headers)
