from __future__ import annotations

from collections.abc import Callable, Iterator
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
    """Module-level stand-in that forwards every operation to the object bound to the current request."""

    __slots__ = ("_getter", "_name")

    def __init__(self, getter: Callable[[], T], name: str) -> None:
        object.__setattr__(self, "_getter", getter)
        object.__setattr__(self, "_name", name)

    def _current(self) -> T:
        return self._getter()

    def __getattr__(self, item: str) -> Any:
        if item.startswith("__") and item.endswith("__"):
            # Protocol probes (copy, pickle, dir) must not require an active request context.
            raise AttributeError(item)
        return getattr(self._current(), item)

    def __setattr__(self, item: str, value: Any) -> None:
        # Writes must reach the request-bound object; storing them on the shared proxy would leak across requests.
        setattr(self._current(), item, value)

    def __delattr__(self, item: str) -> None:
        delattr(self._current(), item)

    def __contains__(self, key: object) -> bool:
        return key in cast(Any, self._current())

    def __iter__(self) -> Iterator[Any]:
        return iter(cast(Any, self._current()))

    def __len__(self) -> int:
        return len(cast(Any, self._current()))

    def __bool__(self) -> bool:
        return bool(self._current())

    def __delitem__(self, key: Any) -> None:
        current = cast(Any, self._current())
        del current[key]

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
    """
    Create a redirect response for the specified location.

    Parameters:
        location (str): The redirect target.
        status_code (int): The HTTP status code for the redirect.
        headers (dict[str, str] | None): Optional response headers.

    Returns:
        Response: A redirect response targeting `location`.
    """

    return Response.redirect(location, status_code=status_code, headers=headers)


def url_for(endpoint: str, **values: Any) -> str:
    """
    Build a relative URL for an application endpoint.

    Parameters:
        endpoint (str): The endpoint name.
        values (Any): Values used to construct the URL.

    Returns:
        str: The generated relative URL.
    """
    return _get_request().scope["flasgo.app"].url_for(endpoint, **values)
