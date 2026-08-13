from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Protocol
from urllib.parse import urlsplit

from .types import Send

if TYPE_CHECKING:
    from collections.abc import Sequence

    from .background import BackgroundTasks
    from .templating import JinjaTemplates

Headers = Mapping[str, str]
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


class DataclassResponse(Protocol):
    """Structural response type implemented by standard-library dataclasses."""

    __dataclass_fields__: ClassVar[dict[str, Any]]


@dataclass(slots=True)
class Response:
    """HTTP response container used by Flasgo handlers and middleware.

    Prefer :meth:`set_cookie`/:meth:`delete_cookie` for cookies. The raw ``cookies``
    list accepts complete ``Set-Cookie`` strings and is intended for trusted,
    developer-built values only; never interpolate request data into it.
    """

    body: bytes
    status_code: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[str] = field(default_factory=list)
    content_type: str = "text/plain; charset=utf-8"
    allow_public_cache: bool = False
    background: BackgroundTasks | None = None

    def __post_init__(self) -> None:
        self.headers = {key.lower(): value for key, value in self.headers.items()}
        self.headers.setdefault("content-type", self.content_type)
        self.prepare()

    def prepare(self) -> None:
        if not 100 <= self.status_code <= 599:
            raise ValueError("HTTP response status codes must be between 100 and 599.")
        self.headers["content-length"] = str(len(self.body))
        for key, value in self.headers.items():
            _validate_header(key, value)
        for cookie in self.cookies:
            _validate_set_cookie(cookie)

    async def send(self, send: Send, *, head_only: bool = False) -> None:
        self.prepare()
        raw_headers = [(key.encode("latin-1"), value.encode("latin-1")) for key, value in self.headers.items()]
        raw_headers.extend((b"set-cookie", cookie.encode("latin-1")) for cookie in self.cookies)
        await send(
            {
                "type": "http.response.start",
                "status": self.status_code,
                "headers": raw_headers,
            }
        )
        body = b"" if head_only else self.body
        await send({"type": "http.response.body", "body": body, "more_body": False})

    @classmethod
    def text(
        cls,
        value: str,
        *,
        status_code: int = 200,
        headers: Headers | None = None,
        background: BackgroundTasks | None = None,
    ) -> Response:
        return cls(
            body=value.encode("utf-8"),
            status_code=status_code,
            headers=dict(headers or {}),
            content_type="text/plain; charset=utf-8",
            background=background,
        )

    @classmethod
    def html(
        cls,
        value: str,
        *,
        status_code: int = 200,
        headers: Headers | None = None,
        background: BackgroundTasks | None = None,
    ) -> Response:
        return cls(
            body=value.encode("utf-8"),
            status_code=status_code,
            headers=dict(headers or {}),
            content_type="text/html; charset=utf-8",
            background=background,
        )

    @classmethod
    def template(
        cls,
        template_name: str,
        *,
        templates: JinjaTemplates | None = None,
        template_dirs: str | Path | Sequence[str | Path] | None = None,
        context: Mapping[str, Any] | None = None,
        status_code: int = 200,
        headers: Headers | None = None,
        background: BackgroundTasks | None = None,
    ) -> Response:
        from .templating import JinjaTemplates

        if templates is None:
            if template_dirs is None:
                raise ValueError("templates or template_dirs must be provided.")
            templates = JinjaTemplates(template_dirs)
        return cls.html(
            templates.render(template_name, context),
            status_code=status_code,
            headers=headers,
            background=background,
        )

    @classmethod
    def json(
        cls,
        value: Any,
        *,
        status_code: int = 200,
        headers: Headers | None = None,
        background: BackgroundTasks | None = None,
    ) -> Response:
        payload = json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
        return cls(
            body=payload,
            status_code=status_code,
            headers=dict(headers or {}),
            content_type="application/json",
            background=background,
        )

    @classmethod
    def redirect(
        cls,
        location: str,
        *,
        status_code: int = 302,
        headers: Headers | None = None,
        background: BackgroundTasks | None = None,
    ) -> Response:
        """Return a redirect response for ``location``.

        The target is not validated beyond header safety. Never pass
        request-controlled input (for example a ``next`` query parameter)
        without checking it first; see :func:`is_safe_redirect_target`.
        """

        response_headers = {"location": location}
        if headers:
            response_headers.update(headers)
        return cls(
            body=b"",
            status_code=status_code,
            headers=response_headers,
            content_type="text/plain; charset=utf-8",
            background=background,
        )

    def set_cookie(
        self,
        name: str,
        value: str,
        *,
        max_age: int | None = None,
        secure: bool = True,
        http_only: bool = True,
        same_site: str = "Lax",
        path: str = "/",
    ) -> None:
        """Append a validated ``Set-Cookie`` header built with :func:`build_set_cookie`."""

        from .security import build_set_cookie

        self.cookies.append(
            build_set_cookie(
                name,
                value,
                max_age=max_age,
                secure=secure,
                http_only=http_only,
                same_site=same_site,
                path=path,
            )
        )

    def delete_cookie(
        self,
        name: str,
        *,
        secure: bool = True,
        http_only: bool = True,
        same_site: str = "Lax",
        path: str = "/",
    ) -> None:
        """Append an expired cookie so the client removes ``name``."""

        self.set_cookie(name, "", max_age=0, secure=secure, http_only=http_only, same_site=same_site, path=path)

    def add_task(self, func: Callable[..., Any], /, *args: Any, **kwargs: Any) -> None:
        if self.background is None:
            from .background import BackgroundTasks

            self.background = BackgroundTasks()
        self.background.add_task(func, *args, **kwargs)


ResponseValue = Response | DataclassResponse | str | bytes | Mapping[str, Any] | list[Any] | tuple[Any, ...] | None


def to_response(value: ResponseValue) -> Response:
    """Normalize supported handler return values into a :class:`Response`."""

    if isinstance(value, Response):
        return value
    if value is None:
        return Response(
            body=b"",
            status_code=204,
            headers={},
            content_type="text/plain; charset=utf-8",
        )
    if isinstance(value, bytes):
        return Response(body=value)
    if isinstance(value, str):
        return Response.text(value)
    if isinstance(value, Mapping):
        return Response.json(dict(value))
    if isinstance(value, list):
        return Response.json(value)
    if isinstance(value, tuple):
        if len(value) == 2:
            body, status_code = value
            return _tuple_to_response(body, status_code, None)
        if len(value) == 3:
            body, status_code, headers = value
            return _tuple_to_response(body, status_code, headers)
    from dataclasses import is_dataclass

    if is_dataclass(value) and not isinstance(value, type):
        from .validation import to_jsonable

        return Response.json(to_jsonable(value))
    msg = (
        f"Unsupported response type: {type(value)!r}. "
        "Return a Response, str, bytes, mapping, list, or a (body, status[, headers]) tuple."
    )
    raise TypeError(msg)


def _tuple_to_response(
    body: Any,
    status_code: object,
    headers: object | None,
) -> Response:
    response = to_response(body if body is not None else b"")
    if not isinstance(status_code, int | str):
        raise TypeError("Response tuple status must be an integer status code.")
    response.status_code = int(status_code)
    if headers is not None and not isinstance(headers, Mapping):
        raise TypeError("Response tuple headers must be a mapping of string names to string values.")
    if headers:
        if not all(isinstance(key, str) and isinstance(value, str) for key, value in headers.items()):
            raise TypeError("Response tuple headers must be a mapping of string names to string values.")
        response.headers.update({str(key).lower(): str(value) for key, value in headers.items()})
        for key, value in response.headers.items():
            _validate_header(key, value)
    response.headers["content-length"] = str(len(response.body))
    return response


def _validate_header(name: str, value: str) -> None:
    if not _HEADER_NAME_RE.fullmatch(name):
        msg = f"Invalid header name: {name!r}"
        raise ValueError(msg)
    if any(char in name for char in ("\r", "\n", "\x00")):
        msg = f"Invalid header name: {name!r}"
        raise ValueError(msg)
    if any(char in value for char in ("\r", "\n", "\x00")):
        msg = f"Invalid header value for {name!r}"
        raise ValueError(msg)
    try:
        name.encode("ascii")
        value.encode("latin-1")
    except UnicodeEncodeError as exc:
        raise ValueError(f"HTTP header {name!r} is not Latin-1 encodable.") from exc


def _validate_set_cookie(value: str) -> None:
    if any(char in value for char in ("\r", "\n", "\x00")):
        msg = "Invalid Set-Cookie value."
        raise ValueError(msg)
    try:
        value.encode("latin-1")
    except UnicodeEncodeError as exc:
        raise ValueError("Set-Cookie values must be Latin-1 encodable.") from exc


def is_safe_redirect_target(location: str) -> bool:
    """Return whether ``location`` is a relative, same-origin redirect target.

    Accepts paths such as ``/dashboard`` or ``?page=2`` and rejects malformed or
    absolute URLs, scheme-relative URLs (``//host``), browser-normalized backslash
    authority forms, non-HTTP schemes (``javascript:``), and control characters.
    Use it before passing request-controlled input (such as a ``next`` parameter)
    to :func:`redirect`/:meth:`Response.redirect`.
    """

    if not location or any(ord(char) < 0x20 or ord(char) == 0x7F for char in location):
        return False
    normalized = location.replace("\\", "/")
    try:
        parts = urlsplit(normalized)
    except ValueError:
        return False
    return not parts.scheme and not parts.netloc and not normalized.startswith("//")
