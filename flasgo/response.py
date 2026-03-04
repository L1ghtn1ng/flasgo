from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .types import Send

if TYPE_CHECKING:
    from collections.abc import Sequence

    from .templating import JinjaTemplates

Headers = Mapping[str, str]
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


@dataclass(slots=True)
class Response:
    """HTTP response container used by Flasgo handlers and middleware."""

    body: bytes
    status_code: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[str] = field(default_factory=list)
    content_type: str = "text/plain; charset=utf-8"
    allow_public_cache: bool = False

    def __post_init__(self) -> None:
        self.headers = {key.lower(): value for key, value in self.headers.items()}
        self.headers.setdefault("content-type", self.content_type)
        self.headers.setdefault("content-length", str(len(self.body)))
        for key, value in self.headers.items():
            _validate_header(key, value)
        for cookie in self.cookies:
            _validate_set_cookie(cookie)

    async def send(self, send: Send, *, head_only: bool = False) -> None:
        for key, value in self.headers.items():
            _validate_header(key, value)
        for cookie in self.cookies:
            _validate_set_cookie(cookie)
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
    ) -> Response:
        return cls(
            body=value.encode("utf-8"),
            status_code=status_code,
            headers=dict(headers or {}),
            content_type="text/plain; charset=utf-8",
        )

    @classmethod
    def html(
        cls,
        value: str,
        *,
        status_code: int = 200,
        headers: Headers | None = None,
    ) -> Response:
        return cls(
            body=value.encode("utf-8"),
            status_code=status_code,
            headers=dict(headers or {}),
            content_type="text/html; charset=utf-8",
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
        )

    @classmethod
    def json(
        cls,
        value: Any,
        *,
        status_code: int = 200,
        headers: Headers | None = None,
    ) -> Response:
        payload = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return cls(
            body=payload,
            status_code=status_code,
            headers=dict(headers or {}),
            content_type="application/json",
        )

    @classmethod
    def redirect(
        cls,
        location: str,
        *,
        status_code: int = 302,
        headers: Headers | None = None,
    ) -> Response:
        response_headers = {"location": location}
        if headers:
            response_headers.update(headers)
        return cls(
            body=b"",
            status_code=status_code,
            headers=response_headers,
            content_type="text/plain; charset=utf-8",
        )


ResponseValue = Response | str | bytes | Mapping[str, Any] | list[Any] | tuple[Any, ...] | None


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
    msg = (
        f"Unsupported response type: {type(value)!r}. "
        "Return a Response, str, bytes, mapping, list, or a (body, status[, headers]) tuple."
    )
    raise TypeError(msg)


def _tuple_to_response(
    body: Any,
    status_code: int,
    headers: Headers | None,
) -> Response:
    response = to_response(body if body is not None else b"")
    response.status_code = int(status_code)
    if headers:
        response.headers.update({key.lower(): val for key, val in headers.items()})
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


def _validate_set_cookie(value: str) -> None:
    if any(char in value for char in ("\r", "\n", "\x00")):
        msg = "Invalid Set-Cookie value."
        raise ValueError(msg)
