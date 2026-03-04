from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from email.parser import BytesParser
from email.policy import default
from typing import TYPE_CHECKING, Any, overload
from urllib.parse import parse_qs

from .exceptions import HTTPException
from .types import Receive, Scope

if TYPE_CHECKING:
    from .auth import User
    from .session import Session


def _decode_headers(raw_headers: list[tuple[bytes, bytes]]) -> dict[str, str]:
    return {key.decode("latin-1").lower(): value.decode("latin-1") for key, value in raw_headers}


def _parse_cookies(cookie_header: str | None) -> dict[str, str]:
    if not cookie_header:
        return {}
    cookies: dict[str, str] = {}
    for chunk in cookie_header.split(";"):
        item = chunk.strip()
        if not item or "=" not in item:
            continue
        key, value = item.split("=", 1)
        cookies[key.strip()] = value.strip()
    return cookies


def _parse_content_type(header_value: str | None) -> tuple[str, dict[str, str]]:
    if not header_value:
        return "", {}
    message = BytesParser(policy=default).parsebytes(f"Content-Type: {header_value}\r\n\r\n".encode("latin-1"))
    content_type = message.get_content_type().lower()
    params = {
        key.lower(): value
        for key, value in message.get_params(header="content-type", failobj=[])
        if key.lower() != content_type
    }
    params.pop("", None)
    return content_type, params


@dataclass(slots=True, frozen=True)
class UploadedFile:
    """Uploaded file parsed from a multipart form request."""

    name: str
    filename: str
    body: bytes
    content_type: str | None = None
    headers: Mapping[str, str] = field(default_factory=dict)

    @property
    def size(self) -> int:
        return len(self.body)

    def text(self, encoding: str = "utf-8") -> str:
        return self.body.decode(encoding)


class FormData(Mapping[str, str]):
    """Form fields and uploaded files parsed from a request body."""

    def __init__(
        self,
        fields: Mapping[str, list[str]] | None = None,
        files: Mapping[str, list[UploadedFile]] | None = None,
    ) -> None:
        self._fields = {key: list(values) for key, values in (fields or {}).items()}
        self._files = {key: list(values) for key, values in (files or {}).items()}

    def __getitem__(self, key: str) -> str:
        values = self._fields.get(key)
        if not values:
            raise KeyError(key)
        return values[0]

    def __iter__(self) -> Iterator[str]:
        return iter(self._fields)

    def __len__(self) -> int:
        return len(self._fields)

    @overload
    def get(self, key: str, /) -> str | None: ...

    @overload
    def get(self, key: str, /, default: str) -> str: ...

    @overload
    def get(self, key: str, /, default: None) -> str | None: ...

    @overload
    def get(self, key: str, /, default: object) -> str | object: ...

    def get(self, key: str, /, default: object = None) -> str | object:
        values = self._fields.get(key)
        if not values:
            return default
        return values[0]

    def getlist(self, key: str) -> list[str]:
        return list(self._fields.get(key, []))

    def file(self, key: str) -> UploadedFile | None:
        files = self._files.get(key)
        if not files:
            return None
        return files[0]

    def filelist(self, key: str) -> list[UploadedFile]:
        return list(self._files.get(key, []))

    @property
    def files(self) -> dict[str, tuple[UploadedFile, ...]]:
        return {key: tuple(values) for key, values in self._files.items()}


def _decode_form_value(payload: bytes, *, charset: str, error_detail: str) -> str:
    try:
        return payload.decode(charset)
    except (LookupError, UnicodeDecodeError) as exc:
        raise HTTPException(400, error_detail) from exc


def _parse_multipart_form(body: bytes, content_type: str) -> FormData:
    message = BytesParser(policy=default).parsebytes(
        f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("latin-1") + body
    )
    if not message.is_multipart():
        raise HTTPException(
            400,
            "Malformed multipart form data. Ensure the request body matches the declared multipart boundary.",
        )

    fields: dict[str, list[str]] = {}
    files: dict[str, list[UploadedFile]] = {}
    for part in message.iter_parts():
        if part.is_multipart():
            raise HTTPException(
                400,
                "Nested multipart form data is not supported. Flatten the upload into standard form-data parts.",
            )
        if part.get_content_disposition() != "form-data":
            continue

        name = part.get_param("name", header="content-disposition")
        if not isinstance(name, str) or not name:
            continue

        decoded_payload = part.get_payload(decode=True)
        payload = decoded_payload if isinstance(decoded_payload, bytes) else b""
        headers = {key.lower(): value for key, value in part.items()}
        filename = part.get_filename()
        if filename:
            uploaded = UploadedFile(
                name=name,
                filename=filename,
                body=payload,
                content_type=part.get_content_type(),
                headers=headers,
            )
            files.setdefault(name, []).append(uploaded)
            continue

        charset = part.get_content_charset("utf-8") or "utf-8"
        value = _decode_form_value(
            payload,
            charset=charset,
            error_detail="Invalid multipart form encoding. Use a supported charset such as UTF-8.",
        )
        fields.setdefault(name, []).append(value)
    return FormData(fields=fields, files=files)


@dataclass(slots=True)
class Request:
    """HTTP request wrapper exposed to Flasgo handlers."""

    scope: Scope
    receive: Receive
    headers: dict[str, str] = field(init=False)
    _body: bytes | None = field(default=None, init=False)
    _form: FormData | None = field(default=None, init=False)
    _form_loaded: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        self.headers = _decode_headers(self.scope.get("headers", []))

    @property
    def method(self) -> str:
        return str(self.scope.get("method", "GET")).upper()

    @property
    def path(self) -> str:
        return str(self.scope.get("path", "/"))

    @property
    def query_string(self) -> str:
        return bytes(self.scope.get("query_string", b"")).decode("latin-1")

    @property
    def scheme(self) -> str:
        raw = self.scope.get("scheme", "http")
        if not isinstance(raw, str):
            return "http"
        normalized = raw.strip().lower()
        return normalized or "http"

    @property
    def query_params(self) -> Mapping[str, list[str]]:
        return parse_qs(self.query_string, keep_blank_values=True)

    @property
    def content_type(self) -> str:
        content_type, _ = _parse_content_type(self.headers.get("content-type"))
        return content_type

    @property
    def cookies(self) -> dict[str, str]:
        return _parse_cookies(self.headers.get("cookie"))

    @property
    def client_ip(self) -> str | None:
        client = self.scope.get("client")
        if not client:
            return None
        return str(client[0])

    @property
    def session(self) -> Session | None:
        return self.scope.get("session")

    @property
    def user(self) -> User | None:
        return self.scope.get("user")

    async def body(self) -> bytes:
        if self._body is not None:
            return self._body

        max_body = self.scope.get("max_request_body_bytes")
        body_limit = int(max_body) if isinstance(max_body, int) else None
        chunks: list[bytes] = []
        seen = 0
        while True:
            message = await self.receive()
            message_type = message.get("type")
            if message_type == "http.disconnect":
                raise HTTPException(400, "Request body was interrupted because the client disconnected early.")
            if message_type != "http.request":
                continue
            piece = bytes(message.get("body", b""))
            seen += len(piece)
            if body_limit is not None and seen > body_limit:
                raise HTTPException(413, f"Request body exceeds MAX_REQUEST_BODY_BYTES ({body_limit} bytes).")
            chunks.append(piece)
            if not message.get("more_body", False):
                break
        self._body = b"".join(chunks)
        return self._body

    async def text(self, encoding: str = "utf-8") -> str:
        try:
            return (await self.body()).decode(encoding)
        except LookupError as exc:
            raise HTTPException(400, f"Unsupported text encoding {encoding!r}.") from exc
        except UnicodeDecodeError as exc:
            raise HTTPException(
                400,
                f"Request body is not valid {encoding} text. Use the correct encoding or call request.body().",
            ) from exc

    async def json(self) -> Any:
        try:
            return json.loads(await self.text())
        except json.JSONDecodeError as exc:
            raise HTTPException(
                400,
                "Malformed JSON request body. Send valid JSON and set Content-Type: application/json.",
            ) from exc

    async def form(self) -> FormData:
        if self._form_loaded:
            return self._form or FormData()

        content_type, params = _parse_content_type(self.headers.get("content-type"))
        if content_type == "application/x-www-form-urlencoded":
            charset = params.get("charset", "utf-8")
            decoded = _decode_form_value(
                await self.body(),
                charset=charset,
                error_detail="Invalid form encoding. Use a supported charset such as UTF-8.",
            )
            form = FormData(fields=parse_qs(decoded, keep_blank_values=True))
        elif content_type == "multipart/form-data":
            boundary = params.get("boundary")
            if not boundary:
                raise HTTPException(
                    400,
                    "Malformed multipart form data. Include a boundary in the Content-Type header.",
                )
            form = _parse_multipart_form(await self.body(), self.headers.get("content-type", ""))
        else:
            form = FormData()

        self._form = form
        self._form_loaded = True
        return form
