from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from email.parser import BytesParser
from email.policy import default
from typing import TYPE_CHECKING, Any, TypeVar, overload
from urllib.parse import parse_qs

from .exceptions import HTTPException
from .types import Receive, Scope

if TYPE_CHECKING:
    from .auth import User
    from .session import Session

_T = TypeVar("_T")

DEFAULT_MAX_MULTIPART_PARTS = 1_000
DEFAULT_MAX_FORM_FIELDS = 1_000
_JSON_BODY_ERROR = "Malformed JSON request body. Send valid JSON and set Content-Type: application/json."


def _scope_positive_int(scope: Scope, key: str, default: int) -> int:
    value = scope.get(key)
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return default


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"Invalid JSON constant: {value!r}")


def _sanitize_filename(filename: str) -> str:
    """Return a path-component-free upload filename safe for filesystem use."""

    cleaned = filename.replace("\\", "/").rsplit("/", 1)[-1]
    cleaned = "".join(char for char in cleaned if ord(char) >= 32 and ord(char) != 127)
    previous = None
    while cleaned != previous:
        previous = cleaned
        cleaned = cleaned.strip().strip(".")
    return cleaned


def _count_multipart_part_delimiters(body: bytes, boundary: bytes) -> int:
    """Count opening boundary delimiter lines without counting payload substrings."""

    marker = b"--" + boundary
    count = 0
    offset = 0
    while (index := body.find(marker, offset)) >= 0:
        suffix = index + len(marker)
        at_line_start = index == 0 or body[index - 1] in (0x0A, 0x0D)
        if at_line_start and not body.startswith(b"--", suffix):
            line_end = suffix
            while line_end < len(body) and body[line_end] in (0x20, 0x09):
                line_end += 1
            if line_end == len(body) or body.startswith((b"\r\n", b"\n", b"\r"), line_end):
                count += 1
        offset = suffix
    return count


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


def _parse_cookie_values(cookie_headers: list[str]) -> dict[str, list[str]]:
    cookies: dict[str, list[str]] = {}
    for cookie_header in cookie_headers:
        for chunk in cookie_header.split(";"):
            item = chunk.strip()
            if not item or "=" not in item:
                continue
            key, value = item.split("=", 1)
            name = key.strip()
            if name:
                cookies.setdefault(name, []).append(value.strip())
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
    """Uploaded file with a sanitized, path-component-free client filename."""

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
    def get(self, key: object, /) -> str | None: ...

    @overload
    def get(self, key: object, /, default: _T) -> str | _T: ...

    def get(self, key: object, /, default: object = None) -> str | object:
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


def _parse_multipart_form(
    body: bytes,
    content_type: str,
    boundary: str,
    *,
    max_parts: int,
    max_fields: int,
) -> FormData:
    try:
        boundary_bytes = boundary.encode("ascii")
    except UnicodeEncodeError as exc:
        raise HTTPException(400, "Malformed multipart form data. The boundary must be ASCII text.") from exc
    if not 1 <= len(boundary_bytes) <= 200:
        raise HTTPException(400, "Malformed multipart form data. The boundary length is invalid.")
    # The email parser has quadratic memory behavior on many tiny parts, so bound the
    # actual delimiter lines with a cheap raw scan before parsing.
    if _count_multipart_part_delimiters(body, boundary_bytes) > max_parts:
        raise HTTPException(413, "Multipart form data exceeds MAX_MULTIPART_PARTS.")
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
    parts_seen = 0
    fields_seen = 0
    for part in message.iter_parts():
        parts_seen += 1
        if parts_seen > max_parts:
            raise HTTPException(413, "Multipart form data exceeds MAX_MULTIPART_PARTS.")
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
                filename=_sanitize_filename(filename) or "upload",
                body=payload,
                content_type=part.get_content_type(),
                headers=headers,
            )
            files.setdefault(name, []).append(uploaded)
            continue

        fields_seen += 1
        if fields_seen > max_fields:
            raise HTTPException(413, "Multipart form data exceeds MAX_FORM_FIELDS.")
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
        max_fields = _scope_positive_int(self.scope, "max_form_fields", DEFAULT_MAX_FORM_FIELDS)
        try:
            return parse_qs(self.query_string, keep_blank_values=True, max_num_fields=max_fields)
        except ValueError as exc:
            raise HTTPException(413, "Query string exceeds MAX_FORM_FIELDS.") from exc

    @property
    def content_type(self) -> str:
        content_type, _ = _parse_content_type(self.headers.get("content-type"))
        return content_type

    @property
    def cookies(self) -> dict[str, str]:
        return _parse_cookies(self.headers.get("cookie"))

    def header_values(self, name: str) -> tuple[str, ...]:
        """Return every wire-level value for a case-insensitive header name."""

        normalized = name.lower().encode("latin-1")
        return tuple(
            value.decode("latin-1") for key, value in self.scope.get("headers", []) if key.lower() == normalized
        )

    def cookie_values(self, name: str) -> tuple[str, ...]:
        """Return every value for an exact, case-sensitive cookie name."""

        parsed = _parse_cookie_values(list(self.header_values("cookie")))
        return tuple(parsed.get(name, ()))

    @property
    def client_ip(self) -> str | None:
        client = self.scope.get("client")
        if not client:
            return None
        return str(client[0])

    @property
    def request_id(self) -> str:
        return str(self.scope.get("request_id", ""))

    @property
    def session(self) -> Session | None:
        return self.scope.get("session")

    @property
    def user(self) -> User | None:
        return self.scope.get("user")

    async def body(self) -> bytes:
        if self.scope.get("flasgo.websocket_upgrade"):
            raise RuntimeError("Request body is not available on a WebSocket upgrade view.")
        if self._body is not None:
            return self._body

        max_body = self.scope.get("max_request_body_bytes")
        body_limit = int(max_body) if isinstance(max_body, int) else None
        configured_timeout = self.scope.get("request_read_timeout_seconds")
        read_timeout = float(configured_timeout) if isinstance(configured_timeout, int | float) else None
        chunks: list[bytes] = []
        seen = 0
        try:
            async with asyncio.timeout(read_timeout):
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
        except TimeoutError as exc:
            raise HTTPException(
                408,
                "Request body was not received before REQUEST_READ_TIMEOUT_SECONDS elapsed.",
            ) from exc
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
            return json.loads(await self.text(), parse_constant=_reject_json_constant)
        except (ValueError, RecursionError) as exc:
            raise HTTPException(400, _JSON_BODY_ERROR) from exc

    async def form(self) -> FormData:
        if self._form_loaded:
            return self._form or FormData()

        max_fields = _scope_positive_int(self.scope, "max_form_fields", DEFAULT_MAX_FORM_FIELDS)
        content_type, params = _parse_content_type(self.headers.get("content-type"))
        if content_type == "application/x-www-form-urlencoded":
            charset = params.get("charset", "utf-8")
            decoded = _decode_form_value(
                await self.body(),
                charset=charset,
                error_detail="Invalid form encoding. Use a supported charset such as UTF-8.",
            )
            try:
                parsed = parse_qs(decoded, keep_blank_values=True, max_num_fields=max_fields)
            except ValueError as exc:
                raise HTTPException(413, "Form data exceeds MAX_FORM_FIELDS.") from exc
            form = FormData(fields=parsed)
        elif content_type == "multipart/form-data":
            boundary = params.get("boundary")
            if not boundary:
                raise HTTPException(
                    400,
                    "Malformed multipart form data. Include a boundary in the Content-Type header.",
                )
            form = _parse_multipart_form(
                await self.body(),
                self.headers.get("content-type", ""),
                boundary,
                max_parts=_scope_positive_int(self.scope, "max_multipart_parts", DEFAULT_MAX_MULTIPART_PARTS),
                max_fields=max_fields,
            )
        else:
            form = FormData()

        self._form = form
        self._form_loaded = True
        return form
