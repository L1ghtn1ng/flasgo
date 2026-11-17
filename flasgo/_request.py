import asyncio
import binascii
import codecs
import json
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, overload, override
from urllib.parse import parse_qs, unquote_to_bytes

from .exceptions import HTTPException, _RequestRejection
from .types import Receive, Scope

if TYPE_CHECKING:
    from ._session import Session
    from .auth import User


DEFAULT_MAX_MULTIPART_PARTS = 1_000
DEFAULT_MAX_FORM_FIELDS = 1_000
# Browsers emit a few hundred bytes of headers per part; the cap keeps a part's header block from becoming the bulk of
# a request body that every later parsing step must walk.
MAX_MULTIPART_PART_HEADER_BYTES = 16_384
# Request data may name its own text encoding, so only codecs with C implementations and linear decoding are
# accepted. Python also ships codecs such as ``punycode`` whose pure-Python decoder is quadratic.
_FORM_CHARSETS = frozenset(
    codecs.lookup(name).name
    for name in (
        "utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be", "ascii",
        *(f"iso-8859-{number}" for number in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 16)),
        *(f"windows-125{number}" for number in range(9)),
        "koi8-r", "koi8-u", "mac-roman", "shift_jis", "cp932", "euc-jp", "iso-2022-jp", "gb2312", "gbk", "gb18030",
        "big5", "cp950", "euc-kr", "cp949",
    )
)  # fmt: skip
_MEDIA_TYPE_RE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+/[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_JSON_BODY_ERROR = "Malformed JSON request body. Send valid JSON and set Content-Type: application/json."


def _scope_positive_int(scope: Scope, key: str, default: int) -> int:
    value = scope.get(key)
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return default


def parse_query_params(scope: Scope) -> dict[str, list[str]]:
    """Decode an HTTP or WebSocket scope's query string, enforcing the ``MAX_FORM_FIELDS`` limit."""
    max_fields = _scope_positive_int(scope, "max_form_fields", DEFAULT_MAX_FORM_FIELDS)
    raw = bytes(scope.get("query_string", b"")).decode("latin-1")
    try:
        return parse_qs(raw, keep_blank_values=True, max_num_fields=max_fields)
    except ValueError as exc:
        raise _RequestRejection(413, "Query string exceeds MAX_FORM_FIELDS.", "form_limit") from exc


def scope_header_values(scope: Scope, name: bytes) -> tuple[str, ...]:
    """Return every value of a lowercase header name from an ASGI scope, preserving duplicates."""
    return tuple(value.decode("latin-1") for key, value in scope.get("headers", []) if key.lower() == name)


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


def _decode_headers(raw_headers: list[tuple[bytes, bytes]]) -> dict[str, str]:
    return {key.decode("latin-1").lower(): value.decode("latin-1") for key, value in raw_headers}


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


def _parse_header_params(value: str) -> tuple[str, dict[str, str]]:
    """Split a ``value; name=param`` header into its lowercased main value and parameters in one linear pass.

    Quoted strings honour ``\\"`` and ``\\\\`` escapes only, so Windows paths in upload filenames survive intact.
    RFC 2231/5987 ``name*=charset'lang'percent-encoded`` parameters and RFC 2231 continuations (``name*0``,
    ``name*1*``, ...) replace their plain form; parameters that cannot be decoded, and parameters without ``=``, are
    ignored rather than failing the request.
    """
    length = len(value)
    end = value.find(";")
    if end < 0:
        end = length
    main = value[:end].strip().lower()
    params: dict[str, str] = {}
    extended: dict[str, str] = {}
    continuations: dict[str, dict[int, tuple[str, bool]]] = {}
    index = end
    while index < length:
        index += 1  # skip ';'
        name_end = index
        while name_end < length and value[name_end] not in "=;":
            name_end += 1
        name = value[index:name_end].strip().lower()
        if name_end >= length or value[name_end] == ";":
            index = name_end
            continue
        index = name_end + 1
        while index < length and value[index] in " \t":
            index += 1
        if index < length and value[index] == '"':
            index += 1
            pieces: list[str] = []
            start = index
            while index < length and value[index] != '"':
                if value[index] == "\\" and index + 1 < length and value[index + 1] in '"\\':
                    pieces.append(value[start:index])
                    start = index + 1
                    index += 2
                    continue
                index += 1
            pieces.append(value[start:index])
            param = "".join(pieces)
            index += 1  # skip the closing quote (or step past the end of an unterminated value)
            while index < length and value[index] != ";":
                index += 1
        else:
            param_end = value.find(";", index)
            if param_end < 0:
                param_end = length
            param = value[index:param_end].strip()
            index = param_end
        if not name:
            continue
        if name.endswith("*") and name.count("*") == 1:
            decoded = _decode_extended_param(param)
            if decoded is not None:
                extended.setdefault(name[:-1], decoded)
            continue
        if (continuation := _CONTINUATION_RE.fullmatch(name)) is not None:
            segments = continuations.setdefault(continuation[1], {})
            if len(segments) < _MAX_CONTINUATIONS:
                segments.setdefault(int(continuation[2]), (param, bool(continuation[3])))
            continue
        params.setdefault(name, param)
    for base, segments in continuations.items():
        joined = _join_continuations(segments)
        if joined is not None:
            extended.setdefault(base, joined)
    params.update(extended)
    return main, params


_CONTINUATION_RE = re.compile(r"([^*]+)\*([0-9]{1,3})(\*?)")
_MAX_CONTINUATIONS = 64


def _join_continuations(segments: Mapping[int, tuple[str, bool]]) -> str | None:
    """Join RFC 2231 ``name*0``, ``name*1*``, ... segments, or return ``None`` when they cannot be decoded."""
    if 0 not in segments:
        return None
    ordered = []
    while len(ordered) in segments:
        ordered.append(segments[len(ordered)])
    if not any(encoded for _value, encoded in ordered):
        return "".join(value for value, _encoded in ordered)
    first, first_encoded = ordered[0]
    if not first_encoded:
        return None
    charset, quote_mark, rest = first.partition("'")
    _language, quote_mark2, first = rest.partition("'")
    codec = _form_codec(charset.strip() or "utf-8")
    if not quote_mark or not quote_mark2 or codec is None:
        return None
    try:
        raw = b"".join(unquote_to_bytes(value) if encoded else value.encode("ascii") for value, encoded in [(first, True), *ordered[1:]])
        return raw.decode(codec)
    except UnicodeError:
        return None


_ENCODED_WORDS_RE = re.compile(r"(?:=\?[^?\s]+\?[BbQq]\?[^?\s]*\?=\s*)+")
_ENCODED_WORD_RE = re.compile(r"=\?([^?\s]+)\?([BbQq])\?([^?\s]*)\?=")


def _decode_encoded_words(value: str) -> str:
    """Decode a value made only of RFC 2047 encoded words, as some MIME libraries send filenames; else return it."""
    if not value.startswith("=?") or not _ENCODED_WORDS_RE.fullmatch(value.strip()):
        return value
    pieces = []
    for charset, encoding, text in _ENCODED_WORD_RE.findall(value):
        codec = _form_codec(charset.partition("*")[0])
        if codec is None:
            return value
        try:
            data = text.encode("ascii")
            raw = binascii.a2b_base64(data) if encoding in "Bb" else binascii.a2b_qp(data, header=True)
            pieces.append(raw.decode(codec))
        except UnicodeError, binascii.Error:
            return value
    return "".join(pieces)


def _decode_extended_param(value: str) -> str | None:
    """Decode an RFC 5987 ``charset'language'percent-encoded`` value, or return ``None`` when it is malformed."""
    charset, quote_mark, rest = value.partition("'")
    _language, quote_mark2, encoded = rest.partition("'")
    if not quote_mark or not quote_mark2:
        return None
    codec = _form_codec(charset.strip() or "utf-8")
    if codec is None:
        return None
    try:
        return unquote_to_bytes(encoded).decode(codec)
    except UnicodeDecodeError:
        return None


def _form_codec(charset: str) -> str | None:
    """Return the canonical codec name for an allowed request charset, or ``None``."""
    try:
        name = codecs.lookup(charset).name
    except LookupError, ValueError:  # unknown names, and names containing NUL
        return None
    return name if name in _FORM_CHARSETS else None


def _parse_content_type(header_value: str | None) -> tuple[str, dict[str, str]]:
    """Return the lowercased media type (empty when absent or malformed) and its parameters."""
    if not header_value:
        return "", {}
    content_type, params = _parse_header_params(header_value)
    if not _MEDIA_TYPE_RE.fullmatch(content_type):
        return "", {}
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

    @override
    def __getitem__(self, key: str) -> str:
        values = self._fields.get(key)
        if not values:
            raise KeyError(key)
        return values[0]

    @override
    def __iter__(self) -> Iterator[str]:
        return iter(self._fields)

    @override
    def __len__(self) -> int:
        return len(self._fields)

    @overload
    def get(self, key: object, /) -> str | None: ...

    @overload
    def get[T](self, key: object, /, default: T) -> str | T: ...

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
    codec = _form_codec(charset)
    if codec is None:
        raise HTTPException(400, error_detail)
    try:
        return payload.decode(codec)
    except UnicodeError as exc:
        raise HTTPException(400, error_detail) from exc


_MALFORMED_MULTIPART = "Malformed multipart form data. Ensure the request body matches the declared multipart boundary."


def _find_multipart_delimiter(body: bytes, marker: bytes, offset: int) -> tuple[int, bool]:
    """Return the next delimiter line at or after ``offset`` and whether it closes the body, or ``(-1, False)``."""
    while (index := body.find(marker, offset)) >= 0:
        suffix = index + len(marker)
        if index == 0 or body[index - 1] == 0x0A:
            closing = body.startswith(b"--", suffix)
            line_end = suffix + 2 if closing else suffix
            while line_end < len(body) and body[line_end] in (0x20, 0x09):
                line_end += 1
            # Only transport padding may follow a delimiter on its line; "--boundary--tail" inside a payload is data.
            if body.startswith((b"\r\n", b"\n"), line_end) or (closing and line_end == len(body)):
                return index, closing
        offset = suffix
    return -1, False


def _split_multipart_parts(body: bytes, boundary: bytes, *, max_parts: int) -> list[bytes]:
    """Split a multipart body into raw parts with one linear scan, enforcing ``max_parts`` as parts are found."""
    marker = b"--" + boundary
    index, closing = _find_multipart_delimiter(body, marker, 0)
    if index < 0:
        raise HTTPException(400, _MALFORMED_MULTIPART)
    parts: list[bytes] = []
    while not closing:
        start = body.index(b"\n", index + len(marker)) + 1
        next_index, closing = _find_multipart_delimiter(body, marker, start)
        if next_index < 0:
            raise HTTPException(400, _MALFORMED_MULTIPART)
        end = next_index
        if end > start and body[end - 1] == 0x0A:
            end -= 2 if end - 1 > start and body[end - 2] == 0x0D else 1
        parts.append(body[start : max(start, end)])
        if len(parts) > max_parts:
            raise _RequestRejection(413, "Multipart form data exceeds MAX_MULTIPART_PARTS.", "multipart_limit")
        index = next_index
    return parts


def _decode_part_header_text(raw: bytes) -> str:
    """Decode part header bytes: browsers send UTF-8 filenames unescaped, so fall back to Latin-1 only if needed."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _parse_part_headers(part: bytes) -> tuple[dict[str, str], bytes]:
    """Split one raw part into lowercased headers (last value wins) and its payload."""
    if not part:
        return {}, b""
    if part.startswith((b"\r\n", b"\n")):
        return {}, part[2 if part.startswith(b"\r\n") else 1 :]
    limit = MAX_MULTIPART_PART_HEADER_BYTES
    crlf = part.find(b"\r\n\r\n", 0, limit + 4)
    lf = part.find(b"\n\n", 0, limit + 2)
    candidates = [(position, size) for position, size in ((crlf, 4), (lf, 2)) if position >= 0]
    if candidates:
        header_end, separator = min(candidates)
    else:
        # RFC 2046 allows a part with headers and no body (no blank line before the next delimiter).
        header_end, separator = len(part.rstrip(b"\r\n")), len(part) - len(part.rstrip(b"\r\n"))
    if header_end > limit:
        raise _RequestRejection(413, "Multipart part headers exceed the size limit.", "multipart_limit")
    headers: dict[str, str] = {}
    current: str | None = None
    for line in _decode_part_header_text(part[:header_end]).replace("\r\n", "\n").split("\n"):
        if line[:1] in (" ", "\t") and current is not None:
            headers[current] = f"{headers[current]} {line.strip()}"
            continue
        name, colon, value = line.partition(":")
        if not colon or not name.strip():
            raise HTTPException(400, "Malformed multipart form data. Part header lines must be 'Name: value'.")
        current = name.strip().lower()
        headers[current] = value.strip()
    return headers, part[header_end + separator :]


def _decode_part_payload(payload: bytes, transfer_encoding: str | None) -> bytes:
    """Undo a legacy Content-Transfer-Encoding; RFC 7578 deprecates them, but some clients still send base64."""
    encoding = (transfer_encoding or "").strip().lower()
    try:
        if encoding == "base64":
            return binascii.a2b_base64(payload)
        if encoding == "quoted-printable":
            return binascii.a2b_qp(payload)
    except binascii.Error as exc:
        raise HTTPException(400, "Malformed multipart form data. A part's transfer encoding could not be decoded.") from exc
    return payload


def _parse_multipart_form(
    body: bytes,
    boundary: str,
    *,
    max_parts: int,
    max_fields: int,
) -> FormData:
    """Parse multipart fields and uploads while enforcing configured field, file, and part limits.

    The parser is linear in the body size: parts are split with ``bytes.find`` and every header is parsed by
    ``_parse_header_params``. (The stdlib ``email`` parser this replaces is quadratic on some header values.)
    """
    try:
        boundary_bytes = boundary.encode("ascii")
    except UnicodeEncodeError as exc:
        raise HTTPException(400, "Malformed multipart form data. The boundary must be ASCII text.") from exc
    if not 1 <= len(boundary_bytes) <= 200:
        raise HTTPException(400, "Malformed multipart form data. The boundary length is invalid.")

    fields: dict[str, list[str]] = {}
    files: dict[str, list[UploadedFile]] = {}
    fields_seen = 0
    for raw_part in _split_multipart_parts(body, boundary_bytes, max_parts=max_parts):
        headers, raw_payload = _parse_part_headers(raw_part)
        part_type, type_params = _parse_content_type(headers.get("content-type"))
        if part_type.startswith("multipart/"):
            raise HTTPException(
                400,
                "Nested multipart form data is not supported. Flatten the upload into standard form-data parts.",
            )
        disposition, disposition_params = _parse_header_params(headers.get("content-disposition", ""))
        if disposition != "form-data":
            continue

        name = disposition_params.get("name")
        if not name:
            continue

        payload = _decode_part_payload(raw_payload, headers.get("content-transfer-encoding"))
        filename = disposition_params.get("filename")
        if filename is not None:
            filename = _decode_encoded_words(filename)
            # Browsers submit an untouched optional file input as a part with ``filename=""`` and no content;
            # that means "no file", not a text field.
            if not filename and not payload:
                continue
            uploaded = UploadedFile(
                name=name,
                filename=_sanitize_filename(filename) or "upload",
                body=payload,
                content_type=part_type or "text/plain",
                headers=headers,
            )
            files.setdefault(name, []).append(uploaded)
            continue

        fields_seen += 1
        if fields_seen > max_fields:
            raise _RequestRejection(413, "Multipart form data exceeds MAX_FORM_FIELDS.", "form_limit")
        charset = type_params.get("charset", "utf-8").strip().lower() or "utf-8"
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
        """Decode query parameters while enforcing the configured field-count limit."""
        return parse_query_params(self.scope)

    @property
    def content_type(self) -> str:
        content_type, _ = _parse_content_type(self.headers.get("content-type"))
        return content_type

    @property
    def cookies(self) -> dict[str, str]:
        """Return cookies from every ``Cookie`` header; the first value wins for a repeated name."""
        return {name: values[0] for name, values in _parse_cookie_values(list(self.header_values("cookie"))).items()}

    def header_values(self, name: str) -> tuple[str, ...]:
        """Return every wire-level value for a case-insensitive header name."""
        return scope_header_values(self.scope, name.lower().encode("latin-1"))

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
        """Read and cache the request body within the configured byte and receive-time limits."""
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
                        raise _RequestRejection(
                            413, f"Request body exceeds MAX_REQUEST_BODY_BYTES ({body_limit} bytes).", "request_body_limit"
                        )
                    chunks.append(piece)
                    if not message.get("more_body", False):
                        break
        except TimeoutError as exc:
            raise _RequestRejection(
                408,
                "Request body was not received before REQUEST_READ_TIMEOUT_SECONDS elapsed.",
                "request_read_timeout",
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
        """Parse supported form encodings while retaining bounded diagnostic rejection reasons."""
        if self._form is not None:
            return self._form

        max_fields = _scope_positive_int(self.scope, "max_form_fields", DEFAULT_MAX_FORM_FIELDS)
        content_type, params = _parse_content_type(self.headers.get("content-type"))
        if content_type == "application/x-www-form-urlencoded":
            charset = _form_codec(params.get("charset", "").strip() or "utf-8")
            if charset is None:
                raise HTTPException(400, "Invalid form encoding. Use a supported charset such as UTF-8.")
            decoded = _decode_form_value(
                await self.body(),
                charset=charset,
                error_detail="Invalid form encoding. Use a supported charset such as UTF-8.",
            )
            try:
                # Percent-escapes must be decoded with the declared charset too, and strictly: silently replacing
                # invalid bytes with U+FFFD would accept input that multipart parsing rejects.
                parsed = parse_qs(decoded, keep_blank_values=True, max_num_fields=max_fields, encoding=charset, errors="strict")
            except UnicodeDecodeError as exc:
                raise HTTPException(400, "Invalid form encoding. Use a supported charset such as UTF-8.") from exc
            except ValueError as exc:
                raise _RequestRejection(413, "Form data exceeds MAX_FORM_FIELDS.", "form_limit") from exc
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
                boundary,
                max_parts=_scope_positive_int(self.scope, "max_multipart_parts", DEFAULT_MAX_MULTIPART_PARTS),
                max_fields=max_fields,
            )
        else:
            form = FormData()

        self._form = form
        return form
