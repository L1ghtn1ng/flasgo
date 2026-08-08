from __future__ import annotations

import asyncio
import mimetypes
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import BinaryIO, cast

from .exceptions import HTTPException
from .request import Request
from .response import Response
from .types import Send

_STREAM_CHUNK_SIZE = 64 * 1024


def _open_static_file(path: Path) -> BinaryIO:
    return cast(BinaryIO, path.open("rb"))


def _read_static_chunk(handle: BinaryIO) -> bytes:
    return handle.read(_STREAM_CHUNK_SIZE)


class StaticFileResponse(Response):
    """Stream a contained static file without buffering it on the event loop."""

    __slots__ = ("_path", "_size")

    def __init__(
        self,
        path: Path,
        size: int,
        *,
        headers: dict[str, str],
        content_type: str,
    ) -> None:
        self._path = path
        self._size = size
        super().__init__(
            body=b"",
            headers=headers,
            content_type=content_type,
            allow_public_cache=True,
        )

    def prepare(self) -> None:
        super().prepare()
        if not self.body:
            self.headers["content-length"] = str(self._size)

    async def send(self, send: Send, *, head_only: bool = False) -> None:
        if self.body:
            await super().send(send, head_only=head_only)
            return

        handle = None if head_only else await asyncio.to_thread(_open_static_file, self._path)
        try:
            if handle is not None:
                stat = os.fstat(handle.fileno())
                self._size = stat.st_size
                self.headers["etag"] = _etag(stat)
                self.headers["last-modified"] = _http_date(stat.st_mtime)
            self.prepare()
            raw_headers = [(key.encode("latin-1"), value.encode("latin-1")) for key, value in self.headers.items()]
            raw_headers.extend((b"set-cookie", cookie.encode("latin-1")) for cookie in self.cookies)
            await send({"type": "http.response.start", "status": self.status_code, "headers": raw_headers})
            if handle is None:
                await send({"type": "http.response.body", "body": b"", "more_body": False})
                return

            while chunk := await asyncio.to_thread(_read_static_chunk, handle):
                await send({"type": "http.response.body", "body": chunk, "more_body": True})
            await send({"type": "http.response.body", "body": b"", "more_body": False})
        finally:
            if handle is not None:
                await asyncio.to_thread(handle.close)


def _http_date(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=UTC).strftime("%a, %d %b %Y %H:%M:%S GMT")


def _etag(stat: os.stat_result) -> str:
    return f'"{stat.st_mtime_ns:x}-{stat.st_size:x}"'


def _normalize_static_path(value: str) -> PurePosixPath:
    if not value or any(char in value for char in ("\x00", "\r", "\n")):
        raise HTTPException(404, "Not Found")

    normalized = value.replace("\\", "/")
    candidate = PurePosixPath(normalized)
    if candidate.is_absolute():
        raise HTTPException(404, "Not Found")
    if any(part in {"", ".", ".."} for part in candidate.parts):
        raise HTTPException(404, "Not Found")
    if any(part.startswith(".") for part in candidate.parts):
        raise HTTPException(404, "Not Found")
    if candidate.parts and candidate.parts[0].endswith(":"):
        raise HTTPException(404, "Not Found")
    return candidate


@dataclass(slots=True, frozen=True)
class StaticDirectory:
    root: Path
    url_path: str
    cache_max_age: int


def resolve_static_directory(directory: str | Path, *, url_path: str, cache_max_age: int) -> StaticDirectory:
    root = Path(directory).expanduser().resolve()
    if not root.exists():
        msg = f"Static directory does not exist: {root}"
        raise ValueError(msg)
    if not root.is_dir():
        msg = f"Static directory is not a directory: {root}"
        raise ValueError(msg)
    if not url_path.startswith("/"):
        raise ValueError("Static url_path must start with '/'.")
    if url_path.endswith("/") and url_path != "/":
        raise ValueError("Static url_path must not end with '/'.")
    if cache_max_age < 0:
        raise ValueError("Static cache_max_age must be greater than or equal to 0.")
    return StaticDirectory(root=root, url_path=url_path, cache_max_age=cache_max_age)


def build_static_response(
    directory: StaticDirectory,
    filename: str,
    *,
    request: Request,
) -> Response:
    normalized = _normalize_static_path(filename)
    candidate = directory.root.joinpath(*normalized.parts)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(directory.root)
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise HTTPException(404, "Not Found") from exc

    if not resolved.is_file():
        raise HTTPException(404, "Not Found")

    stat = resolved.stat()
    etag = _etag(stat)
    if request.headers.get("if-none-match") == etag:
        return Response(
            body=b"",
            status_code=304,
            headers={
                "etag": etag,
                "last-modified": _http_date(stat.st_mtime),
                "cache-control": f"public, max-age={directory.cache_max_age}",
            },
            allow_public_cache=True,
        )

    content_type, encoding = mimetypes.guess_type(str(resolved))
    headers = {
        "cache-control": f"public, max-age={directory.cache_max_age}",
        "etag": etag,
        "last-modified": _http_date(stat.st_mtime),
    }
    if encoding:
        headers["content-encoding"] = encoding
    return StaticFileResponse(
        resolved,
        stat.st_size,
        headers=headers,
        content_type=content_type or "application/octet-stream",
    )
