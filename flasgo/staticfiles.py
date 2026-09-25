from __future__ import annotations

import asyncio
import mimetypes
import os
from dataclasses import dataclass
from email.utils import formatdate
from pathlib import Path, PurePosixPath
from stat import S_ISREG
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
    return formatdate(timestamp, usegmt=True)


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


# Encodings browsers transparently decode; anything else is an archive the user downloads as-is.
_TRANSPARENT_ENCODINGS = frozenset({"gzip", "br"})
_ARCHIVE_CONTENT_TYPES = {
    "gzip": "application/gzip",
    "bzip2": "application/x-bzip2",
    "xz": "application/x-xz",
    "compress": "application/x-compress",
}


async def build_static_response(
    directory: StaticDirectory,
    filename: str,
    *,
    request: Request,
) -> Response:
    """Serve one file from ``directory``, resolving and stat-ing it off the event loop."""
    relative = _normalize_static_path(filename)
    resolved, stat = await asyncio.to_thread(_locate_static_file, directory, relative)
    etag = _etag(stat)
    last_modified = _http_date(stat.st_mtime)
    cache_control = f"public, max-age={directory.cache_max_age}"
    if _etag_matches(request.headers.get("if-none-match"), etag):
        return Response(
            body=b"",
            status_code=304,
            headers={"etag": etag, "last-modified": last_modified, "cache-control": cache_control},
            allow_public_cache=True,
        )

    # Guess from the requested name: a symlink target such as ``app.js.3f2a`` has no useful suffix.
    content_type, encoding = mimetypes.guess_file_type(relative.name)
    if encoding is not None and (encoding not in _TRANSPARENT_ENCODINGS or content_type in {None, "application/x-tar"}):
        # e.g. ``.tar.gz`` or ``.xz``: sending Content-Encoding would make browsers decode (or fail to decode) the
        # download, so serve the archive itself.
        content_type, encoding = _ARCHIVE_CONTENT_TYPES.get(encoding, "application/octet-stream"), None
    headers = {"cache-control": cache_control, "etag": etag, "last-modified": last_modified}
    if encoding:
        headers["content-encoding"] = encoding
    return StaticFileResponse(
        resolved,
        stat.st_size,
        headers=headers,
        content_type=content_type or "application/octet-stream",
    )


def _locate_static_file(directory: StaticDirectory, relative: PurePosixPath) -> tuple[Path, os.stat_result]:
    """Resolve a contained regular file. Blocking; run it in a worker thread."""
    try:
        resolved = directory.root.joinpath(*relative.parts).resolve(strict=True)
        resolved.relative_to(directory.root)
        stat = resolved.stat()
    except OSError, ValueError:
        raise HTTPException(404, "Not Found") from None
    if not S_ISREG(stat.st_mode):
        raise HTTPException(404, "Not Found")
    return resolved, stat


def _etag_matches(if_none_match: str | None, etag: str) -> bool:
    """Apply RFC 9110 weak comparison to an ``If-None-Match`` list, including ``*``."""
    if if_none_match is None:
        return False
    if if_none_match.strip() == "*":
        return True
    target = etag.removeprefix("W/")
    return any(candidate.strip().removeprefix("W/") == target for candidate in if_none_match.split(","))
