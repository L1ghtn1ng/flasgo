from __future__ import annotations

import mimetypes
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from .exceptions import HTTPException
from .request import Request
from .response import Response


def _http_date(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=UTC).strftime("%a, %d %b %Y %H:%M:%S GMT")


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
    etag = f'"{stat.st_mtime_ns:x}-{stat.st_size:x}"'
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

    try:
        payload = resolved.read_bytes()
    except OSError as exc:
        raise HTTPException(404, "Not Found") from exc

    content_type, encoding = mimetypes.guess_type(str(resolved))
    headers = {
        "cache-control": f"public, max-age={directory.cache_max_age}",
        "etag": etag,
        "last-modified": _http_date(stat.st_mtime),
    }
    if encoding:
        headers["content-encoding"] = encoding
    return Response(
        body=payload,
        headers=headers,
        content_type=content_type or "application/octet-stream",
        allow_public_cache=True,
    )
