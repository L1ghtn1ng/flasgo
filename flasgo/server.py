from __future__ import annotations

import asyncio
import os
import shlex
import sys
from collections.abc import Awaitable, Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from .types import Message, Receive, Scope, Send

if TYPE_CHECKING:
    from watchfiles import Change

ASGIHandler = Callable[[Scope, Receive, Send], Awaitable[None]]
type ReloadChanges = set[tuple[Change, str]]
_RELOAD_ENV = "FLASGO_RUN_MAIN"


def _parse_request_head(head: bytes) -> tuple[str, str, str, list[tuple[bytes, bytes]]]:
    lines = head.decode("latin-1").split("\r\n")
    request_line = lines[0]
    method, target, version = request_line.split(" ", 2)
    headers: list[tuple[bytes, bytes]] = []
    for line in lines[1:]:
        if not line:
            continue
        key, value = line.split(":", 1)
        headers.append((key.strip().lower().encode("latin-1"), value.strip().encode("latin-1")))
    return method, target, version, headers


def _content_length(headers: list[tuple[bytes, bytes]]) -> int:
    for key, value in headers:
        if key == b"content-length":
            raw = value.decode("latin-1").strip()
            if not raw.isdigit():
                raise ValueError("Invalid Content-Length")
            return int(raw)
    return 0


def _build_response(start: Message, body: Message) -> bytes:
    status = int(start["status"])
    reason = _reason_phrase(status)
    header_lines = [f"HTTP/1.1 {status} {reason}\r\n"]
    for key, value in start.get("headers", []):
        header_lines.append(f"{key.decode('latin-1')}: {value.decode('latin-1')}\r\n")
    header_lines.append("\r\n")
    return "".join(header_lines).encode("latin-1") + bytes(body.get("body", b""))


def _reason_phrase(status_code: int) -> str:
    return {
        200: "OK",
        201: "Created",
        204: "No Content",
        401: "Unauthorized",
        408: "Request Timeout",
        413: "Payload Too Large",
        429: "Too Many Requests",
        431: "Request Header Fields Too Large",
        400: "Bad Request",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        500: "Internal Server Error",
    }.get(status_code, "OK")


def _simple_error_detail(status_code: int) -> str:
    return {
        400: "Bad Request. Check the request line, headers, and body formatting.",
        401: "Unauthorized. Provide valid credentials and retry.",
        403: "Forbidden. The request was understood but is not allowed.",
        404: "Not Found. Check the request URL.",
        405: "Method Not Allowed. Retry with a supported HTTP method.",
        408: "Request Timeout. Send the request body more quickly or increase the timeout.",
        413: "Payload Too Large. Reduce the request body size or increase MAX_REQUEST_BODY_BYTES.",
        429: "Too Many Requests. Wait a moment before retrying.",
        431: "Request Header Fields Too Large. Reduce the request header size.",
        500: "Internal Server Error. Check the application logs for details.",
    }.get(status_code, _reason_phrase(status_code))


async def run_dev_server(
    app: ASGIHandler,
    host: str,
    port: int,
    *,
    reload: bool = False,
    reload_dirs: Sequence[str | Path] | None = None,
    max_request_body_bytes: int = 1_048_576,
    max_request_head_bytes: int = 16_384,
    request_read_timeout_seconds: float = 10.0,
) -> None:
    if reload and os.environ.get(_RELOAD_ENV) != "true":
        await asyncio.to_thread(run_with_reload, reload_dirs=reload_dirs)
        return

    server = await asyncio.start_server(
        lambda r, w: _handle_connection(
            app,
            r,
            w,
            max_request_body_bytes=max_request_body_bytes,
            request_read_timeout_seconds=request_read_timeout_seconds,
        ),
        host,
        port,
        limit=max_request_head_bytes,
    )
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    print(f"Flasgo dev server listening on {addrs}")
    async with server:
        await server.serve_forever()


def run_with_reload(
    *,
    reload_dirs: Sequence[str | Path] | None = None,
) -> None:
    try:
        from watchfiles import run_process
    except ImportError as exc:
        raise RuntimeError(
            "Reload support requires the 'watchfiles' package. Install project dependencies and retry."
        ) from exc

    watch_paths = tuple(str(resolve_reload_dir(path)) for path in (reload_dirs or (Path.cwd(),)))
    command = build_reload_command()
    previous = os.environ.get(_RELOAD_ENV)
    os.environ[_RELOAD_ENV] = "true"
    try:
        print(f"Flasgo reloader watching {', '.join(watch_paths)}")
        run_process(
            *watch_paths,
            target=command,
            target_type="command",
            callback=log_reload_changes,
            ignore_permission_denied=True,
        )
    finally:
        if previous is None:
            os.environ.pop(_RELOAD_ENV, None)
        else:
            os.environ[_RELOAD_ENV] = previous


def resolve_reload_dir(path: str | Path) -> Path:
    resolved = Path(path).expanduser().resolve()
    if not resolved.exists():
        msg = f"Reload directory does not exist: {resolved}"
        raise ValueError(msg)
    if not resolved.is_dir():
        msg = f"Reload directory is not a directory: {resolved}"
        raise ValueError(msg)
    return resolved


def build_reload_command() -> str:
    argv = list(getattr(sys, "orig_argv", []))
    if not argv:
        argv = [sys.executable, *sys.argv]
    if len(argv) < 2 and not Path(argv[0]).exists():
        raise RuntimeError(
            "Reload support requires starting Flasgo from a Python script or module import, not an interactive shell."
        )
    return shlex.join(argv)


def log_reload_changes(changes: ReloadChanges) -> None:
    changed_paths = ", ".join(sorted(path for _, path in changes))
    if changed_paths:
        print(f"Flasgo reload triggered by changes in: {changed_paths}")


async def _handle_connection(
    app: ASGIHandler,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    max_request_body_bytes: int,
    request_read_timeout_seconds: float,
) -> None:
    try:
        head = await asyncio.wait_for(
            reader.readuntil(b"\r\n\r\n"),
            timeout=request_read_timeout_seconds,
        )
    except TimeoutError:
        await _write_simple_response(writer, 408)
        return
    except asyncio.LimitOverrunError:
        await _write_simple_response(writer, 431)
        return
    except Exception:
        writer.close()
        await writer.wait_closed()
        return

    try:
        method, target, _, headers = _parse_request_head(head[:-4])
    except Exception:
        await _write_simple_response(writer, 400)
        return

    parsed_target = urlsplit(target)

    body = b""
    try:
        length = _content_length(headers)
    except ValueError:
        await _write_simple_response(writer, 400)
        return

    if length > max_request_body_bytes:
        await _write_simple_response(writer, 413)
        return

    if length:
        try:
            body = await asyncio.wait_for(
                reader.readexactly(length),
                timeout=request_read_timeout_seconds,
            )
        except TimeoutError:
            await _write_simple_response(writer, 408)
            return
        except Exception:
            await _write_simple_response(writer, 400)
            return

    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method.upper(),
        "scheme": "http",
        "path": parsed_target.path or "/",
        "raw_path": (parsed_target.path or "/").encode("latin-1"),
        "query_string": parsed_target.query.encode("latin-1"),
        "headers": headers,
        "client": writer.get_extra_info("peername"),
        "server": writer.get_extra_info("sockname"),
    }

    queue = [{"type": "http.request", "body": body, "more_body": False}]
    start_message: Message | None = None
    body_message: Message | None = None

    async def receive() -> Message:
        if queue:
            return queue.pop(0)
        return {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        nonlocal start_message, body_message
        if message["type"] == "http.response.start":
            start_message = message
        elif message["type"] == "http.response.body":
            body_message = message

    await app(scope, receive, send)

    if start_message is None:
        start_message = {"type": "http.response.start", "status": 500, "headers": []}
    if body_message is None:
        body_message = {"type": "http.response.body", "body": b"", "more_body": False}

    writer.write(_build_response(start_message, body_message))
    await writer.drain()
    writer.close()
    await writer.wait_closed()


async def _write_simple_response(writer: asyncio.StreamWriter, status: int) -> None:
    body = _simple_error_detail(status).encode("utf-8")
    header = (
        f"HTTP/1.1 {status} {_reason_phrase(status)}\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("latin-1")
    writer.write(header + body)
    await writer.drain()
    writer.close()
    await writer.wait_closed()
