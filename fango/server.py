from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit

from .types import Message, Receive, Scope, Send

ASGIHandler = Callable[[Scope, Receive, Send], Awaitable[None]]


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


async def run_dev_server(
    app: ASGIHandler,
    host: str,
    port: int,
    *,
    max_request_body_bytes: int = 1_048_576,
    max_request_head_bytes: int = 16_384,
    request_read_timeout_seconds: float = 10.0,
) -> None:
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
    print(f"Fango dev server listening on {addrs}")
    async with server:
        await server.serve_forever()


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
    body = _reason_phrase(status).encode("utf-8")
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
