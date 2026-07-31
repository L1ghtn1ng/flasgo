from __future__ import annotations

import asyncio
import json
import queue
import threading
from collections.abc import Coroutine, Mapping, Sequence
from concurrent.futures import Future
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import Any, cast
from urllib.parse import urlencode, urljoin, urlsplit
from uuid import uuid4

from .types import ASGIApp, Message, Scope
from .websockets import WebSocketDisconnect

type FormValue = str | int | float | bool
type FileValue = tuple[str, str | bytes] | tuple[str, str | bytes, str]
type RequestData = Mapping[str, FormValue | Sequence[FormValue]] | Sequence[tuple[str, FormValue]]


def _flatten_data(data: RequestData) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if isinstance(data, Mapping):
        for key, value in data.items():
            if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
                pairs.extend((str(key), str(item)) for item in value)
                continue
            pairs.append((str(key), str(value)))
        return pairs

    for key, value in data:
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            pairs.extend((str(key), str(item)) for item in value)
            continue
        pairs.append((str(key), str(value)))
    return pairs


def _merge_cookie_headers(cookie_header: str | None, jar: dict[str, str]) -> str | None:
    cookies = dict(jar)
    if cookie_header:
        parsed = SimpleCookie()
        parsed.load(cookie_header)
        for key, morsel in parsed.items():
            cookies[key] = morsel.value
    if not cookies:
        return None
    return "; ".join(f"{key}={value}" for key, value in cookies.items())


def _encode_multipart(
    data: RequestData | None,
    files: Mapping[str, FileValue],
) -> tuple[bytes, str]:
    boundary = f"flasgo-{uuid4().hex}"
    body = bytearray()

    for key, value in _flatten_data(data or []):
        body.extend(f"--{boundary}\r\n".encode("ascii"))
        body.extend(f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode())
        body.extend(value.encode())
        body.extend(b"\r\n")

    for key, file_value in files.items():
        filename, payload, *rest = file_value
        content_type = rest[0] if rest else "application/octet-stream"
        body.extend(f"--{boundary}\r\n".encode("ascii"))
        body.extend(
            (
                f'Content-Disposition: form-data; name="{key}"; filename="{filename}"\r\n'
                f"Content-Type: {content_type}\r\n\r\n"
            ).encode()
        )
        file_bytes = payload.encode() if isinstance(payload, str) else bytes(payload)
        body.extend(file_bytes)
        body.extend(b"\r\n")

    body.extend(f"--{boundary}--\r\n".encode("ascii"))
    return bytes(body), f"multipart/form-data; boundary={boundary}"


@dataclass(slots=True)
class TestResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes
    history: list[TestResponse] = field(default_factory=list)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8")

    @property
    def location(self) -> str | None:
        return self.headers.get("location")

    def json(self) -> object:
        return json.loads(self.body)


class WebSocketHandshakeError(Exception):
    def __init__(self, status_code: int, body: bytes = b"", headers: dict[str, str] | None = None) -> None:
        self.status_code = status_code
        self.body = body
        self.headers = headers or {}
        super().__init__(f"WebSocket handshake denied with HTTP {status_code}.")


class TestClient:
    __test__ = False

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self._cookies: dict[str, str] = {}
        self._mode: str | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._loop_thread: threading.Thread | None = None
        self._work_queue: queue.Queue[tuple[Coroutine[Any, Any, Any], Future[Any]] | None] | None = None
        self._lifespan_receive: asyncio.Queue[Message] | None = None
        self._lifespan_send: asyncio.Queue[Message] | None = None
        self._lifespan_task: asyncio.Task[None] | None = None

    def __enter__(self) -> TestClient:
        if self._mode is not None:
            raise RuntimeError("TestClient contexts may not be re-entered.")
        self._mode = "sync"
        self._loop = asyncio.new_event_loop()
        self._work_queue = queue.Queue()
        self._loop_thread = threading.Thread(target=self._run_loop, daemon=True)
        self._loop_thread.start()
        try:
            self._submit(self._start_lifespan())
        except Exception:
            self._stop_sync_loop()
            raise
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        try:
            self._submit(self._stop_lifespan())
        finally:
            self._stop_sync_loop()

    async def __aenter__(self) -> TestClient:
        if self._mode is not None:
            raise RuntimeError("TestClient contexts may not be re-entered.")
        self._mode = "async"
        self._loop = asyncio.get_running_loop()
        try:
            await self._start_lifespan()
        except Exception:
            self._loop = None
            self._mode = None
            raise
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        try:
            await self._stop_lifespan()
        finally:
            self._loop = None
            self._mode = None

    def _run_loop(self) -> None:
        loop = self._loop
        work_queue = self._work_queue
        if loop is None or work_queue is None:
            return
        asyncio.set_event_loop(loop)
        while True:
            item = work_queue.get()
            if item is None:
                break
            coro, future = item
            try:
                future.set_result(loop.run_until_complete(coro))
            except BaseException as exc:
                future.set_exception(exc)
        loop.close()

    def _stop_sync_loop(self) -> None:
        if self._work_queue is not None:
            self._work_queue.put(None)
        if self._loop_thread is not None:
            self._loop_thread.join(timeout=5)
        self._loop = None
        self._loop_thread = None
        self._work_queue = None
        self._mode = None

    def _submit[T](self, coro: Coroutine[Any, Any, T]) -> T:
        if self._work_queue is None:
            coro.close()
            raise RuntimeError("TestClient is not running.")
        future: Future[T] = Future()
        self._work_queue.put((coro, future))
        return future.result(timeout=10)

    async def _start_lifespan(self) -> None:
        self._lifespan_receive = asyncio.Queue()
        self._lifespan_send = asyncio.Queue()
        receive_queue = self._lifespan_receive
        send_queue = self._lifespan_send

        async def receive() -> Message:
            return await receive_queue.get()

        async def send(message: Message) -> None:
            await send_queue.put(message)

        scope: Scope = {
            "type": "lifespan",
            "asgi": {"version": "3.0", "spec_version": "2.0"},
            "state": {},
        }
        self._lifespan_task = asyncio.create_task(self.app(scope, receive, send))
        await self._lifespan_receive.put({"type": "lifespan.startup"})
        result = await asyncio.wait_for(self._lifespan_send.get(), timeout=5)
        if result.get("type") != "lifespan.startup.complete":
            if self._lifespan_task is not None:
                await self._lifespan_task
            raise RuntimeError(str(result.get("message", "Application lifespan startup failed.")))

    async def _stop_lifespan(self) -> None:
        if self._lifespan_task is None or self._lifespan_task.done():
            return
        receive_queue = self._lifespan_receive
        send_queue = self._lifespan_send
        if receive_queue is None or send_queue is None:
            raise RuntimeError("TestClient lifespan queues are unavailable.")
        await receive_queue.put({"type": "lifespan.shutdown"})
        result = await asyncio.wait_for(send_queue.get(), timeout=5)
        await asyncio.wait_for(self._lifespan_task, timeout=5)
        self._lifespan_task = None
        if result.get("type") != "lifespan.shutdown.complete":
            raise RuntimeError(str(result.get("message", "Application lifespan shutdown failed.")))

    @property
    def cookies(self) -> dict[str, str]:
        return dict(self._cookies)

    def clear_cookies(self) -> None:
        self._cookies.clear()

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        json: object | None = None,
        data: RequestData | None = None,
        files: Mapping[str, FileValue] | None = None,
        scheme: str = "http",
        follow_redirects: bool = False,
    ) -> TestResponse:
        if self._mode == "async":
            raise RuntimeError("Use await client.arequest(...) inside an async TestClient context.")
        if self._mode == "sync":
            return self._submit(
                self._arequest_impl(
                    method,
                    path,
                    headers=headers,
                    body=body,
                    json=json,
                    data=data,
                    files=files,
                    scheme=scheme,
                    follow_redirects=follow_redirects,
                )
            )
        return asyncio.run(
            self._arequest_impl(
                method,
                path,
                headers=headers,
                body=body,
                json=json,
                data=data,
                files=files,
                scheme=scheme,
                follow_redirects=follow_redirects,
            )
        )

    def get(
        self,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        scheme: str = "http",
        follow_redirects: bool = False,
    ) -> TestResponse:
        return self.request("GET", path, headers=headers, scheme=scheme, follow_redirects=follow_redirects)

    def head(
        self,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        scheme: str = "http",
        follow_redirects: bool = False,
    ) -> TestResponse:
        return self.request("HEAD", path, headers=headers, scheme=scheme, follow_redirects=follow_redirects)

    def post(
        self,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        json: object | None = None,
        data: RequestData | None = None,
        files: Mapping[str, FileValue] | None = None,
        scheme: str = "http",
        follow_redirects: bool = False,
    ) -> TestResponse:
        return self.request(
            "POST",
            path,
            headers=headers,
            body=body,
            json=json,
            data=data,
            files=files,
            scheme=scheme,
            follow_redirects=follow_redirects,
        )

    def put(
        self,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        json: object | None = None,
        data: RequestData | None = None,
        files: Mapping[str, FileValue] | None = None,
        scheme: str = "http",
        follow_redirects: bool = False,
    ) -> TestResponse:
        return self.request(
            "PUT",
            path,
            headers=headers,
            body=body,
            json=json,
            data=data,
            files=files,
            scheme=scheme,
            follow_redirects=follow_redirects,
        )

    def patch(
        self,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        json: object | None = None,
        data: RequestData | None = None,
        files: Mapping[str, FileValue] | None = None,
        scheme: str = "http",
        follow_redirects: bool = False,
    ) -> TestResponse:
        return self.request(
            "PATCH",
            path,
            headers=headers,
            body=body,
            json=json,
            data=data,
            files=files,
            scheme=scheme,
            follow_redirects=follow_redirects,
        )

    def delete(
        self,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        json: object | None = None,
        data: RequestData | None = None,
        scheme: str = "http",
        follow_redirects: bool = False,
    ) -> TestResponse:
        return self.request(
            "DELETE",
            path,
            headers=headers,
            body=body,
            json=json,
            data=data,
            scheme=scheme,
            follow_redirects=follow_redirects,
        )

    async def arequest(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        json: object | None = None,
        data: RequestData | None = None,
        files: Mapping[str, FileValue] | None = None,
        scheme: str = "http",
        follow_redirects: bool = False,
    ) -> TestResponse:
        if self._mode == "sync":
            result = await asyncio.to_thread(
                self._submit,
                self._arequest_impl(
                    method,
                    path,
                    headers=headers,
                    body=body,
                    json=json,
                    data=data,
                    files=files,
                    scheme=scheme,
                    follow_redirects=follow_redirects,
                ),
            )
            return cast(TestResponse, result)
        return await self._arequest_impl(
            method,
            path,
            headers=headers,
            body=body,
            json=json,
            data=data,
            files=files,
            scheme=scheme,
            follow_redirects=follow_redirects,
        )

    async def _arequest_impl(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None,
        body: bytes | None,
        json: object | None,
        data: RequestData | None,
        files: Mapping[str, FileValue] | None,
        scheme: str,
        follow_redirects: bool,
    ) -> TestResponse:
        response = await self._send(
            method,
            path,
            headers=headers,
            body=body,
            json=json,
            data=data,
            files=files,
            scheme=scheme,
        )
        if not follow_redirects:
            return response

        history: list[TestResponse] = []
        current_response = response
        current_method = method.upper()
        current_body = body
        current_json = json
        current_data = data
        current_files = files
        current_path = path

        for _ in range(10):
            location = current_response.location
            if current_response.status_code not in {301, 302, 303, 307, 308} or location is None:
                current_response.history = history
                return current_response

            history.append(current_response)
            current_path = urljoin(current_path, location)
            if current_response.status_code in {301, 302, 303} and current_method not in {"GET", "HEAD"}:
                current_method = "GET"
                current_body = None
                current_json = None
                current_data = None
                current_files = None

            current_response = await self._send(
                current_method,
                current_path,
                headers=headers,
                body=current_body,
                json=current_json,
                data=current_data,
                files=current_files,
                scheme=scheme,
            )

        raise RuntimeError("Too many redirects")

    async def _send(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None,
        body: bytes | None,
        json: object | None,
        data: RequestData | None,
        files: Mapping[str, FileValue] | None,
        scheme: str,
    ) -> TestResponse:
        payload, content_type = _encode_request_body(body=body, json=json, data=data, files=files)

        parsed = urlsplit(path)
        normalized_headers = {"host": "localhost"}
        if headers:
            normalized_headers.update({key.lower(): value for key, value in headers.items()})
        if content_type and "content-type" not in normalized_headers:
            normalized_headers["content-type"] = content_type
        if payload:
            normalized_headers.setdefault("content-length", str(len(payload)))

        cookie_header = _merge_cookie_headers(normalized_headers.get("cookie"), self._cookies)
        if cookie_header:
            normalized_headers["cookie"] = cookie_header

        raw_headers = [
            (key.lower().encode("latin-1"), value.encode("latin-1")) for key, value in normalized_headers.items()
        ]
        scope: Scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": method.upper(),
            "scheme": scheme.lower(),
            "path": parsed.path or "/",
            "raw_path": (parsed.path or "/").encode("latin-1"),
            "query_string": parsed.query.encode("latin-1"),
            "headers": raw_headers,
            "client": ("127.0.0.1", 50000),
            "server": ("localhost", 80),
        }

        queue: list[Message] = [{"type": "http.request", "body": payload, "more_body": False}]
        start_message: Message | None = None
        body_chunks: list[bytes] = []

        async def receive() -> Message:
            if queue:
                return queue.pop(0)
            return {"type": "http.disconnect"}

        async def send(message: Message) -> None:
            nonlocal start_message
            if message["type"] == "http.response.start":
                start_message = message
            elif message["type"] == "http.response.body":
                body_chunks.append(bytes(message.get("body", b"")))

        await self.app(scope, receive, send)

        if start_message is None:
            raise RuntimeError("No response start message from application")

        decoded_headers: dict[str, str] = {}
        for key_raw, value_raw in start_message.get("headers", []):
            key = key_raw.decode("latin-1").lower()
            value = value_raw.decode("latin-1")
            if key in decoded_headers:
                decoded_headers[key] = f"{decoded_headers[key]}\n{value}"
            else:
                decoded_headers[key] = value

        self._update_cookies(decoded_headers.get("set-cookie"))
        return TestResponse(
            status_code=int(start_message["status"]),
            headers=decoded_headers,
            body=b"".join(body_chunks),
        )

    def websocket_connect(
        self,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        origin: str | None = "http://localhost",
        subprotocols: Sequence[str] = (),
        scheme: str = "ws",
    ) -> SyncWebSocketSession:
        if self._mode != "sync":
            raise RuntimeError("websocket_connect() requires `with app.test_client()`.")
        transport = _WebSocketTransport(
            self,
            path,
            headers=headers,
            origin=origin,
            subprotocols=subprotocols,
            scheme=scheme,
        )
        return SyncWebSocketSession(self, transport)

    def awebsocket_connect(
        self,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        origin: str | None = "http://localhost",
        subprotocols: Sequence[str] = (),
        scheme: str = "ws",
    ) -> AsyncWebSocketSession:
        if self._mode != "async":
            raise RuntimeError("awebsocket_connect() requires `async with app.test_client()`.")
        transport = _WebSocketTransport(
            self,
            path,
            headers=headers,
            origin=origin,
            subprotocols=subprotocols,
            scheme=scheme,
        )
        return AsyncWebSocketSession(transport)

    def _update_cookies(self, set_cookie_header: str | None) -> None:
        if not set_cookie_header:
            return
        for raw_cookie in set_cookie_header.split("\n"):
            cookie = SimpleCookie()
            cookie.load(raw_cookie)
            for key, morsel in cookie.items():
                if morsel.value:
                    self._cookies[key] = morsel.value
                else:
                    self._cookies.pop(key, None)


class _WebSocketTransport:
    def __init__(
        self,
        client: TestClient,
        path: str,
        *,
        headers: dict[str, str] | None,
        origin: str | None,
        subprotocols: Sequence[str],
        scheme: str,
    ) -> None:
        self.client = client
        self.path = path
        self.headers = headers
        self.origin = origin
        self.subprotocols = tuple(subprotocols)
        self.scheme = scheme
        self._incoming: asyncio.Queue[Message] | None = None
        self._outgoing: asyncio.Queue[Message] | None = None
        self._task: asyncio.Task[None] | None = None
        self.accepted_subprotocol: str | None = None
        self.response_headers: dict[str, str] = {}
        self.closed = False

    async def start(self) -> None:
        parsed = urlsplit(self.path)
        normalized_headers = {"host": "localhost"}
        if self.headers:
            normalized_headers.update({key.lower(): value for key, value in self.headers.items()})
        if self.origin is not None:
            normalized_headers["origin"] = self.origin
        cookie_header = _merge_cookie_headers(normalized_headers.get("cookie"), self.client._cookies)
        if cookie_header:
            normalized_headers["cookie"] = cookie_header
        raw_headers = [(key.encode("latin-1"), value.encode("latin-1")) for key, value in normalized_headers.items()]
        self._incoming = asyncio.Queue()
        self._outgoing = asyncio.Queue()

        async def receive() -> Message:
            if self._incoming is None:
                raise RuntimeError("WebSocket test transport is not running.")
            return await self._incoming.get()

        async def send(message: Message) -> None:
            if self._outgoing is None:
                raise RuntimeError("WebSocket test transport is not running.")
            await self._outgoing.put(message)

        scope: Scope = {
            "type": "websocket",
            "asgi": {"version": "3.0", "spec_version": "2.5"},
            "http_version": "1.1",
            "scheme": self.scheme,
            "path": parsed.path or "/",
            "raw_path": (parsed.path or "/").encode("latin-1"),
            "query_string": parsed.query.encode("latin-1"),
            "headers": raw_headers,
            "client": ("127.0.0.1", 50000),
            "server": ("localhost", 80),
            "subprotocols": list(self.subprotocols),
            "extensions": {"websocket.http.response": {}},
        }
        self._task = asyncio.create_task(self.client.app(scope, receive, send))
        await self._incoming.put({"type": "websocket.connect"})
        first = await self._next_output()
        if first.get("type") == "websocket.accept":
            self.accepted_subprotocol = first.get("subprotocol")
            self.response_headers = _decode_raw_headers(first.get("headers", []))
            return
        if first.get("type") == "websocket.close":
            await self._finish_task()
            raise WebSocketHandshakeError(403)
        if first.get("type") == "websocket.http.response.start":
            status = int(first.get("status", 403))
            headers = _decode_raw_headers(first.get("headers", []))
            body = bytearray()
            while True:
                message = await self._next_output()
                if message.get("type") != "websocket.http.response.body":
                    raise RuntimeError("Invalid WebSocket denial response.")
                body.extend(bytes(message.get("body", b"")))
                if not message.get("more_body", False):
                    break
            await self._finish_task()
            raise WebSocketHandshakeError(status, bytes(body), headers)
        raise RuntimeError(f"Unexpected WebSocket handshake message: {first.get('type')!r}")

    async def send_text(self, value: str) -> None:
        await self._put({"type": "websocket.receive", "text": value})

    async def send_bytes(self, value: bytes) -> None:
        await self._put({"type": "websocket.receive", "bytes": value})

    async def send_json(self, value: object) -> None:
        await self.send_text(json.dumps(value, separators=(",", ":"), ensure_ascii=False))

    async def receive_text(self) -> str:
        message = await self._next_output()
        self._raise_if_closed(message)
        value = message.get("text")
        if not isinstance(value, str):
            raise RuntimeError("Expected a WebSocket text message from the application.")
        return value

    async def receive_bytes(self) -> bytes:
        message = await self._next_output()
        self._raise_if_closed(message)
        value = message.get("bytes")
        if not isinstance(value, bytes):
            raise RuntimeError("Expected a WebSocket binary message from the application.")
        return value

    async def receive_json(self) -> object:
        return json.loads(await self.receive_text())

    async def close(self, code: int = 1000, reason: str = "") -> None:
        if self.closed:
            return
        self.closed = True
        if self._task is not None and not self._task.done():
            await self._put({"type": "websocket.disconnect", "code": code, "reason": reason})
        await self._finish_task()

    async def _put(self, message: Message) -> None:
        if self._incoming is None:
            raise RuntimeError("WebSocket test transport is not connected.")
        await self._incoming.put(message)

    async def _next_output(self) -> Message:
        if self._outgoing is None:
            raise RuntimeError("WebSocket test transport is not connected.")
        return await asyncio.wait_for(self._outgoing.get(), timeout=5)

    def _raise_if_closed(self, message: Message) -> None:
        if message.get("type") == "websocket.close":
            self.closed = True
            raise WebSocketDisconnect(int(message.get("code", 1000)), str(message.get("reason", "")))
        if message.get("type") != "websocket.send":
            raise RuntimeError(f"Unexpected WebSocket output: {message.get('type')!r}")

    async def _finish_task(self) -> None:
        if self._task is not None:
            await asyncio.wait_for(self._task, timeout=5)
            self._task = None


class SyncWebSocketSession:
    def __init__(self, client: TestClient, transport: _WebSocketTransport) -> None:
        self._client = client
        self._transport = transport

    @property
    def accepted_subprotocol(self) -> str | None:
        return self._transport.accepted_subprotocol

    @property
    def response_headers(self) -> dict[str, str]:
        return dict(self._transport.response_headers)

    def __enter__(self) -> SyncWebSocketSession:
        self._client._submit(self._transport.start())
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self._client._submit(self._transport.close())

    def send_text(self, value: str) -> None:
        self._client._submit(self._transport.send_text(value))

    def send_bytes(self, value: bytes) -> None:
        self._client._submit(self._transport.send_bytes(value))

    def send_json(self, value: object) -> None:
        self._client._submit(self._transport.send_json(value))

    def receive_text(self) -> str:
        return self._client._submit(self._transport.receive_text())

    def receive_bytes(self) -> bytes:
        return self._client._submit(self._transport.receive_bytes())

    def receive_json(self) -> object:
        return self._client._submit(self._transport.receive_json())

    def close(self, code: int = 1000, reason: str = "") -> None:
        self._client._submit(self._transport.close(code, reason))


class AsyncWebSocketSession:
    def __init__(self, transport: _WebSocketTransport) -> None:
        self._transport = transport

    @property
    def accepted_subprotocol(self) -> str | None:
        return self._transport.accepted_subprotocol

    @property
    def response_headers(self) -> dict[str, str]:
        return dict(self._transport.response_headers)

    async def __aenter__(self) -> AsyncWebSocketSession:
        await self._transport.start()
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        await self._transport.close()

    async def send_text(self, value: str) -> None:
        await self._transport.send_text(value)

    async def send_bytes(self, value: bytes) -> None:
        await self._transport.send_bytes(value)

    async def send_json(self, value: object) -> None:
        await self._transport.send_json(value)

    async def receive_text(self) -> str:
        return await self._transport.receive_text()

    async def receive_bytes(self) -> bytes:
        return await self._transport.receive_bytes()

    async def receive_json(self) -> object:
        return await self._transport.receive_json()

    async def close(self, code: int = 1000, reason: str = "") -> None:
        await self._transport.close(code, reason)


def _decode_raw_headers(raw_headers: Sequence[tuple[bytes, bytes]]) -> dict[str, str]:
    decoded: dict[str, str] = {}
    for key_raw, value_raw in raw_headers:
        decoded[key_raw.decode("latin-1").lower()] = value_raw.decode("latin-1")
    return decoded


def _encode_request_body(
    *,
    body: bytes | None,
    json: object | None,
    data: RequestData | None,
    files: Mapping[str, FileValue] | None,
) -> tuple[bytes, str | None]:
    provided = sum(value is not None for value in (body, json, data, files))
    if provided > 1 and not (data is not None and files is not None and body is None and json is None):
        raise ValueError("Use only one of body, json, or data/files per request.")

    if json is not None:
        return json_module_dumps(json).encode("utf-8"), "application/json"
    if files is not None:
        return _encode_multipart(data, files)
    if data is not None:
        return urlencode(_flatten_data(data), doseq=True).encode("utf-8"), "application/x-www-form-urlencoded"
    if body is not None:
        return body, None
    return b"", None


def json_module_dumps(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
