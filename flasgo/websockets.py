from __future__ import annotations

import json
import re
import time
from collections import deque
from collections.abc import AsyncIterator, Mapping
from enum import Enum, auto
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs

from .request import _reject_json_constant
from .types import Message, Receive, Scope, Send

_SUBPROTOCOL_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_SENDABLE_CLOSE_CODES = frozenset({1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014})

if TYPE_CHECKING:
    from .auth import User
    from .session import Session


class WebSocketDisconnect(Exception):
    def __init__(self, code: int = 1000, reason: str = "") -> None:
        self.code = code
        self.reason = reason
        super().__init__(f"WebSocket disconnected with code {code}: {reason}")


class WebSocketException(Exception):
    pass


class _ClientState(Enum):
    CONNECTING = auto()
    CONNECTED = auto()
    DISCONNECTED = auto()


class _ApplicationState(Enum):
    CONNECTING = auto()
    ACCEPTED = auto()
    DISCONNECTED = auto()


class WebSocket:
    """Stateful ASGI WebSocket wrapper exposed to endpoint handlers."""

    def __init__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        *,
        max_message_bytes: int,
        max_messages_per_minute: int,
    ) -> None:
        self.scope = scope
        self._receive = receive
        self._send = send
        self._max_message_bytes = max_message_bytes
        self._max_messages_per_minute = max_messages_per_minute
        self._message_times: deque[float] = deque()
        self._client_state = _ClientState.CONNECTING
        self._application_state = _ApplicationState.CONNECTING
        self.headers = _decode_headers(scope.get("headers", []))
        self.path_params: dict[str, Any] = {}
        self.state: dict[str, Any] = {}
        self.close_code: int | None = None
        self.close_reason = ""

    @property
    def accepted(self) -> bool:
        return self._application_state is _ApplicationState.ACCEPTED

    @property
    def disconnected(self) -> bool:
        return self._application_state is _ApplicationState.DISCONNECTED

    @property
    def path(self) -> str:
        return str(self.scope.get("path", "/"))

    @property
    def query_params(self) -> Mapping[str, list[str]]:
        raw = bytes(self.scope.get("query_string", b"")).decode("latin-1")
        return parse_qs(raw, keep_blank_values=True)

    @property
    def client_ip(self) -> str | None:
        client = self.scope.get("client")
        return str(client[0]) if client else None

    @property
    def request_id(self) -> str:
        return str(self.scope.get("request_id", ""))

    @property
    def session(self) -> Session | None:
        return self.scope.get("session")

    @property
    def user(self) -> User | None:
        return self.scope.get("user")

    async def receive_connect(self) -> Message:
        if self._client_state is not _ClientState.CONNECTING:
            raise RuntimeError("websocket.connect has already been consumed.")
        message = await self._receive()
        if message.get("type") != "websocket.connect":
            raise WebSocketException("Expected websocket.connect as the first WebSocket event.")
        self._client_state = _ClientState.CONNECTED
        return message

    async def accept(
        self,
        subprotocol: str | None = None,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        if self._client_state is not _ClientState.CONNECTED:
            raise RuntimeError("WebSocket.accept() requires a connected client.")
        if self._application_state is not _ApplicationState.CONNECTING:
            raise RuntimeError("WebSocket.accept() may only be called once before close.")
        offered = tuple(str(value) for value in self.scope.get("subprotocols", ()))
        if subprotocol is not None and subprotocol not in offered:
            raise ValueError("The selected WebSocket subprotocol was not offered by the client.")
        if subprotocol is not None and _SUBPROTOCOL_RE.fullmatch(subprotocol) is None:
            raise ValueError("The selected WebSocket subprotocol is not a valid token.")
        message: Message = {"type": "websocket.accept"}
        if subprotocol is not None:
            message["subprotocol"] = subprotocol
        raw_headers = _encode_accept_headers(headers or {})
        if self.request_id:
            raw_headers.append((b"x-request-id", self.request_id.encode("ascii")))
        if raw_headers:
            message["headers"] = raw_headers
        await self._safe_send(message)
        self._application_state = _ApplicationState.ACCEPTED

    async def receive_text(self) -> str:
        message = await self._receive_message()
        text = message.get("text")
        if not isinstance(text, str):
            await self.close(1003, "Text message required")
            raise WebSocketDisconnect(1003, "Text message required")
        if len(text.encode("utf-8")) > self._max_message_bytes:
            await self.close(1009, "Message too large")
            raise WebSocketDisconnect(1009, "Message too large")
        return text

    async def receive_bytes(self) -> bytes:
        message = await self._receive_message()
        payload = message.get("bytes")
        if not isinstance(payload, bytes):
            await self.close(1003, "Binary message required")
            raise WebSocketDisconnect(1003, "Binary message required")
        if len(payload) > self._max_message_bytes:
            await self.close(1009, "Message too large")
            raise WebSocketDisconnect(1009, "Message too large")
        return payload

    async def receive_json(self) -> Any:
        try:
            return json.loads(await self.receive_text(), parse_constant=_reject_json_constant)
        except (ValueError, RecursionError) as exc:
            await self.close(1007, "Invalid JSON")
            raise WebSocketDisconnect(1007, "Invalid JSON") from exc

    async def send_text(self, value: str) -> None:
        await self._send_message({"type": "websocket.send", "text": value})

    async def send_bytes(self, value: bytes) -> None:
        await self._send_message({"type": "websocket.send", "bytes": value})

    async def send_json(self, value: Any) -> None:
        await self.send_text(json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False))

    async def close(self, code: int = 1000, reason: str = "") -> None:
        if self._application_state is _ApplicationState.DISCONNECTED:
            return
        if code not in _SENDABLE_CLOSE_CODES and not 3000 <= code <= 4999:
            raise ValueError("WebSocket close code is reserved or outside the sendable ranges.")
        if len(reason.encode("utf-8")) > 123:
            raise ValueError("WebSocket close reasons must not exceed 123 UTF-8 bytes.")
        await self._safe_send({"type": "websocket.close", "code": code, "reason": reason})
        self.close_code = code
        self.close_reason = reason
        self._application_state = _ApplicationState.DISCONNECTED

    async def deny(
        self,
        status_code: int,
        detail: str,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        if self._application_state is not _ApplicationState.CONNECTING:
            raise RuntimeError("A WebSocket handshake may only be denied before acceptance.")
        if not 300 <= status_code <= 599:
            raise ValueError("WebSocket denial responses require an HTTP status between 300 and 599.")
        extensions = self.scope.get("extensions", {})
        if isinstance(extensions, Mapping) and "websocket.http.response" in extensions:
            body = detail.encode("utf-8")
            raw_headers = [
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"cache-control", b"no-store"),
                (b"x-content-type-options", b"nosniff"),
            ]
            raw_headers.extend(_encode_accept_headers(headers or {}))
            if self.request_id:
                raw_headers.append((b"x-request-id", self.request_id.encode("ascii")))
            await self._safe_send(
                {
                    "type": "websocket.http.response.start",
                    "status": status_code,
                    "headers": raw_headers,
                }
            )
            await self._safe_send({"type": "websocket.http.response.body", "body": body})
        else:
            await self._safe_send({"type": "websocket.close", "code": 1008, "reason": "Handshake denied"})
            self.close_code = 1008
            self.close_reason = "Handshake denied"
        self._application_state = _ApplicationState.DISCONNECTED

    async def iter_text(self) -> AsyncIterator[str]:
        while True:
            try:
                yield await self.receive_text()
            except WebSocketDisconnect:
                return

    async def iter_bytes(self) -> AsyncIterator[bytes]:
        while True:
            try:
                yield await self.receive_bytes()
            except WebSocketDisconnect:
                return

    async def iter_json(self) -> AsyncIterator[Any]:
        while True:
            try:
                yield await self.receive_json()
            except WebSocketDisconnect:
                return

    async def _receive_message(self) -> Message:
        if self._application_state is not _ApplicationState.ACCEPTED:
            raise RuntimeError("Accept the WebSocket before receiving messages.")
        if self._client_state is _ClientState.DISCONNECTED:
            raise WebSocketDisconnect()
        message = await self._receive()
        message_type = message.get("type")
        if message_type == "websocket.disconnect":
            self._client_state = _ClientState.DISCONNECTED
            self._application_state = _ApplicationState.DISCONNECTED
            self.close_code = int(message.get("code", 1000))
            self.close_reason = str(message.get("reason", ""))
            raise WebSocketDisconnect(self.close_code, self.close_reason)
        if message_type != "websocket.receive":
            raise WebSocketException(f"Unexpected WebSocket event: {message_type!r}")
        if not self._check_message_rate():
            await self.close(1008, "Message rate exceeded")
            raise WebSocketDisconnect(1008, "Message rate exceeded")
        return message

    def _check_message_rate(self) -> bool:
        if self._max_messages_per_minute <= 0:
            return True
        now = time.monotonic()
        cutoff = now - 60.0
        while self._message_times and self._message_times[0] <= cutoff:
            self._message_times.popleft()
        if len(self._message_times) >= self._max_messages_per_minute:
            return False
        self._message_times.append(now)
        return True

    async def _send_message(self, message: Message) -> None:
        if self._application_state is not _ApplicationState.ACCEPTED:
            raise RuntimeError("Accept the WebSocket before sending messages.")
        await self._safe_send(message)

    async def _safe_send(self, message: Message) -> None:
        try:
            await self._send(message)
        except OSError as exc:
            self._application_state = _ApplicationState.DISCONNECTED
            self.close_code = 1006
            self.close_reason = "Connection lost"
            raise WebSocketDisconnect(1006, "Connection lost") from exc


def _decode_headers(raw_headers: list[tuple[bytes, bytes]]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for key_raw, value_raw in raw_headers:
        key = key_raw.decode("latin-1").lower()
        value = value_raw.decode("latin-1")
        headers[key] = f"{headers[key]}, {value}" if key in headers else value
    return headers


def _encode_accept_headers(headers: Mapping[str, str]) -> list[tuple[bytes, bytes]]:
    encoded: list[tuple[bytes, bytes]] = []
    for key, value in headers.items():
        normalized = key.strip().lower()
        if normalized == "sec-websocket-protocol":
            raise ValueError("Pass the selected protocol with subprotocol=, not an acceptance header.")
        if not normalized or any(char in normalized + value for char in ("\r", "\n", "\x00")):
            raise ValueError("Invalid WebSocket acceptance header.")
        try:
            encoded.append((normalized.encode("ascii"), value.encode("latin-1")))
        except UnicodeEncodeError as exc:
            raise ValueError("WebSocket acceptance headers must be ASCII names with Latin-1 values.") from exc
    return encoded
