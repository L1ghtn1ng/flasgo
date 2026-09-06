from __future__ import annotations

import asyncio
import json
import math
from collections.abc import AsyncIterable, AsyncIterator, Mapping
from dataclasses import dataclass
from typing import Any

from .contracts import project_response, validate_response_model
from .response import Response
from .types import Receive, Send
from .validation import ValidationBudget


def _positive_timeout(value: float, name: str) -> None:
    if isinstance(value, bool) or not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be finite and greater than zero.")


class StreamingResponse(Response):
    """Send an async byte/text iterator with backpressure and bounded lifetimes."""

    def __init__(
        self,
        content: AsyncIterable[bytes | str],
        *,
        status_code: int = 200,
        headers: Mapping[str, str] | None = None,
        content_type: str = "application/octet-stream",
        max_chunk_bytes: int = 65_536,
        send_timeout: float = 10,
        idle_timeout: float = 60,
        max_duration: float = 3600,
    ) -> None:
        if not isinstance(content, AsyncIterable):
            raise TypeError("StreamingResponse content must be an async iterable.")
        if isinstance(max_chunk_bytes, bool) or not isinstance(max_chunk_bytes, int) or max_chunk_bytes <= 0:
            raise ValueError("max_chunk_bytes must be a positive integer.")
        for name, value in (
            ("send_timeout", send_timeout),
            ("idle_timeout", idle_timeout),
            ("max_duration", max_duration),
        ):
            _positive_timeout(value, name)
        self.iterator = aiter(content)
        self.max_chunk_bytes = max_chunk_bytes
        self.send_timeout = send_timeout
        self.idle_timeout = idle_timeout
        self.max_duration = max_duration
        self.receive: Receive | None = None
        self._used = False
        self._closed = False
        self._source: AsyncIterator[Any] | None = None
        super().__init__(body=b"", status_code=status_code, headers=dict(headers or {}), content_type=content_type)

    def prepare(self) -> None:
        super().prepare()
        if self.status_code < 200 or self.status_code in {204, 304}:
            raise ValueError("Streaming responses require a status that permits a response body.")
        self.headers.pop("content-length", None)
        self.headers.pop("transfer-encoding", None)

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            close = getattr(self.iterator, "aclose", None)
            if close is not None:
                await close()
        finally:
            source_close = getattr(self._source, "aclose", None)
            if source_close is not None:
                await source_close()

    async def _send_message(self, send: Send, message: dict[str, Any]) -> None:
        async with asyncio.timeout(self.send_timeout):
            await send(message)

    async def _pump(self, send: Send, head_only: bool) -> None:
        try:
            self.prepare()
            headers = [(key.encode("latin-1"), value.encode("latin-1")) for key, value in self.headers.items()]
            headers.extend((b"set-cookie", value.encode("latin-1")) for value in self.cookies)
            await self._send_message(
                send, {"type": "http.response.start", "status": self.status_code, "headers": headers}
            )
            if not head_only:
                while True:
                    try:
                        async with asyncio.timeout(self.idle_timeout):
                            chunk = await anext(self.iterator)
                    except StopAsyncIteration:
                        break
                    if not isinstance(chunk, bytes | str):
                        raise TypeError("Stream chunks must be bytes or str.")
                    if len(chunk) > self.max_chunk_bytes:
                        raise ValueError("Stream chunk exceeds max_chunk_bytes.")
                    payload = chunk.encode("utf-8") if isinstance(chunk, str) else chunk
                    if len(payload) > self.max_chunk_bytes:
                        raise ValueError("Stream chunk exceeds max_chunk_bytes.")
                    await self._send_message(send, {"type": "http.response.body", "body": payload, "more_body": True})
            await self._send_message(send, {"type": "http.response.body", "body": b"", "more_body": False})
        finally:
            await self.aclose()

    async def _disconnect(self) -> None:
        if self.receive is None:
            await asyncio.Event().wait()
            return
        while True:
            message = await self.receive()
            if message["type"] == "http.disconnect":
                return
            raise RuntimeError("Unexpected ASGI event after the request body was consumed.")

    async def send(self, send: Send, *, head_only: bool = False) -> None:
        if self._used:
            raise RuntimeError("A streaming response can only be sent once.")
        self._used = True
        pump = asyncio.create_task(self._pump(send, head_only))
        disconnect = asyncio.create_task(self._disconnect())
        try:
            async with asyncio.timeout(self.max_duration):
                done, _ = await asyncio.wait({pump, disconnect}, return_when=asyncio.FIRST_COMPLETED)
                if pump in done:
                    await pump
                else:
                    await disconnect
                    raise ConnectionError("Streaming client disconnected.")
        finally:
            pump.cancel()
            disconnect.cancel()
            await asyncio.gather(pump, disconnect, return_exceptions=True)


@dataclass(frozen=True, slots=True)
class ServerSentEvent:
    data: Any
    event: str | None = None
    id: str | None = None
    retry: int | None = None

    def __post_init__(self) -> None:
        for value in (self.event, self.id):
            if value is not None and (
                not isinstance(value, str) or len(value) > 1024 or any(ord(c) < 32 or ord(c) == 127 for c in value)
            ):
                raise ValueError("SSE event/id must be bounded strings without control characters.")
        if self.retry is not None and (
            isinstance(self.retry, bool) or not isinstance(self.retry, int) or not 0 <= self.retry <= 2_147_483_647
        ):
            raise ValueError("SSE retry must be an integer between 0 and 2147483647.")


def _json_payload(value: object, model: object) -> str:
    payload = project_response(model, value, ValidationBudget())
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


class EventSourceResponse(StreamingResponse):
    """JSON SSE events with heartbeats; replay storage remains application-owned."""

    def __init__(
        self,
        events: AsyncIterable[ServerSentEvent],
        *,
        item_model: object = Any,
        heartbeat: float = 15,
        headers: Mapping[str, str] | None = None,
        send_timeout: float = 10,
        idle_timeout: float = 60,
        max_duration: float = 3600,
        max_chunk_bytes: int = 65_536,
    ) -> None:
        _positive_timeout(heartbeat, "heartbeat")
        validate_response_model(item_model)
        source = aiter(events)

        async def encoded() -> AsyncIterator[bytes]:
            pending: asyncio.Future[ServerSentEvent] | None = None
            try:
                while True:
                    if pending is None:
                        pending = asyncio.ensure_future(anext(source))
                    done, _ = await asyncio.wait({pending}, timeout=heartbeat)
                    if not done:
                        yield b": ping\n\n"
                        continue
                    try:
                        event = pending.result()
                    except StopAsyncIteration:
                        return
                    pending = None
                    if not isinstance(event, ServerSentEvent):
                        raise TypeError("SSE sources must yield ServerSentEvent instances.")
                    lines = [
                        f"{name}: {value}"
                        for name, value in (("event", event.event), ("id", event.id), ("retry", event.retry))
                        if value is not None
                    ]
                    lines.append("data: " + _json_payload(event.data, item_model))
                    yield ("\n".join(lines) + "\n\n").encode("utf-8")
            finally:
                if pending is not None:
                    pending.cancel()
                    await asyncio.gather(pending, return_exceptions=True)

        super().__init__(
            encoded(),
            content_type="text/event-stream; charset=utf-8",
            headers={**(headers or {}), "cache-control": "no-store", "x-accel-buffering": "no"},
            send_timeout=send_timeout,
            idle_timeout=idle_timeout,
            max_duration=max_duration,
            max_chunk_bytes=max_chunk_bytes,
        )
        self._source = source


class NDJSONResponse(StreamingResponse):
    def __init__(
        self,
        items: AsyncIterable[object],
        *,
        item_model: object = Any,
        headers: Mapping[str, str] | None = None,
        send_timeout: float = 10,
        idle_timeout: float = 60,
        max_duration: float = 3600,
        max_chunk_bytes: int = 65_536,
    ) -> None:
        validate_response_model(item_model)
        source = aiter(items)

        async def encoded() -> AsyncIterator[bytes]:
            async for item in source:
                yield (_json_payload(item, item_model) + "\n").encode("utf-8")

        super().__init__(
            encoded(),
            content_type="application/x-ndjson",
            headers=headers,
            send_timeout=send_timeout,
            idle_timeout=idle_timeout,
            max_duration=max_duration,
            max_chunk_bytes=max_chunk_bytes,
        )
        self._source = source
