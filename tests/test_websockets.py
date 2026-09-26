"""Unit tests for the WebSocket wrapper, driven directly through fake ASGI channels."""

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from flasgo import WebSocket, WebSocketDisconnect, WebSocketException

type Message = dict[str, Any]


def _socket(
    incoming: list[Message],
    sent: list[Message],
    *,
    extensions: dict[str, Any] | None = None,
    max_message_bytes: int = 16,
    send_error: BaseException | None = None,
) -> WebSocket:
    queue = [{"type": "websocket.connect"}, *incoming]

    async def receive() -> Message:
        return queue.pop(0) if queue else {"type": "websocket.disconnect", "code": 1000}

    async def send(message: Message) -> None:
        if send_error is not None:
            raise send_error
        sent.append(message)

    scope: dict[str, Any] = {"type": "websocket", "headers": [], "subprotocols": ["chat"]}
    if extensions is not None:
        scope["extensions"] = extensions
    return WebSocket(scope, receive, send, max_message_bytes=max_message_bytes, max_messages_per_minute=60)


async def _accepted(incoming: list[Message], sent: list[Message], **kwargs: Any) -> WebSocket:
    websocket = _socket(incoming, sent, **kwargs)
    await websocket.receive_connect()
    await websocket.accept()
    return websocket


def _run(check: Callable[[], Awaitable[None]]) -> None:
    asyncio.run(check())


def test_receive_bytes_enforces_message_type_and_size() -> None:
    async def check() -> None:
        sent: list[Message] = []
        websocket = await _accepted([{"type": "websocket.receive", "bytes": b"ok"}, {"type": "websocket.receive", "text": "x"}], sent)
        assert await websocket.receive_bytes() == b"ok"
        with pytest.raises(WebSocketDisconnect) as wrong_type:
            await websocket.receive_bytes()
        assert wrong_type.value.code == 1003

        sent = []
        websocket = await _accepted([{"type": "websocket.receive", "bytes": b"x" * 17}], sent)
        with pytest.raises(WebSocketDisconnect) as too_large:
            await websocket.receive_bytes()
        assert too_large.value.code == 1009
        assert sent[-1] == {"type": "websocket.close", "code": 1009, "reason": "Message too large"}

    _run(check)


@pytest.mark.parametrize("payload", ["{not json", "NaN", "[1, Infinity]"])
def test_receive_json_closes_with_1007_on_invalid_json(payload: str) -> None:
    async def check() -> None:
        sent: list[Message] = []
        websocket = await _accepted([{"type": "websocket.receive", "text": payload}], sent)
        with pytest.raises(WebSocketDisconnect) as invalid:
            await websocket.receive_json()
        assert invalid.value.code == 1007
        assert sent[-1]["code"] == 1007

    _run(check)


def test_iterators_stop_on_client_disconnect_and_record_its_code() -> None:
    async def check() -> None:
        sent: list[Message] = []
        websocket = await _accepted(
            [
                {"type": "websocket.receive", "text": '{"n": 1}'},
                {"type": "websocket.receive", "text": "[2]"},
                {"type": "websocket.disconnect", "code": 4001, "reason": "bye"},
            ],
            sent,
        )
        assert [item async for item in websocket.iter_json()] == [{"n": 1}, [2]]
        assert (websocket.close_code, websocket.close_reason) == (4001, "bye")
        with pytest.raises(WebSocketDisconnect):
            await websocket.receive_text()

        websocket = await _accepted([{"type": "websocket.receive", "bytes": b"a"}, {"type": "websocket.disconnect", "code": 1001}], [])
        assert [item async for item in websocket.iter_bytes()] == [b"a"]
        assert websocket.close_code == 1001

    _run(check)


def test_unexpected_events_are_rejected() -> None:
    async def check() -> None:
        websocket = await _accepted([{"type": "websocket.bogus"}], [])
        with pytest.raises(WebSocketException, match="Unexpected WebSocket event"):
            await websocket.receive_text()

    _run(check)


@pytest.mark.parametrize(("code", "reason"), [(1005, ""), (1006, ""), (2999, ""), (5000, ""), (1000, "x" * 124)])
def test_close_rejects_reserved_codes_and_long_reasons(code: int, reason: str) -> None:
    async def check() -> None:
        websocket = await _accepted([], [])
        with pytest.raises(ValueError, match=r"close code|close reasons"):
            await websocket.close(code, reason)

    _run(check)


def test_messages_after_close_report_that_the_socket_is_closed() -> None:
    async def check() -> None:
        websocket = await _accepted([], [])
        await websocket.close()
        with pytest.raises(RuntimeError, match="WebSocket is closed"):
            await websocket.send_text("late")

    _run(check)


def test_deny_validates_status_and_falls_back_to_a_policy_close() -> None:
    async def check() -> None:
        sent: list[Message] = []
        websocket = _socket([], sent, extensions={"websocket.http.response": {}})
        await websocket.receive_connect()
        with pytest.raises(ValueError, match="between 300 and 599"):
            await websocket.deny(200, "nope")

        sent = []
        websocket = _socket([], sent)
        await websocket.receive_connect()
        await websocket.deny(403, "Forbidden")
        assert sent == [{"type": "websocket.close", "code": 1008, "reason": "Handshake denied"}]
        assert websocket.close_code == 1008

    _run(check)


def test_accept_rejects_protocol_headers_and_unoffered_subprotocols() -> None:
    async def check() -> None:
        websocket = _socket([], [])
        await websocket.receive_connect()
        with pytest.raises(ValueError, match="subprotocol="):
            await websocket.accept(headers={"Sec-WebSocket-Protocol": "chat"})
        with pytest.raises(ValueError, match="not offered"):
            await websocket.accept("other")
        await websocket.accept("chat")

    _run(check)


def test_send_failures_are_reported_as_abnormal_closure() -> None:
    async def check() -> None:
        websocket = _socket([], [], send_error=ConnectionResetError())
        await websocket.receive_connect()
        with pytest.raises(WebSocketDisconnect) as lost:
            await websocket.accept()
        assert lost.value.code == 1006
        assert websocket.close_code == 1006

    _run(check)
