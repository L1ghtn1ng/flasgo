from __future__ import annotations

import asyncio
import importlib.util
import textwrap
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Annotated

import pytest
from flasgo import (
    Flasgo,
    IsAuthenticated,
    Response,
    User,
    WebSocket,
    WebSocketDisconnect,
    WebSocketHandshakeError,
)


def test_lifespan_background_tasks_and_request_ids() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})
    events: list[str] = []

    @app.lifespan
    async def lifespan(app: Flasgo) -> AsyncGenerator[None]:
        app.state.ready = True
        events.append("startup")
        yield
        events.append("shutdown")

    @app.get("/work")
    async def work() -> Response:
        response = Response.json({"ready": app.state.ready})
        response.add_task(events.append, "background")
        return response

    with app.test_client() as client:
        response = client.get("/work", headers={"x-request-id": "untrusted"})
        assert response.json() == {"ready": True}
        assert response.headers["x-request-id"] != "untrusted"
        assert events == ["startup", "background"]

    assert events == ["startup", "background", "shutdown"]


def test_trusted_request_id_must_match_the_strict_format() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False, "TRUST_INCOMING_REQUEST_ID": True})

    @app.get("/")
    async def home() -> str:
        return "ok"

    client = app.test_client()
    assert client.get("/", headers={"x-request-id": "trace_123"}).headers["x-request-id"] == "trace_123"
    assert client.get("/", headers={"x-request-id": "bad\r\nvalue"}).headers["x-request-id"] != "bad\r\nvalue"


def test_websocket_echo_subprotocol_and_route_params() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.websocket("/rooms/<int:room_id>")
    async def room(websocket: WebSocket, room_id: int) -> None:
        await websocket.accept("chat")
        await websocket.send_json({"room": room_id, "message": await websocket.receive_text()})

    with app.test_client() as client, client.websocket_connect("/rooms/7", subprotocols=("chat",)) as websocket:
        websocket.send_text("hello")
        assert websocket.receive_json() == {"room": 7, "message": "hello"}
        assert websocket.accepted_subprotocol == "chat"
        assert websocket.response_headers["x-request-id"]


def test_async_test_client_uses_one_lifecycle_loop() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.websocket("/async")
    async def socket(websocket: WebSocket) -> None:
        await websocket.accept()
        await websocket.send_text(await websocket.receive_text())

    async def exercise() -> None:
        async with app.test_client() as client, client.awebsocket_connect("/async") as websocket:
            await websocket.send_text("hello")
            assert await websocket.receive_text() == "hello"

    asyncio.run(exercise())


def test_websocket_origin_auth_size_and_rate_limits() -> None:
    app = Flasgo(
        settings={
            "CSRF_ENABLED": False,
            "WEBSOCKET_MAX_MESSAGE_BYTES": 4,
            "WEBSOCKET_MAX_MESSAGES_PER_MINUTE": 1,
        }
    )
    app.register_auth_backend(
        "token",
        lambda request: User(id="alice", is_authenticated=True) if request.headers.get("authorization") == "Bearer valid" else None,
    )

    @app.websocket("/socket")
    @app.authorize(IsAuthenticated(), backend="token")
    async def socket(websocket: WebSocket) -> None:
        await websocket.accept()
        async for message in websocket.iter_text():
            await websocket.send_text(message)

    with app.test_client() as client:
        with (
            pytest.raises(WebSocketHandshakeError) as cross_origin,
            client.websocket_connect(
                "/socket",
                origin="https://attacker.example",
                headers={"authorization": "Bearer valid"},
            ),
        ):
            pass
        assert cross_origin.value.status_code == 403

        with pytest.raises(WebSocketHandshakeError) as anonymous, client.websocket_connect("/socket"):
            pass
        assert anonymous.value.status_code == 401

        with client.websocket_connect("/socket", headers={"authorization": "Bearer valid"}) as websocket:
            websocket.send_text("12345")
            with pytest.raises(WebSocketDisconnect) as too_large:
                websocket.receive_text()
            assert too_large.value.code == 1009

        with client.websocket_connect("/socket", headers={"authorization": "Bearer valid"}) as websocket:
            websocket.send_text("one")
            assert websocket.receive_text() == "one"
            websocket.send_text("two")
            with pytest.raises(WebSocketDisconnect) as too_fast:
                websocket.receive_text()
            assert too_fast.value.code == 1008


def test_websocket_authentication_failures_are_throttled_before_backend() -> None:
    calls = 0

    def backend(request: object) -> None:
        nonlocal calls
        calls += 1
        return None

    app = Flasgo(
        settings={
            "CSRF_ENABLED": False,
            "SECURITY_FAILURE_RATE_LIMIT": 2,
            "SECURITY_FAILURE_WINDOW_SECONDS": 60,
        }
    )
    app.register_auth_backend("test", backend)

    @app.websocket("/private")
    @app.authorize(IsAuthenticated(), backend="test")
    async def private(websocket: WebSocket) -> None:
        await websocket.accept()

    with app.test_client() as client:
        statuses: list[int] = []
        for _ in range(3):
            with pytest.raises(WebSocketHandshakeError) as denied, client.websocket_connect("/private"):
                pass
            statuses.append(denied.value.status_code)

    assert statuses == [401, 401, 429]
    assert calls == 2


def test_websocket_default_route_limit_runs_before_authentication() -> None:
    calls = 0

    def backend(request: object) -> None:
        nonlocal calls
        calls += 1
        return None

    app = Flasgo(settings={"CSRF_ENABLED": False, "SECURITY_FAILURE_RATE_LIMIT": 0})
    app.register_auth_backend("test", backend)

    @app.websocket("/private")
    @app.ratelimit(1, per=60)
    @app.authorize(IsAuthenticated(), backend="test")
    async def private(websocket: WebSocket) -> None:
        await websocket.accept()

    with app.test_client() as client:
        with pytest.raises(WebSocketHandshakeError) as first, client.websocket_connect("/private"):
            pass
        with pytest.raises(WebSocketHandshakeError) as second, client.websocket_connect("/private"):
            pass

    assert first.value.status_code == 401
    assert second.value.status_code == 429
    assert calls == 1


def test_websocket_rejects_ambiguous_origin_headers() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.websocket("/socket")
    async def socket(websocket: WebSocket) -> None:
        await websocket.accept()

    sent: list[dict[str, object]] = []

    async def receive() -> dict[str, object]:
        return {"type": "websocket.connect"}

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    scope = {
        "type": "websocket",
        "asgi": {"version": "3.0", "spec_version": "2.5"},
        "scheme": "ws",
        "path": "/socket",
        "query_string": b"",
        "headers": [
            (b"host", b"localhost"),
            (b"origin", b"http://localhost"),
            (b"origin", b"https://attacker.example"),
        ],
        "client": ("127.0.0.1", 50000),
        "server": ("localhost", 80),
        "subprotocols": [],
        "extensions": {"websocket.http.response": {}},
    }
    asyncio.run(app(scope, receive, send))

    assert sent[0]["type"] == "websocket.http.response.start"
    assert sent[0]["status"] == 403


def test_metrics_require_a_strong_bearer_token_and_use_route_templates() -> None:
    token = "m" * 32
    app = Flasgo(
        settings={
            "CSRF_ENABLED": False,
            "METRICS_ENABLED": True,
            "METRICS_BEARER_TOKEN": token,
        }
    )

    @app.get("/items/<int:item_id>")
    async def item(item_id: int) -> dict[str, int]:
        return {"item_id": item_id}

    client = app.test_client()
    assert client.get("/items/42").status_code == 200
    assert client.get("/metrics").status_code == 401
    metrics = client.get("/metrics", headers={"authorization": f"Bearer {token}"})
    assert metrics.status_code == 200
    assert 'route="/items/<int:item_id>"' in metrics.text
    assert 'route="/items/42"' not in metrics.text
    assert client.get("/metrics", headers={"authorization": "Bearer é"}).status_code == 401


@pytest.mark.parametrize("token", ["é" * 32, " " + "m" * 32, "m" * 32 + " ", "m" * 31 + "?"])
def test_metrics_reject_non_bearer_safe_configured_tokens(token: str) -> None:
    with pytest.raises(ValueError, match="bearer-safe ASCII"):
        Flasgo(settings={"METRICS_ENABLED": True, "METRICS_BEARER_TOKEN": token})


def test_asgi_request_head_limit_rejects_oversized_scopes() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False, "MAX_REQUEST_HEAD_BYTES": 128})

    @app.get("/")
    async def home() -> str:
        return "ok"

    client = app.test_client()
    assert client.get("/").status_code == 200
    oversized = client.get("/", headers={"x-padding": "x" * 256})
    assert oversized.status_code == 431
    assert oversized.headers["connection"] == "close"


def test_response_send_failure_never_attempts_a_second_response() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.get("/")
    async def home() -> str:
        return "ok"

    messages: list[str] = []

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, object]) -> None:
        messages.append(str(message["type"]))
        if message["type"] == "http.response.body":
            raise OSError("client disconnected")

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "headers": [(b"host", b"localhost")],
        "client": ("127.0.0.1", 50000),
        "server": ("localhost", 80),
    }
    asyncio.run(app(scope, receive, send))

    assert messages == ["http.response.start", "http.response.body"]


def test_websocket_handler_parameter_is_resolved_at_registration() -> None:
    """Handlers may take the connection under any name via an annotation, including Annotated metadata."""
    app = Flasgo()

    @app.websocket("/named", public=True)
    async def named(conn: WebSocket) -> None:
        await conn.accept()
        await conn.send_text("named")

    @app.websocket("/annotated", public=True)
    async def annotated(conn: Annotated[WebSocket, {"doc": "connection"}]) -> None:
        await conn.accept()
        await conn.send_text("annotated")

    @app.websocket("/items/<int:item_id>", public=True)
    async def with_params(websocket: WebSocket, item_id: int) -> None:
        await websocket.accept()
        await websocket.send_text(str(item_id))

    with app.test_client() as client:
        for path, expected in (("/named", "named"), ("/annotated", "annotated"), ("/items/7", "7")):
            with client.websocket_connect(path) as websocket:
                assert websocket.receive_text() == expected


def test_websocket_handler_with_type_checking_only_annotation_registers(tmp_path: Path) -> None:
    """Names imported only under TYPE_CHECKING must not break every connection with NameError."""
    module_path = tmp_path / "ws_forward_ref_app.py"
    module_path.write_text(
        textwrap.dedent(
            """
            from typing import TYPE_CHECKING

            from flasgo import Flasgo, WebSocket

            if TYPE_CHECKING:
                from decimal import Decimal

            app = Flasgo()


            @app.websocket("/socket", public=True)
            async def socket(websocket: WebSocket, hint: "Decimal | None" = None) -> None:
                await websocket.accept()
                await websocket.send_text("ok")
            """
        )
    )
    spec = importlib.util.spec_from_file_location("ws_forward_ref_app", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    with module.app.test_client() as client, client.websocket_connect("/socket") as websocket:
        assert websocket.receive_text() == "ok"


def test_websocket_handler_that_never_accepts_is_not_logged_as_success(caplog: pytest.LogCaptureFixture) -> None:
    app = Flasgo()

    @app.websocket("/noaccept", public=True)
    async def noaccept(websocket: WebSocket) -> None:
        return None

    with (
        caplog.at_level("INFO", logger="flasgo.websocket"),
        app.test_client() as client,
        pytest.raises(WebSocketHandshakeError),
        client.websocket_connect("/noaccept"),
    ):
        pass

    outcomes = [getattr(record, "outcome", None) for record in caplog.records if getattr(record, "event", None) == "websocket-complete"]
    assert outcomes == ["not_accepted"]


async def _drive_lifespan(app: Flasgo, *events: str) -> list[str]:
    incoming = [{"type": f"lifespan.{event}"} for event in events]
    sent: list[str] = []

    async def receive() -> dict[str, str]:
        return incoming.pop(0)

    async def send(message: dict[str, object]) -> None:
        sent.append(str(message["type"]))

    await app({"type": "lifespan", "asgi": {"version": "3.0"}, "state": {}}, receive, send)
    return sent


def test_lifespan_handler_that_yields_twice_is_closed_immediately() -> None:
    app = Flasgo()
    events: list[str] = []

    @app.lifespan
    async def lifespan(_app: Flasgo) -> AsyncGenerator[None]:
        try:
            yield
            yield
        finally:
            events.append("cleanup")

    async def run() -> None:
        assert await _drive_lifespan(app, "startup", "shutdown") == ["lifespan.startup.complete", "lifespan.shutdown.failed"]
        assert events == ["cleanup"]

    asyncio.run(run())


def test_lifespan_can_start_again_after_a_failed_startup() -> None:
    app = Flasgo()
    attempts: list[int] = []

    @app.lifespan
    async def lifespan(_app: Flasgo) -> AsyncGenerator[None]:
        attempts.append(len(attempts))
        if len(attempts) == 1:
            raise RuntimeError("first start fails")
        yield

    async def run() -> None:
        assert await _drive_lifespan(app, "startup") == ["lifespan.startup.failed"]
        assert await _drive_lifespan(app, "startup", "shutdown") == ["lifespan.startup.complete", "lifespan.shutdown.complete"]

    asyncio.run(run())
