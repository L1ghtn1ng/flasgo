import asyncio
from collections.abc import AsyncIterator
from contextvars import ContextVar
from typing import Any, cast, get_type_hints

import pytest

import flasgo.app as app_module
import flasgo.streaming as streaming_module
from flasgo import (
    Blueprint,
    Flasgo,
    IsAuthenticated,
    MemoryStore,
    NDJSONResponse,
    Request,
    Response,
    ServerSideSessions,
    Settings,
    StreamingResponse,
    WebSocket,
    WebSocketHandshakeError,
    session,
)
from flasgo.app import _request_head_size
from flasgo.routing import routes_overlap
from flasgo.security import SecurityConfig, build_set_cookie


async def _drain_stream_cleanups() -> None:
    """Let released producers finish and wait for cleanup callbacks before closing their loop."""
    async with asyncio.timeout(2):
        await asyncio.sleep(0)
        # Process-wide cleanup callbacks do not expose a completion event.
        while streaming_module._active_cleanups or streaming_module._pending_cleanups:  # noqa: ASYNC110
            await asyncio.sleep(0)


@pytest.mark.parametrize("codepoint", [*range(0x20), 0x7F], ids=lambda value: f"U+{value:04X}")
def test_cookie_controls_are_rejected_before_emission(codepoint: int) -> None:
    """Reject every C0 control and DEL through cookie builders, raw headers, and late mutations."""
    value = f"before{chr(codepoint)}after"
    raw_cookie = f"sample={value}; Path=/"
    with pytest.raises(ValueError, match="control characters"):
        build_set_cookie("sample", value)
    response = Response.text("ok")
    with pytest.raises(ValueError, match="control characters"):
        response.set_cookie("sample", value)
    assert response.cookies == []
    with pytest.raises(ValueError, match="Invalid Set-Cookie"):
        Response(body=b"", cookies=[raw_cookie])
    with pytest.raises(ValueError, match=r"(?i)set-cookie"):
        Response(body=b"", headers={"Set-Cookie": raw_cookie})

    async def run() -> None:
        """Verify send-time validation rejects post-construction mutations before response start."""
        messages: list[dict[str, Any]] = []

        async def send(message: dict[str, Any]) -> None:
            """Record any unintended ASGI emission of an invalid cookie."""
            messages.append(message)

        for raw_header in (False, True):
            mutated = Response.text("ok")
            if raw_header:
                mutated.headers["Set-Cookie"] = raw_cookie
            else:
                mutated.cookies.append(raw_cookie)
            with pytest.raises(ValueError, match=r"(?i)set-cookie"):
                await mutated.send(send)

        async def receive() -> dict[str, Any]:
            """Supply the connection event required before WebSocket acceptance or denial."""
            return {"type": "websocket.connect"}

        for accept in (False, True):
            websocket = WebSocket(
                {"type": "websocket", "extensions": {"websocket.http.response": {}}},
                receive,
                send,
                max_message_bytes=1024,
                max_messages_per_minute=60,
            )
            await websocket.receive_connect()
            handshake = (
                websocket.accept(headers={"Set-Cookie": raw_cookie})
                if accept
                else websocket.deny(403, "Denied", headers={"Set-Cookie": raw_cookie})
            )
            with pytest.raises(ValueError, match=r"Invalid (Set-Cookie value|WebSocket \w+ header)"):
                await handshake
        assert messages == []

    asyncio.run(run())


def test_cookie_control_validation_preserves_printable_values_and_attributes() -> None:
    """Retain printable cookie punctuation, empty values, and spaces between attributes."""
    response = Response.text("ok")
    response.set_cookie("sample", "!valid~", path="/cookie")
    response.delete_cookie("expired")
    response.headers["Set-Cookie"] = "raw=!valid~; Path=/; SameSite=Lax"
    response.prepare()
    assert response.cookies[0].startswith("sample=!valid~; Path=/cookie;")
    assert response.cookies[1].startswith("expired=;")


@pytest.mark.parametrize("converter", ["path", "str"])
@pytest.mark.parametrize("reverse", [False, True])
def test_intersecting_route_ties_are_rejected_for_both_protocols(converter: str, reverse: bool) -> None:
    """Reject order-dependent matches while retaining disjoint methods and paths."""
    paths = [f"/<{converter}:value>/bar", f"/foo/<{converter}:value>"]
    if reverse:
        paths.reverse()
    app = Flasgo(settings={"CSRF_ENABLED": False})

    def endpoint(value: str) -> str:
        """Echo the shared parameter for either HTTP registration order."""
        return value

    app.get(paths[0])(endpoint)
    with pytest.raises(ValueError, match="conflicts with an existing route pattern"):
        app.get(paths[1])(endpoint)
    app.post(paths[1])(endpoint)
    assert app.test_client().get("/foo/bar").status_code == 200
    assert app.test_client().post("/foo/bar").status_code == 200

    async def socket(value: str) -> None:
        """Provide a WebSocket endpoint for registration-only overlap checks."""
        return

    app.add_websocket_route(paths[0], socket)
    with pytest.raises(ValueError, match="conflicts with an existing route pattern"):
        app.add_websocket_route(paths[1], socket)


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("/<path:a>/bar", "/foo/<path:b>", True),
        ("/a/<str:x>", "/b/<str:y>", False),
        ("/<int:x>/bar", "/foo/<int:y>", False),
        ("/<float:x>", "/12.5", True),
        ("/<float:x>", "/12.", False),
        ("/<float:x>x", "/12x", True),
        ("/a<x>b", "/ac<y>", True),
        ("/雪/<path:x>", "/雪/道", True),
        ("/<path:x>/bar", "/foo/bar/baz", False),
    ],
)
def test_route_language_intersection(left: str, right: str, expected: bool) -> None:
    """Cover converter repetition, optional decimals, embedded params, and Unicode literals."""
    assert routes_overlap(left, right) is expected
    assert routes_overlap(right, left) is expected


def test_cleanup_queue_overflow_is_explicit_and_pending_work_drains(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep active and pending counts bounded without losing accepted finalizers."""
    monkeypatch.setattr(streaming_module, "_MAX_ACTIVE_CLEANUPS", 1)
    monkeypatch.setattr(streaming_module, "_MAX_PENDING_CLEANUPS", 1)

    async def run() -> None:
        """Saturate active and pending cleanup, then verify automatic drain and explicit overflow."""
        release = asyncio.Event()
        entered: list[str] = []

        class Source:
            def __init__(self, name: str) -> None:
                """Label each source so finalization order can be observed."""
                self.name = name

            def __aiter__(self) -> Source:
                """Return this source as its own async iterator."""
                return self

            async def __anext__(self) -> bytes:
                """End iteration immediately so the test isolates cleanup behavior."""
                raise StopAsyncIteration

            async def aclose(self) -> None:
                """Record closure, hold active capacity, and fail the queued primary finalizer."""
                entered.append(self.name)
                if self.name == "active":
                    try:
                        await release.wait()
                    except asyncio.CancelledError:
                        await release.wait()
                if self.name == "pending":
                    raise RuntimeError("detached cleanup failure")

        active = StreamingResponse(Source("active"), cleanup_timeout=0.001)
        pending = StreamingResponse(Source("pending"), cleanup_timeout=0.001)
        pending._source = Source("underlying")
        overflow = StreamingResponse(Source("overflow"), cleanup_timeout=0.001)
        observed: list[dict[str, Any]] = []
        loop = asyncio.get_running_loop()
        old_handler = loop.get_exception_handler()
        loop.set_exception_handler(lambda _loop, context: observed.append(context))
        try:
            await active.aclose()
            await pending.aclose()
            await pending.aclose()
            with pytest.raises(RuntimeError, match="cleanup capacity exhausted"):
                await overflow.aclose()
            assert not overflow._closed
            assert streaming_module._active_cleanups == 1
            assert len(streaming_module._pending_cleanups) == 1
            release.set()
            await _drain_stream_cleanups()
            assert entered == ["active", "pending", "underlying"]
            assert not streaming_module._pending_cleanups
            assert streaming_module._active_cleanups == 0
            await overflow.aclose()
            assert entered == ["active", "pending", "underlying", "overflow"]
            assert observed == []
        finally:
            release.set()
            try:
                await _drain_stream_cleanups()
            finally:
                loop.set_exception_handler(old_handler)

    asyncio.run(run())


def test_deferred_cleanup_preserves_owning_loop_and_context(monkeypatch: pytest.MonkeyPatch) -> None:
    """Drain queued finalizers across loop threads without borrowing another request's context."""
    monkeypatch.setattr(streaming_module, "_MAX_ACTIVE_CLEANUPS", 1)
    marker: ContextVar[str] = ContextVar("cleanup_owner", default="unset")

    async def run() -> None:
        """Release capacity on one loop and verify queued cleanup executes on its original loop."""
        release = asyncio.Event()
        queued = asyncio.Event()
        main_loop = asyncio.get_running_loop()

        class ActiveSource:
            def __aiter__(self) -> ActiveSource:
                """Return the source whose cleanup occupies the sole active slot."""
                return self

            async def __anext__(self) -> bytes:
                """End iteration without producing a response body."""
                raise StopAsyncIteration

            async def aclose(self) -> None:
                """Hold the cleanup slot until explicitly released, surviving one cancellation."""
                try:
                    await release.wait()
                except asyncio.CancelledError:
                    await release.wait()

        def worker() -> None:
            """Run the queued response in a separate event-loop thread."""

            async def other_loop() -> None:
                """Queue a finalizer under its own context and await its completion."""
                owner = asyncio.get_running_loop()
                closed = asyncio.Event()
                observations: list[tuple[bool, str]] = []

                class PendingSource(ActiveSource):
                    async def aclose(self) -> None:
                        """Record the execution loop and context before signalling finalization."""
                        observations.append((asyncio.get_running_loop() is owner, marker.get()))
                        closed.set()

                marker.set("pending")
                try:
                    await StreamingResponse(PendingSource()).aclose()
                    main_loop.call_soon_threadsafe(queued.set)
                    await asyncio.wait_for(closed.wait(), 2)
                    assert observations == [(True, "pending")]
                finally:
                    main_loop.call_soon_threadsafe(release.set)
                    await _drain_stream_cleanups()

            asyncio.run(other_loop())

        task = None
        try:
            marker.set("active")
            await StreamingResponse(ActiveSource(), cleanup_timeout=0.001).aclose()
            task = asyncio.create_task(asyncio.to_thread(worker))
            await asyncio.wait_for(queued.wait(), 2)
        finally:
            release.set()
            try:
                if task is not None:
                    await asyncio.wait_for(task, 3)
            finally:
                await _drain_stream_cleanups()
        assert not streaming_module._pending_cleanups
        assert streaming_module._active_cleanups == 0

    asyncio.run(run())


class CountingMemoryStore(MemoryStore):
    def __init__(self) -> None:
        """Initialize counters for session reads and creation attempts."""
        super().__init__()
        self.get_calls = 0
        self.create_calls = 0

    async def get(self, key: str) -> bytes | None:
        """Count backend reads before delegating to the memory store."""
        self.get_calls += 1
        return await super().get(key)

    async def create(self, key: str, value: bytes, ttl: int) -> bool:
        """Count session creation attempts before delegating to the memory store."""
        self.create_calls += 1
        return await super().create(key, value, ttl)


def test_all_boolean_settings_reject_wrong_typed_values() -> None:
    """Reject wrongly typed boolean settings at every construction and mutation entry point."""
    boolean_settings = [name for name, annotation in get_type_hints(Settings).items() if annotation is bool]
    assert boolean_settings
    for name in boolean_settings:
        with pytest.raises(TypeError, match=rf"^{name} must be a bool\.$"):
            Settings.from_mapping({name: "false"})
        config_type = type("Config", (), {name: "false"})
        with pytest.raises(TypeError, match=rf"^{name} must be a bool\.$"):
            Settings.from_object(config_type())

    wrong_type: Any = "false"
    with pytest.raises(TypeError, match=r"^DEBUG must be a bool\.$"):
        Settings(DEBUG=wrong_type)

    assert Settings(DEBUG=False).DEBUG is False

    mutated = Settings()
    with pytest.raises(TypeError, match=r"^DEBUG must be a bool\.$"):
        mutated.DEBUG = wrong_type


def test_all_security_config_booleans_reject_wrong_typed_values() -> None:
    """Reject non-booleans when constructing or mutating security configuration."""
    boolean_settings = [name for name, annotation in get_type_hints(SecurityConfig).items() if annotation is bool]
    assert boolean_settings
    for name in boolean_settings:
        wrong_value: dict[str, Any] = {name: 0}
        with pytest.raises(TypeError, match=rf"^{name} must be a bool\.$"):
            SecurityConfig(**wrong_value)

    assert SecurityConfig(csrf_enabled=False).csrf_enabled is False

    mutated = SecurityConfig()
    wrong_security_type: Any = 0
    with pytest.raises(TypeError, match=r"^enforce_allowed_hosts must be a bool\.$"):
        mutated.enforce_allowed_hosts = wrong_security_type


@pytest.mark.parametrize(
    ("setting", "name"),
    [
        ("SESSION_COOKIE_NAME", "invalid session"),
        ("CSRF_COOKIE_NAME", "invalid=csrf"),
    ],
)
def test_invalid_cookie_names_fail_application_initialization(setting: str, name: str) -> None:
    """Reject invalid security-cookie names before the application can handle requests."""
    with pytest.raises(ValueError, match="Invalid cookie name"):
        Flasgo(settings={setting: name})


def test_duplicate_signed_session_cookie_is_treated_as_anonymous() -> None:
    """Treat duplicate signed session cookies as anonymous for HTTP and WebSocket requests."""
    app = Flasgo(settings={"CSRF_ENABLED": False, "SECRET_KEY": "s" * 32})

    @app.get("/identity")
    def identity() -> str:
        """Expose the current session identity for cookie ambiguity checks."""
        return str(session().get("identity", "anonymous"))

    valid = app._session_signer.dumps({"identity": "alice"})
    client = app.test_client()
    assert client.get("/identity", headers={"cookie": f"flasgo-session={valid}"}).text == "alice"
    assert (
        client.get(
            "/identity",
            headers={"cookie": f"flasgo-session=invalid; flasgo-session={valid}"},
        ).text
        == "anonymous"
    )
    assert (
        client.get(
            "/identity",
            headers=[("cookie", "flasgo-session=invalid"), ("cookie", f"flasgo-session={valid}")],
        ).text
        == "anonymous"
    )

    @app.websocket("/identity", public=True)
    async def websocket_identity(websocket: WebSocket) -> None:
        """Send the WebSocket session identity after accepting the connection."""
        await websocket.accept()
        active_session = websocket.scope["session"]
        await websocket.send_text(str(active_session.get("identity", "anonymous")))

    with (
        app.test_client() as websocket_client,
        websocket_client.websocket_connect(
            "/identity",
            headers={"cookie": f"flasgo-session=invalid; flasgo-session={valid}"},
        ) as websocket,
    ):
        assert websocket.receive_text() == "anonymous"


def test_duplicate_csrf_binding_values_are_rejected() -> None:
    """Reject repeated CSRF tokens, origins, and referers even when one value is valid."""
    app = Flasgo(settings={"SECRET_KEY": "s" * 32})

    @app.get("/seed")
    def seed() -> str:
        """Serve a safe request that issues the initial CSRF cookie."""
        return "seed"

    @app.post("/submit")
    def submit() -> str:
        """Return success only if the request passes CSRF validation."""
        return "ok"

    client = app.test_client()
    seed_response = client.get("/seed")
    csrf_cookie = next(
        part.split("=", 1)[1] for part in seed_response.headers["set-cookie"].split("\n") if part.startswith("flasgo-csrf=")
    ).split(";", 1)[0]
    accepted = client.post(
        "/submit",
        headers=[
            ("cookie", f"flasgo-csrf={csrf_cookie}"),
            ("x-csrf-token", csrf_cookie),
            ("origin", "http://localhost"),
        ],
    )
    assert accepted.status_code == 200
    response = client.post(
        "/submit",
        headers=[
            ("cookie", f"flasgo-csrf={csrf_cookie}"),
            ("x-csrf-token", csrf_cookie),
            ("x-csrf-token", csrf_cookie),
            ("origin", "http://localhost"),
        ],
    )
    assert response.status_code == 403

    duplicate_origin = client.post(
        "/submit",
        headers=[
            ("cookie", f"flasgo-csrf={csrf_cookie}"),
            ("x-csrf-token", csrf_cookie),
            ("origin", "https://attacker.example"),
            ("origin", "http://localhost"),
        ],
    )
    assert duplicate_origin.status_code == 403

    duplicate_referer = client.post(
        "/submit",
        headers=[
            ("cookie", f"flasgo-csrf={csrf_cookie}"),
            ("x-csrf-token", csrf_cookie),
            ("referer", "https://attacker.example/path"),
            ("referer", "http://localhost/form"),
        ],
    )
    assert duplicate_referer.status_code == 403


def test_session_mutations_from_failed_handlers_are_not_committed() -> None:
    """Roll back raised-handler mutations while preserving deliberate error responses."""
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.get("/fail")
    def fail() -> str:
        """Mutate the session and raise to exercise rollback."""
        session()["failed"] = True
        raise RuntimeError("boom")

    @app.get("/explicit-error")
    def explicit_error() -> Response:
        """Return an intentional error response after a session mutation."""
        session()["explicit"] = True
        return Response.text("bad request", status_code=400)

    @app.get("/state")
    def state() -> dict[str, bool]:
        """Expose persisted flags without mutating the session."""
        return {
            "failed": bool(session().get("failed")),
            "explicit": bool(session().get("explicit")),
        }

    client = app.test_client()
    assert client.get("/fail").status_code == 500
    assert client.get("/state").json() == {"failed": False, "explicit": False}
    assert client.get("/explicit-error").status_code == 400
    assert client.get("/state").json() == {"failed": False, "explicit": True}


def test_failed_handler_does_not_create_server_session() -> None:
    """Avoid creating a backend session for a handler that mutates state and then raises."""
    store = CountingMemoryStore()
    app = Flasgo(settings={"CSRF_ENABLED": False}, session_backend=ServerSideSessions(store))

    @app.get("/fail")
    def fail() -> str:
        """Attempt a privileged session mutation before failing."""
        session()["admin"] = True
        raise RuntimeError("boom")

    assert app.test_client().get("/fail").status_code == 500
    assert store.create_calls == 0


def test_successful_error_handler_can_commit_session_revocation() -> None:
    """Allow a successful error handler to revoke the restored session."""
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.get("/seed")
    def seed() -> str:
        """Establish an authenticated session before the revocation request."""
        session()["identity"] = "alice"
        return "ok"

    @app.get("/revoke")
    def revoke() -> str:
        """Stage a mutation that must be discarded before the error handler runs."""
        session()["failed_mutation"] = True
        raise PermissionError("revoked")

    @app.errorhandler(PermissionError)
    def handle_revoke(request: Request, error: Exception) -> Response:
        """Verify rollback and clear the session as a deliberate revocation."""
        assert isinstance(error, PermissionError)
        assert session().get("failed_mutation") is None
        session().clear()
        return Response.text("revoked", status_code=401)

    @app.get("/identity")
    def identity() -> str:
        """Expose the remaining identity after error-handler revocation."""
        return str(session().get("identity", "anonymous"))

    client = app.test_client()
    assert client.get("/seed").status_code == 200
    assert client.get("/identity").text == "alice"
    assert client.get("/revoke").status_code == 401
    assert client.get("/identity").text == "anonymous"


def test_invalid_final_response_does_not_write_server_session() -> None:
    """Validate outgoing headers before committing server-side session changes."""
    store = CountingMemoryStore()
    app = Flasgo(settings={"CSRF_ENABLED": False}, session_backend=ServerSideSessions(store))

    @app.get("/invalid")
    def invalid() -> Response:
        """Combine a privileged mutation with an invalid outgoing header."""
        session()["admin"] = True
        response = Response.text("ok")
        response.headers["x-invalid"] = "value\nsmuggled"
        return response

    response = app.test_client().get("/invalid")
    assert response.status_code == 500
    assert store.create_calls == 0


def test_oversized_request_head_bypasses_telemetry_and_untrusted_request_id() -> None:
    """Reject oversized heads without invoking tracing or reusing an attacker request ID."""
    app = Flasgo(
        settings={
            "CSRF_ENABLED": False,
            "MAX_REQUEST_HEAD_BYTES": 128,
            "TRUST_INCOMING_REQUEST_ID": True,
        }
    )
    telemetry_calls = 0

    async def telemetry(scope: dict[str, Any], receive: Any, send: Any) -> None:
        """Count unexpected tracing calls for rejected request heads."""
        nonlocal telemetry_calls
        telemetry_calls += 1

    replacement: Any = telemetry
    app._telemetry = replacement
    response = app.test_client().get(
        "/",
        headers={"x-padding": "x" * 256, "x-request-id": "attacker-controlled"},
    )
    assert response.status_code == 431
    assert telemetry_calls == 0
    assert response.headers["x-request-id"] != "attacker-controlled"


def test_request_head_at_exact_limit_is_accepted() -> None:
    """Accept an ASGI request whose measured head equals the configured byte limit."""
    scope: dict[str, Any] = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": [(b"host", b"localhost")],
        "client": ("127.0.0.1", 1234),
        "server": ("localhost", 80),
    }
    app = Flasgo(settings={"CSRF_ENABLED": False, "MAX_REQUEST_HEAD_BYTES": _request_head_size(scope)})

    @app.get("/")
    def index() -> str:
        """Return a success body for the request exactly at the head limit."""
        return "ok"

    async def run() -> list[dict[str, Any]]:
        """Dispatch the exact-limit scope and collect ASGI response messages."""
        messages: list[dict[str, Any]] = []

        async def receive() -> dict[str, Any]:
            """Supply an empty, completed HTTP request body."""
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message: dict[str, Any]) -> None:
            """Capture ASGI output for the response status assertion."""
            messages.append(message)

        await app(scope, receive, send)  # type: ignore[arg-type]
        return messages

    messages = asyncio.run(run())
    assert messages[0]["status"] == 200


def test_rejected_websocket_heads_and_origins_do_not_load_sessions() -> None:
    """Reject invalid WebSocket heads, hosts, and origins before any session read."""
    store = CountingMemoryStore()
    app = Flasgo(
        settings={"CSRF_ENABLED": False, "MAX_REQUEST_HEAD_BYTES": 256},
        session_backend=ServerSideSessions(store),
    )

    @app.websocket("/socket", public=True)
    async def socket(websocket: WebSocket) -> None:
        """Accept the connection only if all handshake checks succeed."""
        await websocket.accept()

    with app.test_client() as client:
        with pytest.raises(WebSocketHandshakeError) as oversized, client.websocket_connect("/socket", headers={"x-padding": "x" * 512}):
            pass
        assert oversized.value.status_code == 431

        with (
            pytest.raises(WebSocketHandshakeError) as bad_origin,
            client.websocket_connect(
                "/socket",
                origin="https://attacker.example",
                headers={"cookie": f"flasgo-session={'a' * 43}"},
            ),
        ):
            pass
        assert bad_origin.value.status_code == 403

        with (
            pytest.raises(WebSocketHandshakeError) as bad_host,
            client.websocket_connect(
                "/socket",
                headers={"host": "attacker.example", "cookie": f"flasgo-session={'a' * 43}"},
            ),
        ):
            pass
        assert bad_host.value.status_code == 400

    assert store.get_calls == 0


def test_websocket_client_rate_limit_runs_before_session_storage() -> None:
    """Apply the WebSocket client rate limit before reading a supplied session identifier."""
    store = CountingMemoryStore()
    app = Flasgo(settings={"CSRF_ENABLED": False}, session_backend=ServerSideSessions(store))

    @app.websocket("/limited", public=True)
    @app.ratelimit(1, per=60)
    async def limited(websocket: WebSocket) -> None:
        """Accept the first connection under a one-request rate limit."""
        await websocket.accept()

    with app.test_client() as client:
        with client.websocket_connect("/limited"):
            pass
        with (
            pytest.raises(WebSocketHandshakeError) as denied,
            client.websocket_connect(
                "/limited",
                headers={"cookie": f"flasgo-session={'a' * 43}"},
            ),
        ):
            pass
        assert denied.value.status_code == 429

    assert store.get_calls == 0


def test_security_failure_tracking_is_bounded_and_reuses_expired_capacity(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bound failure-tracking identities and reclaim expired capacity without evicting live entries."""
    app = Flasgo(settings={"CSRF_ENABLED": False})
    now = 0.0
    monkeypatch.setattr(app_module.time, "monotonic", lambda: now)

    async def receive() -> dict[str, Any]:
        """Supply an empty body for synthetic security-failure requests."""
        return {"type": "http.request", "body": b"", "more_body": False}

    def request_for(identity: str) -> Request:
        """Build a request associated with the supplied client identity."""
        return Request(
            {
                "type": "http",
                "path": "/",
                "method": "GET",
                "headers": [],
                "client": (identity, 443),
            },
            receive,
        )

    for index in range(10_000):
        assert app._register_security_failure(request_for(f"client-{index}")) is False
    assert len(app._security_throttle._clients) == 10_000
    assert app._register_security_failure(request_for("overflow")) is True
    assert len(app._security_throttle._clients) == 10_000
    assert "client-0" in app._security_throttle._clients

    now = 61.0
    assert app._register_security_failure(request_for("after-expiry")) is False
    assert list(app._security_throttle._clients) == ["after-expiry"]


def test_route_registration_rejects_equivalent_shapes_and_prefers_specific_routes() -> None:
    """Reject ambiguous route contracts while preserving specific routes and atomic blueprint registration."""
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.get("/<path:value>")
    def catch_all(value: str) -> str:
        """Expose catch-all dispatch without requiring authentication."""
        return f"public:{value}"

    @app.get("/admin")
    @app.authorize(IsAuthenticated())
    def admin() -> str:
        """Provide the protected static route that must take precedence over the catch-all."""
        return "secret"

    @app.get("/items/<int:item_id>")
    def numeric_item(item_id: int) -> str:
        """Identify successful dispatch through an integer converter."""
        return f"numeric:{item_id}"

    @app.get("/records/<value>")
    def string_item(value: str) -> str:
        """Identify successful dispatch through a string converter."""
        return f"string:{value}"

    assert app.test_client().get("/admin").status_code == 401
    assert app.test_client().get("/items/7").text == "numeric:7"
    assert app.test_client().get("/records/name").text == "string:name"

    with pytest.raises(ValueError, match="conflicts with an existing route pattern"):

        @app.get("/records/<other>")
        def duplicate_shape(other: str) -> str:
            """Provide a renamed parameter that must fail duplicate-shape registration."""
            return other

    with pytest.raises(ValueError, match="conflicts with an existing route pattern"):

        @app.post("/records/<other>")
        def renamed_disjoint_method(other: str) -> str:
            """Provide inconsistent parameter naming even though its HTTP method is disjoint."""
            return other

    @app.post("/records/<value>")
    def same_shape_and_parameter(value: str) -> str:
        """Reuse the established parameter contract for a disjoint HTTP method."""
        return value

    @app.get("/<path:value>/admin")
    def ambiguous_public(value: str) -> str:
        """Register the public member of an intersecting equal-specificity route pair."""
        return f"public:{value}"

    with pytest.raises(ValueError, match="conflicts with an existing route pattern"):

        @app.get("/users/<path:value>")
        @app.authorize(IsAuthenticated())
        def ambiguous_protected(value: str) -> str:
            """Provide the protected member whose ambiguous registration must fail."""
            return f"protected:{value}"

    blueprint = Blueprint("conflicting")

    @blueprint.get("/records/<renamed>")
    def blueprint_duplicate(renamed: str) -> str:
        """Introduce a blueprint conflict to verify registration rolls back atomically."""
        return renamed

    routes_before = tuple(app._routes)
    with pytest.raises(ValueError, match="conflicts with an existing route pattern"):
        app.register_blueprint(blueprint)
    assert tuple(app._routes) == routes_before

    @app.get("/numbers/<int:value>")
    def integer_value(value: int) -> str:
        """Register the integer route before attempting an overlapping float contract."""
        return str(value)

    with pytest.raises(ValueError, match="conflicts with an existing route pattern"):

        @app.get("/numbers/<float:value>")
        def overlapping_float(value: float) -> str:
            """Provide a float route whose language includes the existing integer route."""
            return str(value)


def test_websocket_route_shapes_and_multiple_path_converters_are_rejected() -> None:
    """Reject equivalent WebSocket shapes and multiple greedy converters in both protocols."""
    app = Flasgo(settings={"CSRF_ENABLED": False})

    async def endpoint(websocket: WebSocket, **params: str) -> None:
        """Accept a WebSocket connection for route-registration fixtures."""
        await websocket.accept()

    app.add_websocket_route("/socket/<room>", endpoint, public=True)
    with pytest.raises(ValueError, match="conflicts with an existing route pattern"):
        app.add_websocket_route("/socket/<channel>", endpoint, public=True)
    with pytest.raises(ValueError, match="at most one path converter"):
        app.add_websocket_route("/<path:first>/<path:second>", endpoint, public=True)
    with pytest.raises(ValueError, match="at most one path converter"):
        app.get("/<path:first>/<path:second>")(lambda first, second: first + second)

    @app.get("/archive/<path:directory>/download")
    def download(directory: str) -> str:
        """Expose a valid single greedy converter followed by a literal suffix."""
        return directory

    assert app.test_client().get("/archive/a/b/download").text == "a/b"


def test_stream_cleanup_timeout_bounds_cancellation_resistant_closers() -> None:
    """Bound direct and response-send cleanup even when a producer ignores cancellation."""

    class ResistantStream:
        def __init__(self) -> None:
            """Create a release event that controls the resistant closer."""
            self.release = asyncio.Event()

        def __aiter__(self) -> ResistantStream:
            """Return this stream as its async iterator."""
            return self

        async def __anext__(self) -> bytes:
            """Exhaust the stream immediately to isolate finalizer timing."""
            raise StopAsyncIteration

        async def aclose(self) -> None:
            """Keep finalization pending after cancellation until the test releases it."""
            try:
                await self.release.wait()
            except asyncio.CancelledError:
                await self.release.wait()

    async def run() -> None:
        """Exercise direct cleanup, send teardown, and NDJSON timeout forwarding."""
        source = ResistantStream()
        response = StreamingResponse(source, cleanup_timeout=0.01)
        try:
            await asyncio.wait_for(response.aclose(), timeout=0.1)
            assert response._metrics_outcome == "cleanup_timeout"
        finally:
            source.release.set()
            await _drain_stream_cleanups()

        streamed_source = ResistantStream()
        streamed_response = StreamingResponse(streamed_source, cleanup_timeout=0.01)

        async def send(message: dict[str, Any]) -> None:
            """Accept ASGI output without adding transport delay."""
            return

        try:
            await asyncio.wait_for(streamed_response.send(send), timeout=0.1)
            assert streamed_response._metrics_outcome == "cleanup_timeout"
        finally:
            streamed_source.release.set()
            await _drain_stream_cleanups()

        async def items() -> AsyncIterator[object]:
            """Yield one JSON-serializable item for the NDJSON configuration check."""
            yield {"ok": True}

        assert NDJSONResponse(items(), cleanup_timeout=0.25).cleanup_timeout == 0.25

    asyncio.run(run())


@pytest.mark.parametrize("disconnect", [False, True])
def test_stream_teardown_is_bounded_after_duration_or_disconnect(disconnect: bool) -> None:
    """Bound teardown after duration expiry or disconnect despite a resistant producer."""

    class ResistantProducer:
        def __init__(self) -> None:
            """Create the event that eventually unblocks item production."""
            self.release = asyncio.Event()

        def __aiter__(self) -> ResistantProducer:
            """Return this cancellation-resistant producer as its iterator."""
            return self

        async def __anext__(self) -> bytes:
            """Ignore one cancellation and exhaust only after explicit release."""
            try:
                await self.release.wait()
            except asyncio.CancelledError:
                await self.release.wait()
            raise StopAsyncIteration

    async def run() -> None:
        """Trigger the selected termination path and verify bounded response teardown."""
        source = ResistantProducer()
        response = StreamingResponse(source, max_duration=0.01, cleanup_timeout=0.01)

        async def receive() -> dict[str, Any]:
            """Deliver a disconnect or remain idle until the response duration expires."""
            if disconnect:
                return {"type": "http.disconnect"}
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

        async def send(message: dict[str, Any]) -> None:
            """Accept response messages without affecting the producer deadline."""
            return

        response.receive = receive
        expected = ConnectionError if disconnect else TimeoutError
        try:
            with pytest.raises(expected):
                await asyncio.wait_for(response.send(send), timeout=0.1)
        finally:
            source.release.set()
            await _drain_stream_cleanups()

    asyncio.run(run())


def test_nested_stream_cleanup_is_observed_when_outer_cleanup_is_cancelled() -> None:
    """Consume late finalizer exceptions when outer teardown has already been cancelled."""

    class ResistantCloser:
        def __init__(self) -> None:
            """Create an event controlling the finalizer that will eventually fail."""
            self.release = asyncio.Event()

        def __aiter__(self) -> ResistantCloser:
            """Return this stream as its async iterator."""
            return self

        async def __anext__(self) -> bytes:
            """Remain blocked in production until response teardown cancels the task."""
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

        async def aclose(self) -> None:
            """Survive cancellation and then raise a late cleanup failure after release."""
            try:
                await self.release.wait()
            except asyncio.CancelledError:
                await self.release.wait()
            raise RuntimeError("cleanup failed after cancellation")

    async def run() -> None:
        """Observe loop errors while disconnecting and releasing the detached finalizer."""
        source = ResistantCloser()
        response = StreamingResponse(source, cleanup_timeout=0.01)
        observed: list[dict[str, Any]] = []
        loop = asyncio.get_running_loop()
        previous_handler = loop.get_exception_handler()
        loop.set_exception_handler(lambda _loop, context: observed.append(context))

        async def receive() -> dict[str, Any]:
            """Immediately disconnect the client to trigger nested response teardown."""
            return {"type": "http.disconnect"}

        async def send(message: dict[str, Any]) -> None:
            """Accept transport output without introducing additional failures."""
            return

        response.receive = receive
        try:
            with pytest.raises(ConnectionError):
                await asyncio.wait_for(response.send(send), timeout=0.1)
            source.release.set()
            await _drain_stream_cleanups()
            assert observed == []
        finally:
            source.release.set()
            try:
                await _drain_stream_cleanups()
            finally:
                loop.set_exception_handler(previous_handler)

    asyncio.run(run())


def test_cancellation_resistant_cleanup_has_a_hard_process_limit() -> None:
    """Cap active finalizers and automatically drain accepted pending cleanup exactly once."""

    class ResistantCloser:
        entered = 0

        def __init__(self, release: asyncio.Event) -> None:
            """Bind each closer to the shared event that releases active capacity."""
            self.release = release

        def __aiter__(self) -> ResistantCloser:
            """Return this closer as its own async iterator."""
            return self

        async def __anext__(self) -> bytes:
            """Exhaust immediately so only cleanup consumes concurrency slots."""
            raise StopAsyncIteration

        async def aclose(self) -> None:
            """Count finalizer admission and hold capacity through cancellation until release."""
            type(self).entered += 1
            try:
                await self.release.wait()
            except asyncio.CancelledError:
                await self.release.wait()

    async def run() -> None:
        """Fill active capacity, queue two responses, and verify every accepted closer runs once."""
        release = asyncio.Event()
        responses = [
            StreamingResponse(ResistantCloser(release), cleanup_timeout=0.001) for _ in range(streaming_module._MAX_ACTIVE_CLEANUPS + 2)
        ]
        try:
            for response in responses:
                await response.aclose()
            assert ResistantCloser.entered == streaming_module._MAX_ACTIVE_CLEANUPS
            assert streaming_module._active_cleanups == streaming_module._MAX_ACTIVE_CLEANUPS
            assert len(streaming_module._pending_cleanups) == 2
            for response in responses[-2:]:
                await response.aclose()
            assert len(streaming_module._pending_cleanups) == 2
        finally:
            release.set()
            await _drain_stream_cleanups()
        assert streaming_module._active_cleanups == 0
        assert ResistantCloser.entered == streaming_module._MAX_ACTIVE_CLEANUPS + 2
        assert not streaming_module._pending_cleanups
        assert all(response._closed for response in responses)

    asyncio.run(run())


@pytest.mark.parametrize(
    "host",
    [
        "attacker.com?.example.com",
        "attacker.com#.example.com",
        "attacker.com .example.com",
        "attacker.com%2f.example.com",
        "[evil].example.com",
        "example.com",
        # IPv6 zone IDs accept arbitrary text; a browser reads this link as userinfo "[::1%" at host evil.com.
        "[::1%@evil.com#.example.com]",
        "[::1%@evil.com#.example.com]:443",
        "[::1%.example.com]",
        "[::ffff:127.0.0.1%25x.example.com]",
    ],
)
def test_suffix_host_patterns_reject_url_delimiter_smuggling(host: str) -> None:
    """Only real DNS names may match a suffix pattern; URL delimiters must not smuggle in another host."""
    app = Flasgo(settings={"ALLOWED_HOSTS": {".example.com"}, "CSRF_ENABLED": False})

    @app.get("/")
    def home() -> str:
        return "ok"

    assert app.test_client().get("/", headers={"host": host}).status_code == 400


@pytest.mark.parametrize("host", ["api.example.com", "API.Example.com:8443", "a.b.example.com.", "my_service.example.com"])
def test_suffix_host_patterns_allow_real_subdomains(host: str) -> None:
    """Keep matching ordinary subdomains, ports, trailing dots, and underscore service names."""
    app = Flasgo(settings={"ALLOWED_HOSTS": {".example.com"}, "CSRF_ENABLED": False})

    @app.get("/")
    def home() -> str:
        return "ok"

    assert app.test_client().get("/", headers={"host": host}).status_code == 200


def test_mixed_case_response_headers_replace_instead_of_duplicating() -> None:
    """Flask-style header assignment must not emit conflicting framing or security headers."""
    app = Flasgo()

    @app.get("/")
    def home() -> Response:
        response = Response.html("<p>hi</p>", headers={"X-Frame-Options": "SAMEORIGIN"})
        response.headers["Content-Type"] = "application/json"
        response.headers["Content-Length"] = "999"
        return response

    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": [(b"host", b"localhost")],
        "client": ("127.0.0.1", 1),
        "server": ("localhost", 80),
        "root_path": "",
    }
    asyncio.run(app(scope, receive, send))

    names = [name.lower() for name, _ in sent[0]["headers"]]
    assert len(names) == len(set(names))
    headers = dict(sent[0]["headers"])
    assert headers[b"content-type"] == b"application/json"
    assert headers[b"content-length"] == b"9"
    assert headers[b"x-frame-options"] == b"SAMEORIGIN"


def test_response_headers_are_case_insensitive() -> None:
    response = Response.text("ok", headers={"X-Custom": "1"})
    response.headers.update({"x-CUSTOM": "2"})
    response.headers |= {"X-Other": "3"}
    assert response.headers["X-CUSTOM"] == "2"
    assert "X-OTHER" in response.headers
    assert response.headers.pop("X-Other") == "3"
    response.headers = {"Content-Type": "text/csv"}
    response.prepare()
    assert response.headers["content-type"] == "text/csv"
    assert list(response.headers) == ["content-type", "content-length"]


def test_session_supports_mapping_protocol() -> None:
    """Flask idioms such as ``"user" in session`` must work instead of raising KeyError(0)."""
    from flasgo.session import Session

    current = Session({"user": 1})
    assert "user" in current
    assert "missing" not in current
    assert list(current) == ["user"]
    assert len(current) == 1
    assert not Session({})
    assert current.setdefault("theme", "dark") == "dark"
    assert current.modified
    del current["theme"]
    assert dict(current.items()) == {"user": 1}


def test_session_pop_of_missing_key_does_not_mark_modified() -> None:
    """Consuming an absent flash message on every page must not re-sign the cookie or rotate the CSRF binding."""
    from flasgo.session import Session

    current = Session({"user": 1})
    assert current.pop("flash", None) is None
    assert not current.modified
    assert current.pop("user") == 1
    assert current.modified


def test_session_proxy_forwards_attribute_writes_to_the_request_session() -> None:
    """``session.modified = True`` must reach the request's session rather than the shared module-level proxy."""
    import flasgo.globals as globals_module

    app = Flasgo(settings={"CSRF_ENABLED": False})
    observed: list[bool] = []

    @app.get("/mark")
    def mark() -> str:
        session.modified = True
        return "ok"

    @app.get("/check")
    def check() -> str:
        observed.append(session.modified)
        return "ok"

    client = app.test_client()
    marked = client.get("/mark")
    assert "set-cookie" in marked.headers
    client.get("/check")
    assert observed == [False]
    assert "modified" not in object.__dir__(globals_module.session)


def test_session_proxy_supports_container_operations() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.get("/")
    def home() -> dict[str, Any]:
        session["a"] = 1
        session["b"] = 2
        del session["b"]
        return {"has_a": "a" in session, "has_b": "b" in session, "keys": list(session), "size": len(session), "truthy": bool(session)}

    assert app.test_client().get("/").json() == {"has_a": True, "has_b": False, "keys": ["a"], "size": 1, "truthy": True}


@pytest.mark.parametrize(
    "app_factory",
    [
        lambda: Flasgo(settings={"ENFORCE_NO_STORE_CACHE": False}),
        lambda: Flasgo(security=SecurityConfig(enforce_no_store_cache=False)),
    ],
    ids=["settings", "security-config"],
)
def test_disabling_no_store_cache_is_honoured_by_every_config_path(app_factory: Any) -> None:
    """A directly built SecurityConfig used to carry cache headers in its defaults, so the opt-out had no effect."""
    app = app_factory()

    @app.get("/")
    def home() -> str:
        return "ok"

    response = app.test_client().get("/")
    assert "cache-control" not in response.headers
    assert "pragma" not in response.headers
    assert response.headers["x-frame-options"] == "DENY"
    assert SecurityConfig().security_headers == Settings().SECURITY_HEADERS


@pytest.mark.parametrize(
    ("trusted", "origin", "expected"),
    [
        ("https://partner.example.com", "https://partner.example.com", True),
        ("https://partner.example.com/", "https://partner.example.com", True),
        ("https://partner.example.com:443", "https://partner.example.com", True),
        ("https://partner.example.com", "http://partner.example.com", False),
        ("https://*.example.com", "https://api.example.com", True),
        ("https://*.example.com", "http://api.example.com", False),
        ("https://*.example.com", "https://example.com", False),
        (".example.com", "https://api.example.com", True),
        (".example.com", "http://evil.example.com", False),
        ("partner.example.com", "https://partner.example.com", True),
        ("partner.example.com", "http://partner.example.com", False),
    ],
)
def test_csrf_trusted_origins_respect_scheme_and_canonical_form(trusted: str, origin: str, expected: bool) -> None:
    """Bare entries must not trust plain-HTTP origins on an HTTPS app, and exact entries tolerate a trailing slash."""
    from types import SimpleNamespace

    from flasgo.security import _origin_matches_request

    request = SimpleNamespace(scheme="https", headers={"host": "app.example.org"})
    config = SecurityConfig(csrf_trusted_origins={trusted})
    assert _origin_matches_request(origin, cast(Any, request), config) is expected


@pytest.mark.parametrize(
    ("origin", "expected"),
    [
        ("https://app.example.org", True),
        ("https://app.example.org:443", True),
        ("https://app.example.org/some/referer?path", True),
        ("http://app.example.org", False),
        ("null", False),
        ("https://[::1", False),
    ],
)
def test_csrf_same_origin_comparison_is_canonical(origin: str, expected: bool) -> None:
    from types import SimpleNamespace

    from flasgo.security import _origin_matches_request

    request = SimpleNamespace(scheme="https", headers={"host": "APP.example.org"})
    assert _origin_matches_request(origin, cast(Any, request), SecurityConfig()) is expected


@pytest.mark.parametrize("max_age", [0, -1, True, "3600"])
def test_session_cookie_max_age_must_be_positive(max_age: object) -> None:
    with pytest.raises(ValueError, match="SESSION_COOKIE_MAX_AGE must be a positive"):
        Flasgo(settings={"SESSION_COOKIE_MAX_AGE": max_age})


@pytest.mark.parametrize("pattern", ["*", "*.example.com", "exa mple.com", "evil.com/path"])
def test_allowed_hosts_rejects_unsupported_patterns(pattern: str) -> None:
    """``"*"`` looked like "allow any host" but matched nothing, so every request failed with 400."""
    with pytest.raises(ValueError, match="ALLOWED_HOSTS entry"):
        Flasgo(settings={"ALLOWED_HOSTS": {pattern}})


def test_settings_get_only_returns_settings_fields() -> None:
    settings = Settings(EXTRA={"custom": 1})
    assert settings.get("DEBUG") is False
    assert settings.get("custom") == 1
    assert settings.get("to_security_config") is None
    assert settings.get("get", "fallback") == "fallback"


def test_cookie_expires_is_locale_independent() -> None:
    from datetime import UTC, datetime

    from flasgo.security import _format_http_date

    assert _format_http_date(datetime(2026, 1, 5, 12, 0, tzinfo=UTC)) == "Mon, 05 Jan 2026 12:00:00 GMT"


def test_settings_subclass_bool_fields_are_checked_on_assignment() -> None:
    """Assignment checks used the concrete class's own annotations only, missing inherited and subclass fields."""
    from dataclasses import dataclass

    @dataclass
    class AppSettings(Settings):
        FEATURE_ENABLED: bool = False

    settings = AppSettings()
    with pytest.raises(TypeError, match="FEATURE_ENABLED must be a bool"):
        setattr(settings, "FEATURE_ENABLED", "yes")  # noqa: B010 - bypass static typing on purpose
    with pytest.raises(TypeError, match="DEBUG must be a bool"):
        setattr(settings, "DEBUG", "false")  # noqa: B010 - bypass static typing on purpose


@pytest.mark.parametrize("host", ["[::1%eth0]", "[::1%25eth0]:8000", "[fe80::1%lo]"])
def test_ipv6_hosts_with_zone_ids_are_rejected(host: str) -> None:
    """Zone IDs have no meaning in a Host header and must not match an allowed IPv6 address."""
    app = Flasgo(settings={"ALLOWED_HOSTS": {"::1", "fe80::1"}, "CSRF_ENABLED": False})

    @app.get("/")
    def home() -> str:
        return "ok"

    client = app.test_client()
    assert client.get("/", headers={"host": host}).status_code == 400
    assert client.get("/", headers={"host": "[::1]:8000"}).status_code == 200


def test_allowed_hosts_rejects_ipv6_zone_id_patterns() -> None:
    with pytest.raises(ValueError, match="ALLOWED_HOSTS entry"):
        Flasgo(settings={"ALLOWED_HOSTS": {"::1%eth0"}})


def test_suffix_patterns_never_match_ipv6_literals() -> None:
    from flasgo.security import host_is_allowed

    assert not host_is_allowed("[::1]", allowed_hosts={".example.com"})
    assert host_is_allowed("[::1]", allowed_hosts={"::1"})
