from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextvars import ContextVar
from typing import Any, get_type_hints

import flasgo.app as app_module
import flasgo.streaming as streaming_module
import pytest
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
from flasgo.security import SecurityConfig


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
        return None

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
            for _ in range(20):
                await asyncio.sleep(0)
                if streaming_module._active_cleanups == 0:
                    break
            assert entered == ["active", "pending", "underlying"]
            assert not streaming_module._pending_cleanups
            assert streaming_module._active_cleanups == 0
            await overflow.aclose()
            assert entered == ["active", "pending", "underlying", "overflow"]
            assert observed == []
        finally:
            release.set()
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

        marker.set("active")
        await StreamingResponse(ActiveSource(), cleanup_timeout=0.001).aclose()

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
                await StreamingResponse(PendingSource()).aclose()
                main_loop.call_soon_threadsafe(queued.set)
                await asyncio.wait_for(closed.wait(), 2)
                assert observations == [(True, "pending")]

            asyncio.run(other_loop())

        task = asyncio.create_task(asyncio.to_thread(worker))
        try:
            await asyncio.wait_for(queued.wait(), 2)
        finally:
            release.set()
        await asyncio.wait_for(task, 3)
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
    assert len(app._security_failures) == 10_000
    assert app._register_security_failure(request_for("overflow")) is True
    assert len(app._security_failures) == 10_000
    assert "client-0" in app._security_failures

    now = 61.0
    assert app._register_security_failure(request_for("after-expiry")) is False
    assert list(app._security_failures) == ["after-expiry"]


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
        await asyncio.wait_for(response.aclose(), timeout=0.1)
        assert response._metrics_outcome == "cleanup_timeout"
        source.release.set()
        await asyncio.sleep(0)

        streamed_source = ResistantStream()
        streamed_response = StreamingResponse(streamed_source, cleanup_timeout=0.01)

        async def send(message: dict[str, Any]) -> None:
            """Accept ASGI output without adding transport delay."""
            return None

        await asyncio.wait_for(streamed_response.send(send), timeout=0.1)
        assert streamed_response._metrics_outcome == "cleanup_timeout"
        streamed_source.release.set()
        await asyncio.sleep(0)

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
            return None

        response.receive = receive
        expected = ConnectionError if disconnect else TimeoutError
        with pytest.raises(expected):
            await asyncio.wait_for(response.send(send), timeout=0.1)
        source.release.set()
        await asyncio.sleep(0)

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
            return None

        response.receive = receive
        try:
            with pytest.raises(ConnectionError):
                await asyncio.wait_for(response.send(send), timeout=0.1)
            source.release.set()
            await asyncio.sleep(0.01)
            assert observed == []
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
        for response in responses:
            await response.aclose()
        assert ResistantCloser.entered == streaming_module._MAX_ACTIVE_CLEANUPS
        assert streaming_module._active_cleanups == streaming_module._MAX_ACTIVE_CLEANUPS
        assert len(streaming_module._pending_cleanups) == 2
        for response in responses[-2:]:
            await response.aclose()
        assert len(streaming_module._pending_cleanups) == 2
        release.set()
        for _ in range(10):
            if streaming_module._active_cleanups == 0:
                break
            await asyncio.sleep(0)
        assert streaming_module._active_cleanups == 0
        assert ResistantCloser.entered == streaming_module._MAX_ACTIVE_CLEANUPS + 2
        assert not streaming_module._pending_cleanups
        assert all(response._closed for response in responses)

    asyncio.run(run())
