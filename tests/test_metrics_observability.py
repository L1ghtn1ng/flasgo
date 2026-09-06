import asyncio
import builtins
from collections.abc import AsyncIterator
from typing import Annotated, Any

import pytest
from flasgo import (
    Depends,
    EventSourceResponse,
    Flasgo,
    MemoryStore,
    Request,
    Response,
    ServerSideSessions,
    StoreUnavailable,
    StreamingResponse,
)
from flasgo.metrics import Metrics
from flasgo.ratelimit import RateLimiter
from prometheus_client import Counter, Gauge, Histogram
from prometheus_client.openmetrics.parser import text_string_to_metric_families as parse_openmetrics
from prometheus_client.parser import text_string_to_metric_families as parse_prometheus

_TOKEN = "observability-test-" + "m" * 32


def _app(**settings: Any) -> Flasgo:
    return Flasgo(settings={"METRICS_ENABLED": True, "METRICS_BEARER_TOKEN": _TOKEN, "CSRF_ENABLED": False, **settings})


def _sample(app: Flasgo, name: str, **labels: str) -> float | None:
    registry = app.metrics_registry
    assert registry is not None
    return registry.get_sample_value("flasgo_" + name, labels)


def _scope(path: str = "/", method: str = "GET") -> dict[str, Any]:
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [(b"host", b"localhost")],
        "client": ("127.0.0.1", 50000),
        "server": ("localhost", 80),
    }


async def _send(message: dict[str, Any]) -> None:
    pass


def _receive():
    received = False

    async def receive() -> dict[str, Any]:
        nonlocal received
        if not received:
            received = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    return receive


def test_public_registry_is_optional_isolated_and_rejects_duplicates(monkeypatch: pytest.MonkeyPatch) -> None:
    first, second = _app(), _app()
    registry = first.metrics_registry
    assert registry is not None
    counter = Counter("application_operations_total", "Operations.", registry=registry)
    counter.inc()
    Gauge("application_pending", "Pending.", registry=registry).set(2)
    Histogram("application_duration_seconds", "Duration.", registry=registry).observe(0.1)
    with pytest.raises(ValueError, match="Duplicated"):
        Counter("application_operations_total", "Duplicate.", registry=registry)
    headers = {"authorization": f"Bearer {_TOKEN}"}
    for accept, parser in (("text/plain", parse_prometheus), ("application/openmetrics-text; version=1.0.0", parse_openmetrics)):
        response = first.test_client().get("/metrics", headers={**headers, "accept": accept})
        assert response.status_code == 200
        families = list(parser(response.text))
        assert any(family.name == "application_operations" for family in families)
    assert "application_operations" not in second.test_client().get("/metrics", headers=headers).text
    original_import = builtins.__import__

    def restricted_import(name, *args, **kwargs):
        if name.startswith("prometheus_client"):
            raise ImportError("metrics extra unavailable")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", restricted_import)
    disabled = Flasgo(settings={"CSRF_ENABLED": False})
    assert disabled.metrics_registry is None
    assert disabled.test_client().get("/metrics").status_code == 404
    with pytest.raises(RuntimeError, match="optional dependency"):
        _app()


def test_metrics_auth_is_counted_without_request_instrumentation_or_collector_access() -> None:
    app = _app(LOG_SECURITY_EVENTS=False, SECURITY_FAILURE_RATE_LIMIT=1)

    class Collector:
        def collect(self):
            raise AssertionError("Unauthenticated requests must not collect")

    registry = app.metrics_registry
    assert registry is not None
    collector = Collector()
    registry.register(collector)
    client = app.test_client()
    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics").status_code == 429
    registry.unregister(collector)
    assert _sample(app, "metrics_auth_failures_total", reason="invalid_credentials") == 1
    assert _sample(app, "metrics_auth_failures_total", reason="throttled") == 1
    assert _sample(app, "http_responses_in_flight") == 0
    assert _sample(app, "http_requests_total", method="GET", route="/metrics", status="401") is None


@pytest.mark.parametrize("interval", [0, -1, True, 0.001, 61, float("nan"), float("inf"), "0.1"])
def test_sampler_interval_is_bounded(interval: Any) -> None:
    with pytest.raises(ValueError, match="METRICS_EVENT_LOOP_INTERVAL_SECONDS"):
        _app(METRICS_EVENT_LOOP_INTERVAL_SECONDS=interval)


@pytest.mark.parametrize("finish", ["shutdown", "cancel", "shutdown_failure"])
def test_event_loop_sampler_follows_lifespan_and_stops_on_failure(finish: str) -> None:
    app = _app(METRICS_EVENT_LOOP_INTERVAL_SECONDS=0.01)

    @app.lifespan
    async def lifespan(app: Flasgo):
        yield
        if finish == "shutdown_failure":
            raise RuntimeError("shutdown failure")

    async def run() -> None:
        queue = asyncio.Queue()
        ready = asyncio.Event()

        async def send(message):
            if message["type"] == "lifespan.startup.complete":
                ready.set()

        assert _sample(app, "event_loop_sampler_running") == 0
        assert _sample(app, "event_loop_lag_seconds_count") is None
        task = asyncio.create_task(app({"type": "lifespan"}, queue.get, send))
        await queue.put({"type": "lifespan.startup"})
        await asyncio.wait_for(ready.wait(), 1)
        await asyncio.sleep(0.04)
        assert _sample(app, "event_loop_sampler_running") == 1
        assert (_sample(app, "event_loop_lag_seconds_count") or 0) >= 1
        if finish == "cancel":
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            await queue.put({"type": "lifespan.shutdown"})
            await asyncio.wait_for(task, 1)
        assert _sample(app, "event_loop_sampler_running") == 0
        count = _sample(app, "event_loop_lag_seconds_count")
        await asyncio.sleep(0.03)
        assert _sample(app, "event_loop_lag_seconds_count") == count

    asyncio.run(run())


def test_sampler_can_be_disabled_and_startup_failure_does_not_start_it() -> None:
    app = _app(METRICS_EVENT_LOOP_ENABLED=False)
    with app.test_client():
        assert _sample(app, "event_loop_sampler_running") == 0
        assert _sample(app, "event_loop_lag_seconds_count") is None
    failed = _app()

    @failed.lifespan
    async def lifespan(app: Flasgo):
        raise RuntimeError("startup failure")
        yield

    with pytest.raises(RuntimeError, match="startup"), failed.test_client():
        pass
    assert _sample(failed, "event_loop_sampler_running") == 0
    assert _sample(failed, "event_loop_lag_seconds_count") is None


@pytest.mark.parametrize(
    "outcome",
    [
        "completed",
        "producer_failure",
        "producer_timeout",
        "producer_connection_error",
        "idle_timeout",
        "send_timeout",
        "send_failure",
        "client_disconnect",
        "max_duration",
        "cancelled",
    ],
)
def test_stream_outcomes_and_partial_bytes(outcome: str) -> None:
    app = _app()
    closed = []
    first = asyncio.Event()

    @app.get("/events/<int:item_id>")
    async def endpoint(item_id: int) -> StreamingResponse:
        async def chunks() -> AsyncIterator[bytes]:
            try:
                yield b""
                yield b"first"
                if outcome == "producer_failure":
                    raise ValueError("secret producer failure")
                if outcome == "producer_timeout":
                    raise TimeoutError("producer raised its own timeout")
                if outcome == "producer_connection_error":
                    raise ConnectionError("producer lost a backend")
                if outcome in {"idle_timeout", "max_duration", "client_disconnect", "cancelled"}:
                    await asyncio.Event().wait()
                yield b"last"
            finally:
                closed.append(True)

        return StreamingResponse(
            chunks(),
            idle_timeout=0.02 if outcome == "idle_timeout" else 5,
            max_duration=0.02 if outcome == "max_duration" else 5,
            send_timeout=0.02 if outcome == "send_timeout" else 5,
        )

    async def run():
        body_received = False

        async def streaming_receive():
            nonlocal body_received
            if not body_received:
                body_received = True
                return {"type": "http.request", "body": b"", "more_body": False}
            if outcome == "client_disconnect":
                await first.wait()
                return {"type": "http.disconnect"}
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

        async def send(message):
            if message.get("body") == b"first":
                first.set()
            if message.get("body") == b"last":
                if outcome == "send_timeout":
                    await asyncio.Event().wait()
                if outcome == "send_failure":
                    raise RuntimeError("send failed")

        task = asyncio.create_task(app(_scope("/events/42"), streaming_receive, send))
        if outcome == "cancelled":
            await asyncio.wait_for(first.wait(), 1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            await asyncio.wait_for(task, 1)

    asyncio.run(run())
    route = "/events/<int:item_id>"
    expected = "producer_failure" if outcome in {"producer_timeout", "producer_connection_error"} else outcome
    assert _sample(app, "http_streams_total", route=route, outcome=expected) == 1
    assert _sample(app, "http_stream_body_bytes_total", route=route) == (9 if outcome == "completed" else 5)
    assert _sample(app, "http_streams_active", route=route) == 0
    assert _sample(app, "http_responses_in_flight") == 0
    assert _sample(app, "http_requests_active") == 0
    assert _sample(app, "http_response_start_duration_seconds_count", route=route, method="GET") == 1
    assert _sample(app, "http_response_first_body_duration_seconds_count", route=route, method="GET") == 1
    assert closed == [True]


def test_sse_is_observable_while_open_and_empty_bodies_have_no_first_body_sample() -> None:
    app = _app()

    @app.get("/sse")
    async def sse() -> EventSourceResponse:
        async def events():
            await asyncio.Event().wait()
            yield "never"

        return EventSourceResponse(events(), heartbeat=0.01)

    @app.get("/empty")
    def empty() -> str:
        return ""

    async def run():
        async with app.test_client().astream("GET", "/sse") as response:
            assert b": ping" in await anext(response.iter_bytes())
            assert _sample(app, "http_streams_active", route="/sse") == 1
            assert (_sample(app, "http_stream_body_bytes_total", route="/sse") or 0) > 0
            assert _sample(app, "http_response_first_body_duration_seconds_count", route="/sse", method="GET") == 1
        assert _sample(app, "http_streams_active", route="/sse") == 0

    asyncio.run(run())
    assert app.test_client().get("/empty").status_code == 200
    assert app.test_client().head("/empty").status_code == 200
    for method in ("GET", "HEAD"):
        assert _sample(app, "http_response_first_body_duration_seconds_count", route="/empty", method=method) is None


@pytest.mark.parametrize("cancel", [True, False])
def test_background_counts_separate_response_delivery_from_execution(cancel: bool) -> None:
    app = _app()
    entered, release = asyncio.Event(), asyncio.Event()

    async def slow():
        entered.set()
        await release.wait()

    async def failure():
        raise RuntimeError("task failure")

    @app.get("/")
    def endpoint() -> Response:
        response = Response.text("ok")
        response.add_task(slow)
        response.add_task(failure)
        response.add_task(lambda: None)
        return response

    async def run():
        task = asyncio.create_task(app(_scope(), _receive(), _send))
        await asyncio.wait_for(entered.wait(), 1)
        assert _sample(app, "http_requests_active") == 1
        assert _sample(app, "http_responses_in_flight") == 0
        assert _sample(app, "background_tasks_active") == 1
        assert _sample(app, "background_tasks_pending") == 2
        if cancel:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            release.set()
            await asyncio.wait_for(task, 1)

    asyncio.run(run())
    assert _sample(app, "background_tasks_active") == 0
    assert _sample(app, "background_tasks_pending") == 0
    assert _sample(app, "http_requests_active") == 0
    if cancel:
        assert _sample(app, "background_tasks_total", outcome="cancelled") == 1
        assert _sample(app, "background_tasks_total", outcome="skipped") == 2
        assert _sample(app, "background_task_duration_seconds_count") == 1
    else:
        assert _sample(app, "background_tasks_total", outcome="success") == 2
        assert _sample(app, "background_tasks_total", outcome="failure") == 1
        assert _sample(app, "background_task_duration_seconds_count") == 3


@pytest.mark.parametrize("mode", ["send_failure", "prepare_failure", "replaced"])
def test_undelivered_response_background_work_is_skipped(mode: str) -> None:
    app = _app()
    executed = []

    @app.get("/")
    def endpoint() -> Response:
        response = Response.text("original")
        response.add_task(executed.append, True)
        if mode == "prepare_failure":
            response.headers["invalid\nheader"] = "value"
        return response

    if mode == "replaced":

        @app.after_request
        def replace(req, response):
            return Response.text("replacement")

    async def send(message):
        if mode == "send_failure":
            raise ConnectionError("disconnected")

    asyncio.run(app(_scope(), _receive(), send))
    assert executed == []
    assert _sample(app, "background_tasks_pending") == 0
    assert _sample(app, "background_tasks_total", outcome="skipped") == 1


def test_cleanup_failure_is_counted_after_successful_response() -> None:
    app = _app(LOG_SECURITY_EVENTS=False)

    async def dependency():
        yield "ok"
        assert _sample(app, "http_responses_in_flight") == 0
        raise RuntimeError("private cleanup error")

    @app.get("/")
    async def endpoint(value: Annotated[str, Depends(dependency)]) -> str:
        return value

    assert app.test_client().get("/").status_code == 200
    assert _sample(app, "internal_errors_total", phase="dependency_cleanup", reason="failure") == 1


def test_backend_success_timeout_cancellation_and_capacity_are_distinct() -> None:
    metrics = Metrics()
    for exception, outcome in (
        (None, "success"),
        (TimeoutError(), "timeout"),
        (asyncio.CancelledError(), "cancelled"),
        (StoreUnavailable("secret"), "failure"),
    ):
        try:
            with metrics.backend_operation("session", "load"):
                if exception is not None:
                    raise exception
        except StoreUnavailable, TimeoutError, asyncio.CancelledError:
            pass
        assert (
            metrics.registry.get_sample_value(
                "flasgo_backend_operations_total", {"component": "session", "operation": "load", "outcome": outcome}
            )
            == 1
        )

    app = Flasgo(
        settings={"METRICS_ENABLED": True, "METRICS_BEARER_TOKEN": _TOKEN, "CSRF_ENABLED": False},
        session_backend=ServerSideSessions(MemoryStore(max_keys=1)),
    )

    @app.get("/")
    def endpoint() -> str:
        from flasgo import session

        session["value"] = "sensitive-value"
        return "ok"

    assert app.test_client().get("/").status_code == 200
    assert app.test_client().get("/").status_code == 503
    assert _sample(app, "backend_operations_total", component="session", operation="save", outcome="success") == 1
    assert _sample(app, "backend_operations_total", component="session", operation="save", outcome="failure") == 1
    assert _sample(app, "http_rejections_total", route="/", reason="capacity") == 1


def test_rejections_are_specific_bounded_and_independent_of_security_logging() -> None:
    app = _app(LOG_SECURITY_EVENTS=False, MAX_REQUEST_BODY_BYTES=1)

    @app.post("/items/<int:item_id>")
    async def endpoint(item_id: int, request: Request) -> str:
        await request.body()
        return "ok"

    client = app.test_client()
    assert client.post("/items/42", body=b"too large").status_code == 413
    assert _sample(app, "http_rejections_total", route="/items/<int:item_id>", reason="request_body_limit") == 1
    response = client.post("/items/43", body=b"{}")
    assert response.status_code == 413
    text = client.get("/metrics", headers={"authorization": f"Bearer {_TOKEN}"}).text
    assert "/items/42" not in text
    assert "too large" not in text


def test_rate_limit_capacity_is_separate_from_quota() -> None:
    app = Flasgo(
        settings={"METRICS_ENABLED": True, "METRICS_BEARER_TOKEN": _TOKEN, "CSRF_ENABLED": False}, rate_limiter=RateLimiter(max_keys=1)
    )

    @app.get("/")
    @app.ratelimit(1, per=60)
    def endpoint() -> str:
        return "ok"

    assert app.test_client().get("/").status_code == 200
    assert app.test_client().get("/").status_code == 429
    scope = _scope()
    scope["client"] = ("127.0.0.2", 50000)
    asyncio.run(app(scope, _receive(), _send))
    assert _sample(app, "http_rejections_total", route="/", reason="rate_limit") == 1
    assert _sample(app, "http_rejections_total", route="/", reason="capacity") == 1
    assert _sample(app, "backend_operations_total", component="rate_limit", operation="check_batch", outcome="success") == 3


def test_concurrent_response_reuse_keeps_background_metrics_isolated() -> None:
    first, second = _app(), _app()
    response = Response.text("shared response")
    started = asyncio.Queue()
    release = asyncio.Event()

    async def work():
        await started.put(True)
        await release.wait()

    response.add_task(work)
    response.add_task(work)
    first.get("/")(lambda: response)
    second.get("/")(lambda: response)

    async def run():
        tasks = [asyncio.create_task(app(_scope(), _receive(), _send)) for app in (first, first, second)]
        for _ in tasks:
            await asyncio.wait_for(started.get(), 1)
        assert _sample(first, "background_tasks_active") == 2
        assert _sample(first, "background_tasks_pending") == 2
        assert _sample(second, "background_tasks_active") == 1
        assert _sample(second, "background_tasks_pending") == 1
        release.set()
        await asyncio.wait_for(asyncio.gather(*tasks), 1)

    asyncio.run(run())
    for app, successes in ((first, 4), (second, 2)):
        assert _sample(app, "background_tasks_active") == 0
        assert _sample(app, "background_tasks_pending") == 0
        assert _sample(app, "background_tasks_total", outcome="success") == successes
        assert _sample(app, "background_tasks_total", outcome="skipped") == 0


@pytest.mark.parametrize("synchronous", [False, True])
def test_background_tasks_added_during_execution_are_tracked(synchronous: bool) -> None:
    app = _app()
    response = Response.text("ok")
    finished = []

    async def added():
        finished.append(True)

    def add_more():
        response.add_task(added)
        assert _sample(app, "background_tasks_pending") == 1

    async def original():
        add_more()

    response.add_task(add_more if synchronous else original)
    app.get("/")(lambda: response)
    assert app.test_client().get("/").status_code == 200
    assert finished == [True]
    assert _sample(app, "background_tasks_total", outcome="success") == 2
    assert _sample(app, "background_tasks_pending") == 0


@pytest.mark.parametrize("outcome", ["anonymous", "authenticated", "failure", "timeout", "forbidden"])
def test_authentication_execution_is_separate_from_rejection(outcome: str) -> None:
    from flasgo import IsAuthenticated, User

    app = _app(LOG_SECURITY_EVENTS=False)

    async def backend(req):
        if outcome == "failure":
            raise RuntimeError("private backend detail")
        if outcome == "timeout":
            raise TimeoutError("private backend timeout")
        return User(id="private-user-id", is_authenticated=True) if outcome in {"authenticated", "forbidden"} else None

    app.register_auth_backend("private-backend-name", backend)
    permissions = [IsAuthenticated()]
    if outcome == "forbidden":
        permissions.append(lambda req, user: False)

    @app.get("/private")
    @app.authorize(*permissions, backend="private-backend-name")
    def endpoint() -> str:
        return "ok"

    response = app.test_client().get("/private")
    assert response.status_code == (200 if outcome == "authenticated" else 403 if outcome == "forbidden" else 401)
    expected = outcome if outcome in {"timeout", "failure"} else "success"
    assert _sample(app, "backend_operations_total", component="authentication", operation="authenticate", outcome=expected) == 1
    if outcome in {"anonymous", "forbidden"}:
        assert (
            _sample(app, "http_rejections_total", route="/private", reason="authentication" if outcome == "anonymous" else "permission")
            == 1
        )
    metrics = app.test_client().get("/metrics", headers={"authorization": f"Bearer {_TOKEN}"}).text
    assert "private-user-id" not in metrics
    assert "private-backend-name" not in metrics
    assert "private backend" not in metrics


def test_validation_and_request_read_timeout_are_observed_at_their_source() -> None:
    app = _app(REQUEST_READ_TIMEOUT_SECONDS=0.01)

    @app.get("/validate")
    def validate(value: int) -> str:
        return str(value)

    @app.post("/body")
    async def body(request: Request) -> str:
        await request.body()
        return "ok"

    assert app.test_client().get("/validate?value=secret-invalid-value").status_code == 422
    assert _sample(app, "http_rejections_total", route="/validate", reason="validation") == 1

    async def no_body():
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    asyncio.run(app(_scope("/body", "POST"), no_body, _send))
    assert _sample(app, "http_rejections_total", route="/body", reason="request_read_timeout") == 1
    assert _sample(app, "http_responses_in_flight") == 0


def test_cancellation_before_response_sending_releases_in_flight_gauges() -> None:
    app = _app()
    entered = asyncio.Event()

    @app.get("/")
    async def endpoint() -> str:
        entered.set()
        await asyncio.Event().wait()
        return "unreachable"

    async def run():
        task = asyncio.create_task(app(_scope(), _receive(), _send))
        await asyncio.wait_for(entered.wait(), 1)
        assert _sample(app, "http_responses_in_flight") == 1
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert _sample(app, "http_responses_in_flight") == 0
        assert _sample(app, "http_requests_active") == 0

    asyncio.run(run())


def test_rejected_duplicate_lifespan_does_not_stop_the_active_sampler() -> None:
    app = _app()

    async def run():
        first, second = asyncio.Queue(), asyncio.Queue()
        ready = asyncio.Event()
        messages = []

        async def send(message):
            messages.append(message["type"])
            if message["type"] == "lifespan.startup.complete":
                ready.set()

        tasks = [asyncio.create_task(app({"type": "lifespan"}, queue.get, send)) for queue in (first, second)]
        await asyncio.sleep(0)
        await first.put({"type": "lifespan.startup"})
        await asyncio.wait_for(ready.wait(), 1)
        await second.put({"type": "lifespan.startup"})
        await asyncio.wait_for(tasks[1], 1)
        assert "lifespan.startup.failed" in messages
        assert _sample(app, "event_loop_sampler_running") == 1
        await first.put({"type": "lifespan.shutdown"})
        await asyncio.wait_for(tasks[0], 1)
        assert _sample(app, "event_loop_sampler_running") == 0

    asyncio.run(run())


def test_authenticated_collectors_run_off_the_event_loop() -> None:
    import threading

    app = _app()
    started, release = asyncio.Event(), threading.Event()
    collector_threads = []
    loop: asyncio.AbstractEventLoop | None = None

    class Collector:
        def collect(self):
            collector_threads.append(threading.get_ident())
            assert loop is not None
            loop.call_soon_threadsafe(started.set)
            if not release.wait(2):
                raise RuntimeError("test collector was not released")
            return []

    registry = app.metrics_registry
    assert registry is not None
    registry.register(Collector())

    async def run():
        nonlocal loop
        loop = asyncio.get_running_loop()
        scope = _scope("/metrics")
        scope["headers"].append((b"authorization", f"Bearer {_TOKEN}".encode()))
        task = asyncio.create_task(app(scope, _receive(), _send))
        try:
            await asyncio.wait_for(started.wait(), 1)
            assert len(collector_threads) == 1
            assert collector_threads[0] != threading.get_ident()
            assert not task.done()
        finally:
            release.set()
            await task

    asyncio.run(run())


def test_reused_stream_is_not_reported_as_another_completion() -> None:
    app = _app()

    async def chunks():
        yield b"done"

    response = StreamingResponse(chunks())
    app.get("/")(lambda: response)
    assert app.test_client().get("/").body == b"done"
    asyncio.run(app(_scope(), _receive(), _send))
    assert _sample(app, "http_streams_total", route="/", outcome="completed") == 1
    assert _sample(app, "http_streams_total", route="/", outcome="producer_failure") == 1
    assert _sample(app, "http_streams_active", route="/") == 0


def test_request_limit_exceptions_preserve_http_exception_handler_contract() -> None:
    from flasgo import HTTPException

    app = _app(MAX_REQUEST_BODY_BYTES=1)
    arguments = []

    @app.errorhandler(HTTPException)
    def handle(req, exc):
        arguments.append(exc.args)
        return Response.text(exc.detail, status_code=exc.status_code)

    @app.post("/")
    async def endpoint(request: Request) -> str:
        await request.body()
        return "ok"

    assert app.test_client().post("/", body=b"xx").status_code == 413
    assert arguments == [(413, "Request body exceeds MAX_REQUEST_BODY_BYTES (1 bytes).")]
    assert _sample(app, "http_rejections_total", route="/", reason="request_body_limit") == 1


@pytest.mark.parametrize("existing_container", [False, True])
@pytest.mark.parametrize("send_failure", [False, True])
def test_background_tasks_attached_during_dependency_cleanup_are_observed(existing_container: bool, send_failure: bool) -> None:
    app = _app()
    response = Response.text("ok")
    executions = []

    async def work():
        assert _sample(app, "background_tasks_active") == 1
        executions.append(True)

    if existing_container:
        response.add_task(work)

    async def dependency():
        try:
            yield "ready"
        finally:
            response.add_task(work)

    @app.get("/")
    async def endpoint(value: Annotated[str, Depends(dependency)]) -> Response:
        return response

    async def send(message):
        if send_failure:
            raise ConnectionError("response send failed")

    asyncio.run(app(_scope(), _receive(), send))
    tasks = 2 if existing_container else 1
    assert len(executions) == (0 if send_failure else tasks)
    assert _sample(app, "background_tasks_total", outcome="success") == (0 if send_failure else tasks)
    assert _sample(app, "background_tasks_total", outcome="skipped") == (tasks if send_failure else 0)
    assert _sample(app, "background_task_duration_seconds_count") == (0 if send_failure else tasks)
    assert _sample(app, "background_tasks_pending") == 0
    assert _sample(app, "background_tasks_active") == 0


@pytest.mark.parametrize("security_logging", [False, True])
@pytest.mark.parametrize("rejection", ["host", "csrf", "authentication"])
def test_security_throttling_counts_registration_and_precheck_decisions(rejection: str, security_logging: bool) -> None:
    from flasgo import IsAuthenticated

    app = _app(CSRF_ENABLED=True, LOG_SECURITY_EVENTS=security_logging, SECURITY_FAILURE_RATE_LIMIT=1)

    @app.get("/private")
    @app.authorize(IsAuthenticated())
    def private() -> str:
        return "ok"

    client = app.test_client()
    if rejection == "host":
        statuses = [client.get("/", headers={"host": "invalid.example"}).status_code for _ in range(4)]
        first_status, route, original_rejections = 400, "<unmatched>", 4
    elif rejection == "csrf":
        statuses = [client.post("/").status_code for _ in range(4)]
        first_status, route, original_rejections = 403, "<unmatched>", 4
    else:
        statuses = [client.get("/private").status_code for _ in range(4)]
        first_status, route, original_rejections = 401, "/private", 1

    assert statuses == [first_status, 429, 429, 429]
    assert _sample(app, "http_rejections_total", route=route, reason=rejection) == original_rejections
    assert _sample(app, "http_rejections_total", route=route, reason="security_rate_limit") == 3
