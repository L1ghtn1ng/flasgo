from __future__ import annotations

import asyncio
import sys
from typing import Any

from flasgo import CORSConfig, Flasgo
from flasgo.metrics import Metrics
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

_TOKEN = "metrics-token-" + "m" * 32


def _app(**settings: object) -> Flasgo:
    return Flasgo(
        settings={
            "CSRF_ENABLED": False,
            "METRICS_ENABLED": True,
            "METRICS_BEARER_TOKEN": _TOKEN,
            **settings,
        }
    )


def _scrape(app: Flasgo, *, accept: str | None = None) -> str:
    headers = {"authorization": f"Bearer {_TOKEN}"}
    if accept is not None:
        headers["accept"] = accept
    response = app.test_client().get("/metrics", headers=headers)
    assert response.status_code == 200
    return response.text


def test_http_metrics_include_runtime_status_latency_and_response_size() -> None:
    app = _app()

    @app.post("/items/<int:item_id>")
    async def item(item_id: int) -> bytes:
        return f"item:{item_id}".encode()

    @app.get("/known")
    async def known() -> str:
        return "ok"

    client = app.test_client()
    assert client.post("/items/42", body=b"ignored").status_code == 200
    assert client.request("X-ATTACKER-METHOD", "/known").status_code == 405

    metrics = _scrape(app)
    assert 'flasgo_info{version="0.7.0"} 1.0' in metrics
    assert "python_info{" in metrics
    assert "python_gc_collections_total{" in metrics
    if sys.platform.startswith("linux"):
        assert "process_cpu_seconds_total " in metrics
    request_labels = 'method="POST",route="/items/<int:item_id>",status="200"'
    distribution_labels = 'method="POST",route="/items/<int:item_id>",status_class="2xx"'
    assert f"flasgo_http_requests_total{{{request_labels}}} 1.0" in metrics
    assert f"flasgo_http_request_duration_seconds_count{{{distribution_labels}}} 1.0" in metrics
    assert f"flasgo_http_response_body_size_bytes_count{{{distribution_labels}}} 1.0" in metrics
    assert f"flasgo_http_response_body_size_bytes_sum{{{distribution_labels}}} 7.0" in metrics
    assert 'method="_OTHER",route="/known",status="405"' in metrics
    assert "X-ATTACKER-METHOD" not in metrics


def test_websocket_duration_buckets_cover_long_lived_connections() -> None:
    metrics = Metrics()
    metrics.observe_websocket(route="/events", outcome="closed", duration=4000)

    rendered, _ = metrics.render()
    text = rendered.decode()
    labels = 'le="3600.0",outcome="closed",route="/events"'
    assert f"flasgo_websocket_connection_duration_seconds_bucket{{{labels}}} 0.0" in text
    labels = 'le="7200.0",outcome="closed",route="/events"'
    assert f"flasgo_websocket_connection_duration_seconds_bucket{{{labels}}} 1.0" in text


def test_pre_dispatch_rejections_and_response_send_failures_are_observable() -> None:
    app = _app(MAX_REQUEST_HEAD_BYTES=128)

    @app.get("/send-failure")
    async def send_failure() -> str:
        return "payload"

    oversized = app.test_client().get("/", headers={"x-padding": "x" * 256})
    assert oversized.status_code == 431

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/send-failure",
        "raw_path": b"/send-failure",
        "query_string": b"",
        "headers": [(b"host", b"localhost")],
        "client": ("127.0.0.1", 50000),
        "server": ("localhost", 80),
    }
    received = False

    async def receive() -> dict[str, Any]:
        nonlocal received
        if not received:
            received = True
            return {"type": "http.request", "body": b"", "more_body": False}
        return {"type": "http.disconnect"}

    async def fail_on_body(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.body":
            raise ConnectionError("client disconnected")

    asyncio.run(app(scope, receive, fail_on_body))

    metrics = _scrape(app)
    assert 'method="GET",route="<unmatched>",status="431"' in metrics
    failure_labels = 'method="GET",route="/send-failure",status="200"'
    assert f"flasgo_http_response_send_failures_total{{{failure_labels}}} 1.0" in metrics
    assert f"flasgo_http_response_body_size_bytes_count{{{failure_labels}}}" not in metrics
    assert "flasgo_http_requests_active 0.0" in metrics


def test_openmetrics_scrapes_expose_trace_exemplars_without_framework_cookies() -> None:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    app = Flasgo(
        settings={
            "METRICS_ENABLED": True,
            "METRICS_BEARER_TOKEN": _TOKEN,
            "OTEL_ENABLED": True,
        },
        tracer_provider=provider,
    )

    @app.get("/orders/<int:order_id>")
    async def order(order_id: int) -> dict[str, int]:
        return {"id": order_id}

    client = app.test_client()
    assert client.get("/orders/7").status_code == 200
    unauthorized = client.get("/metrics")
    assert unauthorized.status_code == 401
    assert unauthorized.headers["cache-control"] == "no-store, no-cache, must-revalidate, max-age=0"
    assert "set-cookie" not in unauthorized.headers
    response = client.get(
        "/metrics",
        headers={
            "authorization": f"Bearer {_TOKEN}",
            "accept": "application/openmetrics-text; version=1.0.0",
        },
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/openmetrics-text; version=1.0.0")
    assert response.headers["cache-control"] == "no-store, no-cache, must-revalidate, max-age=0"
    assert response.headers["vary"] == "accept"
    assert "set-cookie" not in response.headers
    assert response.text.endswith("# EOF\n")
    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    context = spans[0].context
    assert context is not None
    assert f'trace_id="{context.trace_id:032x}"' in response.text
    assert f'span_id="{context.span_id:016x}"' in response.text


def test_malformed_openmetrics_version_falls_back_without_failing_scrape() -> None:
    app = _app()

    response = app.test_client().get(
        "/metrics",
        headers={
            "authorization": f"Bearer {_TOKEN}",
            "accept": "application/openmetrics-text; version=a",
        },
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert response.headers["cache-control"] == "no-store, no-cache, must-revalidate, max-age=0"
    assert "set-cookie" not in response.headers
    assert response.text.startswith("# HELP")


def test_metrics_reject_duplicate_authorization_headers() -> None:
    app = _app()

    response = app.test_client().get(
        "/metrics",
        headers=[
            ("authorization", "Bearer wrong"),
            ("authorization", f"Bearer {_TOKEN}"),
        ],
    )

    assert response.status_code == 401
    assert response.headers["cache-control"] == "no-store, no-cache, must-revalidate, max-age=0"
    assert "set-cookie" not in response.headers


def test_http_distributions_use_bounded_status_classes() -> None:
    metrics = Metrics()
    for status in (100, 200, 300, 400, 500, 599):
        metrics.observe_http(
            method="GET",
            route="/status",
            status=status,
            duration=0.001,
            response_body_size=0,
            response_sent=True,
        )

    rendered, _ = metrics.render()
    text = rendered.decode()
    assert text.count('flasgo_http_request_duration_seconds_count{method="GET",route="/status"') == 5
    assert text.count('flasgo_http_response_body_size_bytes_count{method="GET",route="/status"') == 5
    assert 'status_class="2xx"' in text
    assert 'flasgo_http_requests_total{method="GET",route="/status",status="599"} 1.0' in text


def test_framework_metrics_endpoint_does_not_inherit_catch_all_cors() -> None:
    app = Flasgo(
        settings={
            "CSRF_ENABLED": False,
            "METRICS_ENABLED": True,
            "METRICS_BEARER_TOKEN": _TOKEN,
        },
        cors=CORSConfig(
            allow_origins={"https://app.example.com"},
            allow_methods={"GET"},
            allow_headers={"authorization"},
            allow_credentials=True,
        ),
    )

    @app.get("/<path:rest>")
    def catch_all(rest: str) -> str:
        return rest

    response = app.test_client().get(
        "/metrics",
        headers={
            "authorization": f"Bearer {_TOKEN}",
            "origin": "https://app.example.com",
        },
    )
    preflight = app.test_client().request(
        "OPTIONS",
        "/metrics",
        headers={
            "origin": "https://app.example.com",
            "access-control-request-method": "GET",
            "access-control-request-headers": "authorization",
        },
    )

    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers
    assert preflight.status_code == 405
    assert "access-control-allow-origin" not in preflight.headers
