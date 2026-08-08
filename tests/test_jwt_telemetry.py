from __future__ import annotations

import logging
import os
import queue
import subprocess
import sys
import textwrap
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import cast

import pytest
from flasgo import Flasgo, HasScope, IsAuthenticated, WebSocket, encode_jwt, jwt_backend
from flasgo.logging import log_event
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import jwt

_JWT_SECRET = "this-is-a-test-secret-with-at-least-32-bytes"


def test_jwt_backend_enforces_algorithm_issuer_audience_expiry_and_scopes() -> None:
    app = Flasgo()
    app.register_auth_backend(
        "jwtAuth",
        jwt_backend(_JWT_SECRET, issuer="https://issuer.example", audience="flasgo-tests"),
    )

    @app.get("/admin")
    @app.authorize(IsAuthenticated(), HasScope("admin"), backend="jwtAuth")
    def admin() -> str:
        return "ok"

    client = app.test_client()
    valid = encode_jwt(
        "alice",
        _JWT_SECRET,
        issuer="https://issuer.example",
        audience="flasgo-tests",
        scopes=("admin",),
    )
    assert client.get("/admin", headers={"authorization": f"Bearer {valid}"}).status_code == 200

    wrong_audience = encode_jwt(
        "alice",
        _JWT_SECRET,
        issuer="https://issuer.example",
        audience="another-api",
        scopes=("admin",),
    )
    rejected = client.get("/admin", headers={"authorization": f"Bearer {wrong_audience}"})
    assert rejected.status_code == 401
    assert rejected.headers["www-authenticate"] == "Bearer"

    unsigned = jwt.encode(
        {
            "sub": "alice",
            "iss": "https://issuer.example",
            "aud": "flasgo-tests",
            "iat": 1,
            "exp": 4_102_444_800,
            "scope": "admin",
        },
        key="",
        algorithm="none",
    )
    assert client.get("/admin", headers={"authorization": f"Bearer {unsigned}"}).status_code == 401


def test_jwt_backend_rejects_weak_secrets_and_reserved_claim_overrides() -> None:
    try:
        jwt_backend("short", issuer="issuer", audience="audience")
    except ValueError as exc:
        assert "at least 32 bytes" in str(exc)
    else:
        raise AssertionError("A weak HS256 secret was accepted.")

    try:
        encode_jwt(
            "alice",
            _JWT_SECRET,
            issuer="issuer",
            audience="audience",
            additional_claims={"sub": "mallory"},
        )
    except ValueError as exc:
        assert "reserved claims" in str(exc)
    else:
        raise AssertionError("A reserved JWT claim was overridden.")


@pytest.mark.parametrize("scope_claim", ["sub", "iss", "aud", "exp", "iat", "nbf", "jti", "alg"])
def test_jwt_helpers_reject_scope_claims_that_collide_with_registered_claims(scope_claim: str) -> None:
    with pytest.raises(ValueError, match="scope_claim"):
        jwt_backend(_JWT_SECRET, issuer="issuer", audience="audience", scope_claim=scope_claim)
    with pytest.raises(ValueError, match="scope_claim"):
        encode_jwt(
            "alice",
            _JWT_SECRET,
            issuer="issuer",
            audience="audience",
            scopes=("admin",),
            scope_claim=scope_claim,
        )


def test_openapi_includes_jwt_security_scheme_and_route_requirements() -> None:
    app = Flasgo(settings={"ENABLE_DOCS": True})
    app.register_auth_backend("jwtAuth", jwt_backend(_JWT_SECRET, issuer="issuer", audience="audience"))

    @app.get("/private")
    @app.authorize(backend="jwtAuth")
    def private() -> dict[str, bool]:
        return {"ok": True}

    spec = app.openapi_spec()
    assert spec["components"]["securitySchemes"]["jwtAuth"] == {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }
    operation = spec["paths"]["/private"]["get"]
    assert operation["security"] == [{"jwtAuth": []}]
    assert operation["responses"]["401"] == {"description": "Unauthorized"}
    assert operation["responses"]["403"] == {"description": "Forbidden"}


def _tracing_app(*, excluded_paths: set[str] | None = None) -> tuple[Flasgo, InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    app = Flasgo(
        settings={
            "CSRF_ENABLED": False,
            "OTEL_ENABLED": True,
            "OTEL_EXCLUDED_PATHS": excluded_paths or set(),
        },
        tracer_provider=provider,
    )
    return app, exporter


def test_opentelemetry_emits_route_bounded_server_spans_and_excludes_paths() -> None:
    app, exporter = _tracing_app(excluded_paths={"/health", "/private/<int:item_id>"})

    @app.get("/widgets/<int:widget_id>")
    def widget(widget_id: int) -> dict[str, int]:
        return {"id": widget_id}

    @app.get("/health")
    def health() -> str:
        return "ok"

    @app.get("/private/<int:item_id>")
    def private(item_id: int) -> dict[str, int]:
        return {"id": item_id}

    client = app.test_client()
    assert client.get("/widgets/42?token=collector-secret").status_code == 200
    assert client.get("/health").status_code == 200
    assert client.get("/private/9?token=private-secret").status_code == 200

    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    span = spans[0]
    assert span.name == "GET /widgets/<int:widget_id>"
    assert span.kind is trace.SpanKind.SERVER
    attributes = span.attributes
    assert attributes is not None
    assert attributes["http.route"] == "/widgets/<int:widget_id>"
    assert len(cast(str, attributes["flasgo.request_id"])) >= 16
    serialized_attributes = repr(dict(attributes))
    assert "collector-secret" not in serialized_attributes
    assert attributes["http.target"] == "/widgets/42"
    assert attributes["http.url"] == "http://localhost/widgets/42?token=REDACTED"
    assert "private-secret" not in serialized_attributes


def test_opentelemetry_normalizes_unknown_methods_in_span_names() -> None:
    app, exporter = _tracing_app()

    @app.get("/widgets/<int:widget_id>")
    def widget(widget_id: int) -> dict[str, int]:
        return {"id": widget_id}

    @app.route("/custom", methods=("QUERY",))
    def custom() -> str:
        return "ok"

    client = app.test_client()
    assert client.request("X-ATTACKER-ONE", "/widgets/1").status_code == 405
    assert client.request("X-ATTACKER-TWO", "/widgets/2").status_code == 405
    assert client.request("QUERY", "/custom").status_code == 200

    spans = exporter.get_finished_spans()
    # Unknown methods use "HTTP" in the span name (stable OTel HTTP naming); QUERY is known.
    assert [span.name for span in spans] == [
        "HTTP /widgets/<int:widget_id>",
        "HTTP /widgets/<int:widget_id>",
        "QUERY /custom",
    ]


def test_opentelemetry_does_not_export_rejected_host_values() -> None:
    app, exporter = _tracing_app()

    @app.get("/")
    def home() -> str:
        return "ok"

    response = app.test_client().get("/", headers={"host": "attacker.example"})
    assert response.status_code == 400

    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    attributes = spans[0].attributes
    assert attributes is not None
    assert "attacker.example" not in repr(dict(attributes))


def test_opentelemetry_excludes_route_templates_for_method_not_allowed_requests() -> None:
    app, exporter = _tracing_app(excluded_paths={"/reset/<token>"})

    @app.get("/reset/<value>")
    def generic_reset(value: str) -> str:
        return value

    @app.get("/reset/<token>")
    def reset(token: str) -> str:
        return token

    @app.get("/public/<value>")
    def public(value: str) -> str:
        return value

    client = app.test_client()
    assert client.post("/reset/private-reset-token").status_code == 405
    assert client.post("/public/visible").status_code == 405

    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    assert spans[0].name == "POST /public/<value>"
    attributes = spans[0].attributes
    assert attributes is not None
    assert attributes["http.route"] == "/public/<value>"
    assert "private-reset-token" not in repr(dict(attributes))


def test_stable_http_semconv_uses_real_path_and_redacted_query() -> None:
    script = textwrap.dedent(
        """
        import json

        from flasgo import Flasgo
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        app = Flasgo(settings={"CSRF_ENABLED": False, "OTEL_ENABLED": True}, tracer_provider=provider)

        @app.get("/widgets/<int:widget_id>")
        def widget(widget_id: int) -> dict[str, int]:
            return {"id": widget_id}

        app.test_client().get("/widgets/42?token=collector-secret&empty=&flag&tag=one&tag=two")
        span = exporter.get_finished_spans()[0]
        print(json.dumps({"name": span.name, "attributes": dict(span.attributes or {})}, sort_keys=True))
        """
    )
    environment = {**os.environ, "OTEL_SEMCONV_STABILITY_OPT_IN": "http/dup"}
    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    payload = __import__("json").loads(completed.stdout)
    attributes = payload["attributes"]
    assert payload["name"] == "GET /widgets/<int:widget_id>"
    assert attributes["http.route"] == "/widgets/<int:widget_id>"
    assert attributes["url.path"] == "/widgets/42"
    assert attributes["url.query"] == "token=REDACTED&empty=&flag&tag=REDACTED&tag=REDACTED"
    assert "collector-secret" not in repr(attributes)


def test_opentelemetry_scrubs_websocket_paths_and_queries() -> None:
    app, exporter = _tracing_app()

    @app.websocket("/rooms/<int:room_id>")
    async def room(websocket: WebSocket, room_id: int) -> None:
        _ = room_id
        await websocket.accept()

    with app.test_client() as client:
        with client.websocket_connect("/rooms/7?token=websocket-secret"):
            pass

    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    attributes = spans[0].attributes
    assert attributes is not None
    assert attributes["http.route"] == "/rooms/<int:room_id>"
    serialized_attributes = repr(dict(attributes))
    assert "websocket-secret" not in serialized_attributes
    assert "/rooms/7" not in serialized_attributes


def test_log_events_include_active_trace_identifiers(caplog: pytest.LogCaptureFixture) -> None:
    provider = TracerProvider()
    tracer = provider.get_tracer("tests")
    logger = logging.getLogger("flasgo.test.telemetry")
    logger.propagate = True

    with tracer.start_as_current_span("operation") as span:
        with caplog.at_level(logging.INFO, logger=logger.name):
            log_event(logger, logging.INFO, "inside-span")

    record = caplog.records[-1]
    context = span.get_span_context()
    assert record.__dict__["trace_id"] == format(context.trace_id, "032x")
    assert record.__dict__["span_id"] == format(context.span_id, "016x")


def test_owned_tracer_provider_registers_process_global_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    registered: list[object] = []
    monkeypatch.setattr(trace, "set_tracer_provider", registered.append)
    provider = TracerProvider()
    monkeypatch.setattr("flasgo.telemetry._build_tracer_provider", lambda settings: provider)

    Flasgo(settings={"OTEL_ENABLED": True})

    assert registered == [provider]


def test_global_provider_registration_respects_opt_out_and_external_providers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registered: list[object] = []
    monkeypatch.setattr(trace, "set_tracer_provider", registered.append)
    monkeypatch.setattr("flasgo.telemetry._build_tracer_provider", lambda settings: TracerProvider())

    Flasgo(settings={"OTEL_ENABLED": True, "OTEL_SET_GLOBAL_PROVIDER": False})
    Flasgo(settings={"OTEL_ENABLED": True}, tracer_provider=TracerProvider())

    assert registered == []


def test_invalid_opentelemetry_settings_fail_early() -> None:
    for settings in (
        {"OTEL_SERVICE_NAME": ""},
        {"OTEL_TRACE_SAMPLE_RATIO": 1.1},
        {"OTEL_EXCLUDED_PATHS": {"health"}},
    ):
        try:
            Flasgo(settings=settings)
        except ValueError:
            pass
        else:
            raise AssertionError(f"Invalid telemetry settings were accepted: {settings!r}")


def test_owned_provider_exports_otlp_protobuf_and_flushes_on_shutdown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: queue.Queue[tuple[str, dict[str, str], bytes]] = queue.Queue()

    class Collector(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            size = int(self.headers.get("content-length", "0"))
            headers = {key.lower(): value for key, value in self.headers.items()}
            requests.put((self.path, headers, self.rfile.read(size)))
            self.send_response(200)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            _ = format, args

    server = ThreadingHTTPServer(("127.0.0.1", 0), Collector)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = cast(tuple[str, int], server.server_address)
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", f"http://{host}:{port}/v1/traces")
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_HEADERS", "x-test-header=contract")
        monkeypatch.setattr(trace, "set_tracer_provider", lambda provider: None)
        app = Flasgo(settings={"CSRF_ENABLED": False, "OTEL_ENABLED": True})

        @app.get("/export")
        def export() -> str:
            return "ok"

        with app.test_client() as client:
            assert client.get("/export").status_code == 200

        path, headers, body = requests.get(timeout=5)
        assert path == "/v1/traces"
        assert headers["content-type"] == "application/x-protobuf"
        assert headers["x-test-header"] == "contract"
        assert body
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
