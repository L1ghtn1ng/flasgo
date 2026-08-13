from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import quote_from_bytes

from .settings import Settings
from .types import Receive, Scope, Send

type ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]
type SpanDetails = Callable[[Scope], tuple[str, dict[str, str]]]
type ScopeHeaders = Callable[[Scope], list[tuple[bytes, bytes]]]
_ORIGINAL_SCOPE = "flasgo.telemetry.original_scope"
_SPAN_DETAILS = "flasgo.telemetry.span_details"


class Telemetry:
    """A narrow tracing boundary around the Flasgo ASGI dispatcher."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        settings: Settings,
        span_details: SpanDetails,
        scope_headers: ScopeHeaders,
        tracer_provider: Any | None = None,
    ) -> None:
        try:
            from opentelemetry import trace
            from opentelemetry.instrumentation.asgi import OpenTelemetryMiddleware
        except ImportError as exc:
            raise RuntimeError(
                "OpenTelemetry tracing requires the optional dependency. Install Flasgo with `flasgo[otel]`."
            ) from exc

        self._excluded_paths = frozenset((*settings.OTEL_EXCLUDED_PATHS, settings.METRICS_PATH))
        self._app = app
        self._owned_provider = tracer_provider is None
        self._span_details = span_details
        self._scope_headers = scope_headers
        provider = tracer_provider or _build_tracer_provider(settings)
        if self._owned_provider and settings.OTEL_SET_GLOBAL_PROVIDER:
            trace.set_tracer_provider(provider)
        self._provider = provider
        self._middleware: Any = OpenTelemetryMiddleware(
            self._dispatch_original_scope,
            default_span_details=self._sanitized_span_details,
            tracer_provider=provider,
            exclude_spans=["receive", "send"],
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        span_name, attributes = self._span_details(scope)
        route = attributes.get("http.route", "<unmatched>")
        request_path = str(scope.get("path", ""))
        if request_path in self._excluded_paths or route in self._excluded_paths:
            await self._app(scope, receive, send)
            return
        scope_type = str(scope.get("type", ""))
        if scope_type == "http":
            telemetry_path = request_path or "/"
            raw_path = scope.get("raw_path")
            telemetry_raw_path = raw_path if isinstance(raw_path, bytes) else telemetry_path.encode("utf-8")
            query_string = _redacted_query_string(scope.get("query_string", b""))
            root_path = scope.get("root_path", "")
        else:
            telemetry_path = route if route.startswith("/") else f"/{route}"
            telemetry_raw_path = telemetry_path.encode("utf-8")
            query_string = b""
            root_path = ""
        telemetry_scope = {
            **scope,
            "path": telemetry_path,
            "raw_path": telemetry_raw_path,
            "root_path": root_path,
            "query_string": query_string,
            "headers": self._scope_headers(scope),
            _ORIGINAL_SCOPE: scope,
            _SPAN_DETAILS: (span_name, attributes),
        }
        await self._middleware(telemetry_scope, receive, send)

    async def _dispatch_original_scope(self, scope: Scope, receive: Receive, send: Send) -> None:
        original_scope = scope.get(_ORIGINAL_SCOPE)
        if not isinstance(original_scope, dict):
            raise RuntimeError("OpenTelemetry dispatch is missing the original ASGI scope.")
        await self._app(original_scope, receive, send)

    def _sanitized_span_details(self, scope: Scope) -> tuple[str, dict[str, str]]:
        details = scope.get(_SPAN_DETAILS)
        if not isinstance(details, tuple) or len(details) != 2:
            raise RuntimeError("OpenTelemetry dispatch is missing sanitized span details.")
        name, attributes = details
        if not isinstance(name, str) or not isinstance(attributes, dict):
            raise RuntimeError("OpenTelemetry span details are invalid.")
        return name, attributes

    def shutdown(self) -> None:
        """Flush and close only a tracer provider created by Flasgo."""

        if self._owned_provider:
            self._provider.shutdown()


def _build_tracer_provider(settings: Settings) -> Any:
    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased
    except ImportError as exc:
        raise RuntimeError(
            "Turnkey OpenTelemetry export requires the optional dependency. Install Flasgo with `flasgo[otel]`."
        ) from exc

    attributes: dict[str, str] = {"service.name": settings.OTEL_SERVICE_NAME}
    if settings.OTEL_SERVICE_VERSION:
        attributes["service.version"] = settings.OTEL_SERVICE_VERSION
    provider = TracerProvider(
        resource=Resource.create(attributes),
        sampler=ParentBased(TraceIdRatioBased(settings.OTEL_TRACE_SAMPLE_RATIO)),
    )
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    return provider


_QUERY_KEY_MAX_BYTES = 64


def _redacted_query_string(value: object) -> bytes:
    if not isinstance(value, bytes) or not value:
        return b""
    fields: list[bytes] = []
    for field in value.split(b"&"):
        key, separator, raw_value = field.partition(b"=")
        # Query keys are attacker-controlled and sometimes carry credentials in the
        # key position, so bound their length before they reach span attributes.
        safe_key = quote_from_bytes(key[:_QUERY_KEY_MAX_BYTES], safe="!$'()*+,-./:;?@_~%").encode("ascii")
        if not separator:
            fields.append(safe_key)
        elif not raw_value:
            fields.append(safe_key + b"=")
        else:
            fields.append(safe_key + b"=REDACTED")
    return b"&".join(fields)
