from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

_HTTP_DURATION_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10)
_HTTP_RESPONSE_SIZE_BUCKETS = (64, 256, 1024, 4096, 16_384, 65_536, 262_144, 1_048_576, 4_194_304)
_WEBSOCKET_DURATION_BUCKETS = (1, 5, 15, 30, 60, 300, 900, 1800, 3600, 7200, 21_600, 43_200, 86_400)
_KNOWN_HTTP_METHODS = frozenset(
    {"CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "QUERY", "TRACE"}
)


def _framework_version() -> str:
    try:
        return version("flasgo")
    except PackageNotFoundError:
        return "unknown"


def _trace_exemplar() -> dict[str, str] | None:
    try:
        from opentelemetry import trace
    except ImportError:
        return None
    context = trace.get_current_span().get_span_context()
    if not context.is_valid:
        return None
    return {
        "trace_id": format(context.trace_id, "032x"),
        "span_id": format(context.span_id, "016x"),
    }


def normalize_http_method(method: str) -> str:
    normalized = method.upper()
    return normalized if normalized in _KNOWN_HTTP_METHODS else "_OTHER"


def _status_class(status: int) -> str:
    return f"{status // 100}xx" if 100 <= status <= 599 else "_OTHER"


class Metrics:
    """Small, per-process Prometheus registry with bounded labels."""

    def __init__(self) -> None:
        try:
            from prometheus_client import (
                CollectorRegistry,
                Counter,
                Gauge,
                GCCollector,
                Histogram,
                Info,
                PlatformCollector,
                ProcessCollector,
            )
        except ImportError as exc:
            raise RuntimeError(
                "Metrics require the optional dependency. Install Flasgo with `flasgo[metrics]`."
            ) from exc

        self.registry = CollectorRegistry()
        # A private registry avoids collisions between multiple Flasgo apps, but it
        # would otherwise omit the standard runtime collectors from client_python.
        ProcessCollector(registry=self.registry)
        PlatformCollector(registry=self.registry)
        GCCollector(registry=self.registry)
        framework = Info("flasgo", "Flasgo framework information.", registry=self.registry)
        framework.info({"version": _framework_version()})

        self.http_requests = Counter(
            "flasgo_http_requests_total",
            "Completed HTTP request attempts, including response send failures.",
            ("method", "route", "status"),
            registry=self.registry,
        )
        self.http_duration = Histogram(
            "flasgo_http_request_duration_seconds",
            "HTTP request duration through response send.",
            ("method", "route", "status_class"),
            buckets=_HTTP_DURATION_BUCKETS,
            registry=self.registry,
        )
        self.http_response_body_size = Histogram(
            "flasgo_http_response_body_size_bytes",
            "Successfully sent HTTP response body size in bytes.",
            ("method", "route", "status_class"),
            buckets=_HTTP_RESPONSE_SIZE_BUCKETS,
            registry=self.registry,
        )
        self.http_response_send_failures = Counter(
            "flasgo_http_response_send_failures_total",
            "HTTP responses that failed while sending to the ASGI server.",
            ("method", "route", "status"),
            registry=self.registry,
        )
        self.http_active = Gauge(
            "flasgo_http_requests_active",
            "Active HTTP requests.",
            registry=self.registry,
        )
        self.websocket_connections = Counter(
            "flasgo_websocket_connections_total",
            "Completed WebSocket connections and denials.",
            ("route", "outcome"),
            registry=self.registry,
        )
        self.websocket_duration = Histogram(
            "flasgo_websocket_connection_duration_seconds",
            "WebSocket connection duration.",
            ("route", "outcome"),
            buckets=_WEBSOCKET_DURATION_BUCKETS,
            registry=self.registry,
        )
        self.websocket_active = Gauge(
            "flasgo_websocket_connections_active",
            "Active authorized WebSocket handler calls.",
            ("route",),
            registry=self.registry,
        )
        self.background_tasks = Counter(
            "flasgo_background_tasks_total",
            "Background task outcomes.",
            ("outcome",),
            registry=self.registry,
        )
        self.lifespan_events = Counter(
            "flasgo_lifespan_events_total",
            "Lifespan outcomes.",
            ("phase", "outcome"),
            registry=self.registry,
        )

    def render(self, accept_header: str | None = None) -> tuple[bytes, str]:
        from prometheus_client.exposition import choose_encoder

        try:
            encoder, content_type = choose_encoder(accept_header or "")
        except TypeError, ValueError:
            encoder, content_type = choose_encoder("")
        return encoder(self.registry), content_type

    def observe_http(
        self,
        *,
        method: str,
        route: str,
        status: int,
        duration: float,
        response_body_size: int | None,
        response_sent: bool,
    ) -> None:
        method_label = normalize_http_method(method)
        labels = {"method": method_label, "route": route, "status": str(status)}
        distribution_labels = {"method": method_label, "route": route, "status_class": _status_class(status)}
        exemplar = _trace_exemplar()
        self.http_requests.labels(**labels).inc(exemplar=exemplar)
        self.http_duration.labels(**distribution_labels).observe(duration, exemplar=exemplar)
        if response_sent and response_body_size is not None:
            self.http_response_body_size.labels(**distribution_labels).observe(response_body_size, exemplar=exemplar)
        else:
            self.http_response_send_failures.labels(**labels).inc(exemplar=exemplar)

    def observe_websocket(self, *, route: str, outcome: str, duration: float) -> None:
        exemplar = _trace_exemplar()
        self.websocket_connections.labels(route=route, outcome=outcome).inc(exemplar=exemplar)
        self.websocket_duration.labels(route=route, outcome=outcome).observe(duration, exemplar=exemplar)

    def observe_background(self, outcome: str) -> None:
        self.background_tasks.labels(outcome=outcome).inc(exemplar=_trace_exemplar())

    def observe_lifespan(self, phase: str, outcome: str) -> None:
        self.lifespan_events.labels(phase=phase, outcome=outcome).inc()
