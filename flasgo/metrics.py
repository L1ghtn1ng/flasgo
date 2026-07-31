from __future__ import annotations


class Metrics:
    """Small, per-process Prometheus registry with bounded labels."""

    def __init__(self) -> None:
        try:
            from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram
        except ImportError as exc:
            raise RuntimeError(
                "Metrics require the optional dependency. Install Flasgo with `flasgo[metrics]`."
            ) from exc

        self.registry = CollectorRegistry()
        self.http_requests = Counter(
            "flasgo_http_requests_total",
            "Completed HTTP requests.",
            ("method", "route", "status"),
            registry=self.registry,
        )
        self.http_duration = Histogram(
            "flasgo_http_request_duration_seconds",
            "HTTP request duration through response send.",
            ("method", "route"),
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
            ("route",),
            registry=self.registry,
        )
        self.websocket_active = Gauge(
            "flasgo_websocket_connections_active",
            "Active accepted WebSocket connections.",
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

    def render(self) -> tuple[bytes, str]:
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

        return generate_latest(self.registry), CONTENT_TYPE_LATEST

    def observe_background(self, outcome: str) -> None:
        self.background_tasks.labels(outcome=outcome).inc()

    def observe_lifespan(self, phase: str, outcome: str) -> None:
        self.lifespan_events.labels(phase=phase, outcome=outcome).inc()
