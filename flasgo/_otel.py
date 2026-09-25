"""Optional OpenTelemetry lookups that stay cheap when the ``otel`` extra is not installed."""

from functools import cache
from types import ModuleType


@cache
def _trace_api() -> ModuleType | None:
    # A failed import is not cached by Python, so without this every log line and metric would retry it.
    try:
        from opentelemetry import trace
    except ImportError:
        return None
    return trace


def current_trace_ids() -> tuple[str, str] | None:
    """Return the active span's ``(trace_id, span_id)`` as hex, or ``None`` without a valid span."""
    trace = _trace_api()
    if trace is None:
        return None
    context = trace.get_current_span().get_span_context()
    if not context.is_valid:
        return None
    return format(context.trace_id, "032x"), format(context.span_id, "016x")
