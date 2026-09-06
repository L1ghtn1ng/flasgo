# Metrics reference

Flasgo's optional `flasgo[metrics]` extra exposes an authenticated Prometheus/OpenMetrics endpoint. Metrics remain
disabled by default. Existing metric names, labels, and timing boundaries are preserved. See the README for the
existing enablement settings. This reference describes the additional measurements and public extension API.

## HTTP and streaming

All names in the tables below include their full prefix. Histograms export `_bucket`, `_sum`, and `_count` series.
Duration units are seconds; byte counters measure payload bytes rather than headers or transport framing.

| Metric | Type | Labels | Boundary |
| --- | --- | --- | --- |
| `flasgo_http_responses_in_flight` | Gauge | None | Request entry through response sending, excluding subsequent dependency cleanup and background work |
| `flasgo_http_response_start_duration_seconds` | Histogram | `method`, `route` | Request entry to the successful ASGI response-start send |
| `flasgo_http_response_first_body_duration_seconds` | Histogram | `method`, `route` | Request entry to the first successfully sent non-empty body message |
| `flasgo_http_streams_active` | Gauge | `route` | Execution of `StreamingResponse.send`, including its iterator cleanup |
| `flasgo_http_streams_total` | Counter | `route`, `outcome` | One terminal outcome for each streaming send attempt |
| `flasgo_http_stream_body_bytes_total` | Counter | `route` | Incremental body bytes successfully handed to ASGI, including partial streams |

`route` is the registered route template or `<unmatched>`, never a raw request path. HTTP methods retain the existing
bounded normalization and `_OTHER` fallback. Start/first-body histograms use the existing HTTP latency buckets:
0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, and 10 seconds, plus infinity.

Stream outcomes are `completed`, `client_disconnect`, `idle_timeout`, `send_timeout`, `max_duration`,
`producer_failure`, `send_failure`, and `cancelled`. An exception raised by the producer itself is a producer failure;
a framework timeout is identified using the timeout context's expiry state. ASGI send `OSError`s indicate a closed
connection; other send exceptions use `send_failure`. Iterator cleanup failures can prevent normal completion.

These metrics cover SSE, NDJSON, and other `StreamingResponse` subclasses. ASGI acceptance does not establish when
a browser received or rendered the data. SSE heartbeat comments count as first-body data and bytes. Applications
needing time to the first useful event should add their own metric. Empty responses and HEAD responses have no
first-body sample. Long streams update active/byte measurements before completion and are never buffered for metrics.

HTTP status and stream completion are separate facts: a stream can send `200` headers and later fail. Expected client
disconnects should be evaluated separately from server faults. The existing HTTP duration includes response sending
and request-dependency cleanup; the existing active-request gauge also includes background work. The new in-flight
gauge ends when response sending exits. A streaming send itself includes stream iterator cleanup. Existing completed
HTTP counters retain their cancellation behavior; use stream outcomes for explicit stream cancellation accounting.

## Backend operations

| Metric | Type | Labels |
| --- | --- | --- |
| `flasgo_backend_operations_total` | Counter | `component`, `operation`, `outcome` |
| `flasgo_backend_operation_duration_seconds` | Histogram | `component`, `operation` |

The instrumented logical calls are `session/load`, `session/save`, `authentication/authenticate`, and
`rate_limit/check_batch`. Session calls include their serialization and storage work. A load returning an empty
session is still a successful call, even when no storage read was needed. Saves are measured only when persistence
is needed. Authentication includes the configured backend call; permission decisions are reported separately.
Rate limits count each applicable batch/phase once. HTTP, documentation authentication, and WebSocket upgrade
backend calls share these measurements. Scrapes do not contribute backend operations.

Outcomes are `success`, `failure`, `timeout`, `cancelled`, and `conflict` (an HTTP 409 from the operation).
An immediate `TimeoutError` cause wrapped by a backend is also recognized. Expected negative results, including
missing sessions, invalid credentials returned normally, and quota denials, are successful **operation execution**;
they are not infrastructure failures. Backend duration uses the HTTP latency buckets above. Lower storage adapters
are not instrumented again, avoiding double-counting and labels containing storage keys or backend addresses.

## Rejections and internal errors

| Metric | Type | Labels |
| --- | --- | --- |
| `flasgo_http_rejections_total` | Counter | `route`, `reason` |
| `flasgo_internal_errors_total` | Counter | `phase`, `reason` |
| `flasgo_metrics_auth_failures_total` | Counter | `reason` |

Rejection reasons are `host`, `cors`, `csrf`, `authentication`, `permission`, `security_rate_limit`, `rate_limit`,
`capacity`, `validation`, `request_head_limit`, `request_body_limit`, `request_read_timeout`, `multipart_limit`, and
`form_limit`. Each reason is counted at most once per HTTP request. Pre-routing rejections use `<unmatched>`.
Validation/limit exceptions remain diagnostic observations even if a custom error handler changes the response.
Application-generated status codes are not used to infer a reason. Backend exceptions are reported as backend/internal
failures rather than ordinary credential denials. Built-in local/shared rate-limit capacity
exhaustion and local session-store capacity failures have explicit capacity observations.

Internal phase/reason pairs include `dispatch/unhandled_exception`, `response_prepare/failure`,
`dependency_cleanup/failure`, `error_handler/failure`, `backend/unavailable`,
`authentication/backend_error`, `authentication/backend_missing`, and `authorization/permission_error`.
These include security events during WebSocket authorization. HTTP rejection counters exclude WebSocket upgrades.
Metrics-endpoint authentication uses `invalid_credentials` or `throttled` on its dedicated counter, without ordinary
HTTP self-instrumentation. Counter updates do not depend on `LOG_SECURITY_EVENTS`.

Diagnostic counters overlap with request and backend counters: do not sum them as a request total. They supplement
existing security logs and do not replace audit records or an application's monitoring policy.

## Background work

| Metric | Type | Labels |
| --- | --- | --- |
| `flasgo_background_tasks_active` | Gauge | None |
| `flasgo_background_tasks_pending` | Gauge | None |
| `flasgo_background_task_duration_seconds` | Histogram | None |
| `flasgo_background_tasks_total` | Existing counter, extended outcomes | `outcome` |

Pending tracking begins when the framework sees an attached response, not when an unattached `BackgroundTasks`
object is constructed. It includes registered tasks awaiting execution, including tasks added while tracking is
active. Replaced/undeliverable responses and cancelled execution release their remaining pending tasks as `skipped`.
Running tasks report `success`, `failure`, or `cancelled`; skipped tasks have no duration sample. Existing success
and failure outcomes keep their meaning. These four outcome counters start at zero.

Tasks remain sequential and best effort. Duration measures the awaited task call, including thread dispatch for
synchronous tasks. Cancelling an await cannot stop an already running Python worker thread: the `cancelled` outcome
and active gauge describe the framework call, not proof that the underlying thread has stopped. There is no durable
queue, retry, or delivery guarantee. No task arguments, callable names, or request identities become labels.
Background buckets extend the HTTP buckets with 30, 60, 300, 900, and 3600 seconds.

## Event-loop responsiveness

`flasgo_event_loop_lag_seconds` is a histogram of delay beyond a scheduled callback, using the event loop's monotonic
clock. Buckets are 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, and 10 seconds, plus infinity.
A delayed callback creates one sample and schedules the next interval; it does not replay missed samples.

- `METRICS_EVENT_LOOP_ENABLED`: boolean, default `True`; takes effect only when metrics are enabled.
- `METRICS_EVENT_LOOP_INTERVAL_SECONDS`: default `0.1`; finite numeric values from `0.01` through `60` are accepted.
- `flasgo_event_loop_sampler_running`: gauge, `1` while scheduled and `0` otherwise.

The sampler starts after successful application startup and stops when lifespan exits, including exceptional exits.
It creates no task or thread and performs no backend calls. Without lifespan startup, the lag histogram is absent
and the running gauge is zero. The histogram persists after shutdown, so consult the running gauge and sample count
before interpreting a zero lag value. A fully blocked event loop also cannot serve a scrape until it recovers.

## Application metrics

`app.metrics_registry` is the supported, read-only property exposing the application-local `CollectorRegistry`.
It returns `None` when metrics are disabled and does not import the optional Prometheus dependency in that mode.
Use the standard Prometheus client constructors during application setup:

```python
registry = app.metrics_registry
completed = None
if registry is not None:
    from prometheus_client import Counter

    completed = Counter(
        "application_reports_completed_total",
        "Reports completed successfully.",
        registry=registry,
    )

# After successful application work:
if completed is not None:
    completed.inc()
```

`Gauge` and `Histogram` accept the same registry argument. Duplicate names raise `ValueError` during registration.
Multiple Flasgo apps have isolated registries. Avoid passing `registry=None` to client constructors as a substitute
for the guard: it has a different meaning in the Prometheus client.

Custom backend adapters can similarly time their operations with a registered `Histogram` and record outcomes with
a `Counter`; use fixed operation/outcome labels and preserve the original exceptions. Do not repeat instrumentation
for calls already covered by Flasgo's logical backend measurements.

Authenticated collection and encoding are offloaded with `asyncio.to_thread` so larger registries do not render
entirely on the event loop. Cancelling a scrape cannot forcibly stop a collector already running in that thread.
Custom collectors use `registry.register(collector)` and `registry.unregister(collector)`. Implement the client
collector `describe()` method so duplicate names can be detected at registration without running collection. They are trusted application
code and run synchronously in a worker thread after scrape authentication succeeds. They must be fast and must not make network calls, scan
large stores, mutate application state, or emit credentials or personal data. Use a distinct application prefix and
small, fixed label sets. Flasgo cannot enforce the cardinality or behavior of application-supplied collectors.

Unlabelled gauges, background/metrics-auth/backend outcome counters, and known internal-error pairs expose initial
zeros. Other labelled series are
created when observed, avoiding a route-by-outcome histogram expansion at startup. A missing labelled series means
it has not been observed in this process, not necessarily that instrumentation is disabled. Metrics still use a
per-process registry; no new aggregation mode is introduced.

## Validation and security scope

Regression tests cover registry isolation and duplicate detection, both exposition formats, authentication before
collection, disabled optional dependencies, sampler lifetime, cancellation, partial stream bytes, timeout origins,
SSE heartbeats, background work, backend outcomes, and bounded rejection labels.

The implementation supports the relevant [OWASP Top 10:2025](https://owasp.org/Top10/2025/) controls: existing endpoint
authentication and CORS boundaries (A01/A07), opt-in exposure and validated sampler settings (A02), bounded labels and
work (A06), additional security observations without secrets (A09), and exception/cancellation cleanup (A10). No new
dependency or cryptographic mechanism is introduced. This is not a claim of application-wide OWASP certification;
application authorization, custom collectors, deployment controls, and monitoring remain application responsibilities.

Run `python -m benchmarks.metrics --requests 500 --rounds 5` for a repeatable local ASGI benchmark of enabled/disabled buffered
requests, 16-chunk streams, and scrapes after observing 1 or 100 routes. It uses no sockets or external backends and
reports median request microseconds, scrape milliseconds, and scrape body bytes. Compare the same script and Python
environment against the previous revision; local overhead measurements are not production capacity estimates.

### Local comparison (2026-09-06)

Compared the pre-change revision `2b7965e` with this implementation on CPython 3.14.7, outside the sandbox, using
500 requests per round and five rounds per case. Each request figure is the median round average; scrape figures
are medians of five scrapes after all routes have been observed. These synthetic measurements exclude network and
backend latency and are subject to host scheduling noise.

| Routes | Response | Metrics | Before, µs/request | After, µs/request |
| --- | --- | --- | --- | --- |
| 1 | Buffered | Disabled | 308.42 | 344.44 |
| 1 | Buffered | Enabled | 324.01 | 418.29 |
| 1 | 16-chunk stream | Disabled | 962.56 | 1081.83 |
| 1 | 16-chunk stream | Enabled | 1068.64 | 1183.37 |
| 100 | Buffered | Disabled | 373.76 | 415.58 |
| 100 | Buffered | Enabled | 424.38 | 523.73 |
| 100 | 16-chunk stream | Disabled | 1049.16 | 1168.65 |
| 100 | 16-chunk stream | Enabled | 1139.25 | 1298.81 |

| Routes | Response | Before scrape, ms | After scrape, ms | After scrape, bytes |
| --- | --- | --- | --- | --- |
| 1 | Buffered | 1.67 | 7.13 | 23918 |
| 1 | 16-chunk stream | 2.08 | 6.64 | 24566 |
| 100 | Buffered | 74.64 | 150.8 | 737100 |
| 100 | 16-chunk stream | 73.47 | 185.62 | 772524 |

The two additional HTTP histograms increase exposition size and scrape work. Rendering is therefore offloaded
after authentication, and a regression test verifies that collection does not run on the event-loop thread.
This does not eliminate CPU cost or guarantee isolation from a slow custom collector.
