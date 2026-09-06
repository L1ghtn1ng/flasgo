# Building and operating larger Flasgo applications

Existing applications retain their routing, response coercion, signed-cookie sessions, and in-process rate limiter until they opt into the new APIs.

## Inspecting security policy

```bash
uv run flasgo routes app.py --policy
uv run flasgo routes app.py --json > policy.json
uv run flasgo check app.py --deploy
uv run flasgo check app.py --deploy --json
uv run flasgo check app.py --against policy.json --json
```

`routes --json` emits a versioned snapshot of registered HTTP and WebSocket routes, authentication backend names,
permissions, CSRF methods, CORS policies, quotas, response contracts, application limits, and internal endpoint
configuration. It excludes session data, signing keys, metrics credentials, and storage connection strings.
Custom permission callables are identified by name; their meaning and application middleware remain application-owned.
A snapshot cannot establish that an authentication backend validates credentials correctly or that arbitrary
middleware preserves the described policy. Keep snapshots in the development/review workflow, not a public endpoint.

`check --deploy` adds warnings for debug mode, relaxed host/cookie/CSRF/origin/cache controls, unprotected docs,
disabled security logging, and routes without an explicit access declaration. Warnings cause a nonzero exit status.
`public=True` records intentional public access; it does not bypass CSRF, rate limiting, host checks, or existing
authorization. An authorization decorator combined with `public=True` is a contradictory declaration and fails the
deployment check. A warning about disabled CSRF requires application review: an API that accepts only explicit bearer
credentials differs from an API that also accepts browser cookies.

`check --against` accepts a `routes --json` snapshot, reports changed application controls and individual added,
removed, or changed routes, and returns nonzero for any change. Review intended changes before replacing the
baseline. It compares declared policies, not Python code or custom authorization semantics. Input snapshots are
limited to 2 MiB. Normal `flasgo check app.py` retains its registration checks.

## Blueprints and URL generation

```python
from flasgo import Blueprint, Flasgo, HasScope, IsAuthenticated

app = Flasgo()
api = Blueprint("api", url_prefix="/api", permissions=[IsAuthenticated()])
reports = Blueprint("reports", url_prefix="/reports", permissions=[HasScope("reports:read")])


@reports.get("/<int:report_id>", name="detail")
def report(report_id: int) -> dict[str, int]:
    return {"id": report_id}


api.register_blueprint(reports)
app.register_blueprint(api)
# Register an application-owned authentication backend before serving requests.

assert app.url_for("api.reports.detail", report_id=42) == "/api/reports/42"
```

`Blueprint` groups HTTP routes. Its `get`, `post`, `put`, `patch`, `delete`, `route`, and `add_route` APIs match the
application. WebSockets continue to use `app.websocket`. Nested prefixes and names compose. Group `permissions`,
`dependencies`, and `rate_limits` are additive. Protected parents and protected children must use the same `backend`;
a route cannot declare itself public inside a protected group. Public routes belong in a separate group. CORS inherits
when omitted and can be explicitly replaced with a route/group `CORSConfig` or disabled with `cors=False`.

Registration takes a snapshot: subsequent changes to a blueprint or its original endpoint decorators do not modify
an already registered application. Each registration uses separate endpoint metadata. Cycles and duplicate names or
HTTP registrations reject the whole registration without retaining partially registered routes.

Use `name=` for stable URL names. `app.url_for(name, **values)` works outside a request; `flasgo.url_for` uses the active
request's application. `app.configure_templates()` supplies `url_for` to Jinja by default. Converters are validated,
parameters and query values are encoded, ambiguous names raise an error, and traversal/authority forms are rejected.
The active request's ASGI `root_path` is included when generating URLs inside a mounted application. Outside a request,
URLs are relative to the application's root. URL generation does not accept an external host or scheme.

## Dependency lifetimes and test overrides

```python
from typing import Annotated, Protocol, runtime_checkable
from flasgo import Depends, Flasgo

app = Flasgo()


@runtime_checkable
class Database(Protocol):
    async def list_public_users(self) -> list[dict[str, object]]: ...


async def database_session():
    async with app.state.database.session() as database:
        yield database


@app.get("/users")
async def users(database: Annotated[Database, Depends(database_session)]):
    return await database.list_public_users()
```

Providers may return an ordinary value, return an awaitable, or yield exactly one value from a sync/async generator.
Use `try/finally` or a context manager inside the provider for cleanup. Application exceptions reach the provider at
its `yield`; providers must re-raise exceptions rather than suppressing them. Resources close in reverse acquisition
order, including when binding, validation, or the handler fails.

- `Depends(provider, scope="request")`, the default, retains the resource until response sending finishes or fails.
  It supports a resource used by a streaming producer. Cleanup runs before background tasks.
- `Depends(provider, scope="function")` closes the resource before response headers are sent. Use this scope for
  transaction boundaries whose commit failure must prevent a successful response.
- A request-scoped provider cannot depend on a function-scoped provider. Cache identity includes the declared scope;
  `use_cache=False` acquires a separate value/resource for each binding.
- A request-scoped cleanup failure after response delivery is logged; the framework cannot retract an already sent
  response. Critical transactions must finish before sending. Background tasks must acquire their own resources.

Ordinary synchronous providers retain their existing execution behavior. Keep their work short and nonblocking; use
async database/network APIs for I/O. Cleanup and cancellation require cooperative application code.

Routes and blueprints accept `dependencies=[Depends(...)]` for providers whose result is not injected into a handler
parameter, such as an audit or prerequisite check. Their request parameters participate in binding and OpenAPI.
Inherited authorization and rate checks execute before these dependencies.

```python
with app.override_dependencies({database_session: fake_database_session}):
    response = app.test_client().get("/users")
```

Overrides are context-local, nest safely, and restore automatically. They do not mutate global provider registrations
or the public OpenAPI contract. Concurrent async tests can use different overrides on the same application. Replacement
providers undergo the same binding, lifetime, and cycle checks. Declare providers at module scope when using postponed
string annotations; Python 3.14's native deferred annotations also work.

## Enforced response contracts

```python
from dataclasses import dataclass
from flasgo import Flasgo

app = Flasgo()


@dataclass
class PublicUser:
    id: int
    display_name: str


@app.get("/user", response_model=PublicUser, public=True)
def user() -> dict[str, object]:
    return {"id": 1, "display_name": "Alice", "internal_note": "not part of the public response"}
```

The response contains only `id` and `display_name`. Filtering applies recursively to dataclasses and typed containers.
Output types, required fields, finite numbers, and bounded validation are enforced before sending. Dataclass models
can project mappings or other dataclass instances without constructing the output dataclass. Underscore-prefixed
fields remain private and are omitted from output schemas. Ordinary mapping keys remain application data; use explicit
public dataclasses when fields must be filtered. `Any` intentionally permits arbitrary bounded JSON-compatible data.

Invalid output produces a safe `500` through `ResponseValidationError`, rather than reflecting rejected values as a
request-validation error. Custom exception handlers must preserve that confidentiality. Tuple return values retain
their status and headers. A raw `Response` cannot bypass a declared response contract: raise `HTTPException` for an
error response, or use a separate uncontracted route where raw responses are required. Trusted application middleware
can still modify responses and requires its own review.

Only `response_model=` enables runtime enforcement. Existing return annotations continue to describe OpenAPI without
changing existing response coercion. Routes with no response model retain their current behavior.

## Streaming, SSE, and NDJSON

```python
import asyncio
from flasgo import EventSourceResponse, Flasgo, ServerSentEvent

app = Flasgo()


@app.get("/progress", public=True)
def progress() -> EventSourceResponse:
    async def events():
        for step in range(3):
            yield ServerSentEvent({"step": step}, event="progress", id=str(step))
            await asyncio.sleep(0.1)

    return EventSourceResponse(events())
```

`StreamingResponse` accepts an async iterable of bytes or strings. `NDJSONResponse` accepts async items and emits one
JSON value per line. `EventSourceResponse` accepts `ServerSentEvent` objects; data is JSON encoded so embedded newlines
cannot introduce another SSE field. Event names/IDs reject control characters and are length-bounded; retry values are
validated integers. Optional `item_model=` applies a response contract to each SSE/NDJSON item's data. Annotate the
response class so OpenAPI advertises the corresponding streaming media type. Item schemas selected inside a handler
are runtime configuration and are not inferred into OpenAPI.

Defaults are a 64 KiB chunk/event limit, a 10-second send timeout, a 60-second wait for the next output chunk, and a
one-hour maximum connection lifetime. Constructor options `max_chunk_bytes`, `send_timeout`, `idle_timeout`, and
`max_duration` configure these positive finite limits. SSE emits a heartbeat every 15 seconds (`heartbeat=`), which
counts as output for the idle timeout; the maximum lifetime still applies. Per-item JSON validation uses bounded
validation budgets. Producers must also avoid allocating oversized data themselves.

Sending awaits the ASGI transport before requesting the next chunk. A disconnect, send timeout, or producer failure
closes the source and request dependencies. If headers have already been sent, an error terminates the stream without
sending a second response or appending diagnostic data. Background tasks run only after successful completion.
`HEAD` sends headers without iterating content. Response instances are single-use, have no `Content-Length`, and retain
normal security headers. Framework session/cookie changes must occur before the handler returns; modifications made
inside the producer cannot update already sent cookies. Sessions loaded before a stream opens are not continually
revalidated during that connection.

SSE sends `Cache-Control: no-store` and `X-Accel-Buffering: no`; configure proxy buffering and connection timeouts to
match. Event IDs support application-defined replay: read `Last-Event-ID` through `Header()` or `Request` and validate
access to the requested history. Flasgo does not store events or promise automatic replay. Browser-native EventSource
uses GET and does not let applications set arbitrary authorization headers; choose authentication appropriate to the
client without placing credentials in URLs. CORS and CSRF continue to apply normally.

Tests can read streams incrementally and disconnect deterministically:

```python
async with app.test_client().astream("GET", "/progress") as response:
    assert response.status_code == 200
    first_chunk = await anext(response.iter_bytes())
```

`astream` is for async tests, optionally inside the client's async lifespan context. Its one-message queue preserves
backpressure. Leaving the context disconnects; a stream ending without a final body event raises an incomplete-response
error. The ordinary buffered test client remains useful for finite streams.

## Shared quotas and server-side sessions

```bash
uv add 'flasgo[redis]'
```

```python
import os
from flasgo import Flasgo, RedisRateLimiter, RedisStore, ServerSideSessions

store = RedisStore.from_url(os.environ["FLASGO_REDIS_URL"], namespace="billing")
app = Flasgo(
    settings={"SECRET_KEY": os.environ["FLASGO_SECRET_KEY"]},
    rate_limiter=RedisRateLimiter(store),
    session_backend=ServerSideSessions(store),
)


@app.lifespan
async def lifespan(app: Flasgo):
    try:
        yield
    finally:
        await store.aclose()
```

Use a TLS `rediss://` URL and appropriate credentials for a remote service. Redis and Valkey use the same adapter.
Connection acquisition and operations have finite timeouts; the convenience constructor caps the pool at 100
connections. `RedisStore(client, ...)` can wrap an application-owned async Redis-compatible client, whose lifecycle
remains application-owned. `aclose()` closes only a client created by `from_url`.

Give each application a distinct stable namespace and use the same namespace and signing secret across its workers.
A namespace's keys share a cluster hash slot to keep multi-key Lua operations atomic; this deliberately trades
cross-slot scaling for consistent accounting. Use a dedicated, authenticated store with `noeviction`, suitable
persistence/availability controls, and restrictive access. If a server evicts or loses security state, an application
cannot reconstruct previous quotas. Never use a cache configured to discard live keys for this purpose.

`RedisRateLimiter` implements shared sliding windows with server time, atomic evaluation of all rules in one phase,
and a bounded number of active quota keys (`max_keys=10000`). Capacity pressure rejects new keys without evicting
existing quotas. It supports up to 64 rules per phase. Its default identities use protocol, route path/methods, and
rule position, never process-local object IDs. Explicit `scope=` shares a quota across routes. HTTP methods belonging
to separate route registrations have separate default quotas; GET/HEAD in the same registration share one. Keep rule
configuration consistent across workers. The existing in-process limiter retains its callable-based behavior.
Authentication-failure throttling and per-WebSocket message throttling remain process-local; shared storage here
coordinates decorated route quotas. Keep edge protections for aggregate abuse control.

Storage errors return `503`, without falling back to independent per-worker quotas or accepting unauthenticated
session state. A distributed timeout may occur after the server applied an operation; retryable callers must account
for that uncertainty. Quotas are abuse controls, not an exactly-once application transaction mechanism.

`ServerSideSessions` stores bounded JSON behind a random 256-bit opaque cookie identifier. `Session.regenerate()`
rotates the identifier on the next save; call it after login or privilege changes. `Session.clear()` deletes the
session when saved. `backend.revoke(session_id)` supports explicit revocation; treat `Session.session_id` as a
credential and never log it. Session metadata is private to response serialization.

Updates compare the previously loaded stored value before replacing it. Rotation atomically replaces the identifier.
A stale concurrent write, expired session, or revoked session produces `409` rather than recreating old authenticated
state. Applications must not blindly replay side effects after a session conflict: arrange session changes before
irreversible work or use application transactions/idempotency as appropriate. Expiry uses `SESSION_COOKIE_MAX_AGE`;
modified saves refresh the storage TTL. Revocation affects subsequent loads, not requests/connections already using
an acquired identity. WebSocket handlers do not persist session changes.

Signed-cookie sessions remain the default. Switching an existing deployment to server-side sessions intentionally
requires users with old signed cookies to log in again; no implicit cookie-format migration is attempted. CSRF remains
bound to the actual session cookie, including identifier rotation. `MemoryStore` supplies bounded process-local
storage for development/tests. New sessions are created only when modified, with a default maximum serialized size
of 64 KiB. Store failures must be monitored through Flasgo's structured security events (`StoreUnavailable`).

## Validation and security model

Run the existing README verification commands. Shared-storage integration tests use `FLASGO_TEST_REDIS_URL` if set,
otherwise launch an isolated local `redis-server` or `valkey-server` over a temporary Unix socket. They require local
socket permissions. Without either an installed server or an explicit URL, these integration tests are skipped.
CI supplies pinned Redis and Valkey service images and runs the full suite against both.

Python's [context manager semantics](https://docs.python.org/3.14/library/contextlib.html) and the
[ASGI response/disconnect protocol](https://asgi.readthedocs.io/en/latest/specs/www.html) define the lifecycle boundaries.
