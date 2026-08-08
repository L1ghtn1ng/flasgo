# Changelog

## [Unreleased]

## [0.7.0] - 2026-08-08

### Added

- `Annotated` request binding with `Body()`, `Query()`, `Header()`, `Cookie()`, `Form()`, and async-capable `Depends()` providers, including
  dataclass validation, per-request dependency caching, structured `422` responses, and a redisplay-friendly
  `FormValidationError` contract.
- OpenAPI 3.2 request bodies, reusable dataclass schemas, typed query/header/cookie parameters (including parameters
  supplied by dependencies), validation responses, authorization security requirements, and an explicit JSON Schema
  2020-12 dialect validated by the locked `openapi-spec-validator` dependency in CI.
- OpenAPI 3.2 `QUERY` and `additionalOperations` generation, plus validated local Security Scheme metadata for
  deprecation, OAuth2 metadata discovery, device authorization, extensions, and required scopes or roles.
- Optional `flasgo[jwt]` strict HS256 helpers with issuer, audience, lifetime, subject, and scope validation.
- Optional `flasgo[otel]` HTTP and WebSocket tracing with OTLP/HTTP export, route-template span names, configurable
  sampling and exclusions, request-ID attributes, and trace/span correlation in structured logs.
- OpenAPI operations document the framework error responses that apply to them: `413`/`415` on body and form
  endpoints, `403` on unsafe methods while CSRF protection is enabled, and `429` on rate-limited routes. A root
  `servers` list can be declared with the `API_SERVERS` setting.
- `OTEL_SET_GLOBAL_PROVIDER` (default `True`) registers a Flasgo-built tracer provider as the process-global
  provider so other OpenTelemetry instrumentations share its sampler and exporter.
- `DOCS_AUTH_BACKEND` optionally protects both Swagger UI and the OpenAPI document with a registered auth backend.

### Security

- CSRF double-submit tokens are HMAC-signed and bound to the signed session, rotate when session state changes, and
  reject attacker-fixed or legacy unsigned values. Publicly cacheable responses no longer emit framework-managed
  CSRF or session cookies.
- The in-process rate limiter preserves active quota buckets under key-cardinality pressure and fails closed for new
  keys until safely expired accounting state frees capacity.
- JSON and form model validation rejects unknown dataclass fields, enforces media types, and reports bounded field
  locations without reflecting request values in the default error response.
- Request reads enforce the configured timeout across the complete body, request-head limits apply in both Flasgo
  and its H11 development server, and recursive validation has depth, work, and issue budgets.
- JWT decoding fixes the accepted algorithm to HS256, rejects weak signing secrets and `alg=none`, and requires
  issuer, audience, expiry, issued-at, and subject claims.
- Swagger UI is version-pinned with SRI, disables query-driven configuration and remote validation, and runs its
  inline script and style under a per-request CSP nonce without `unsafe-inline`.
- Header and cookie binding rejects unsafe names, ambiguous duplicate scalar values, and reserved OpenAPI headers.
- The test client accepts ordered header pairs so repeated wire headers can be exercised without collapsing values.
- Route registration rejects empty method collections and malformed HTTP method tokens before they can reach runtime
  dispatch or OpenAPI generation. OAuth/OpenID metadata requires HTTPS and external Security Scheme references are
  rejected.
- Authentication failures and default per-IP route quotas are throttled before HTTP or WebSocket authentication
  backends run. Custom identity-based rate-limit keys continue to run after successful authentication.
- SSRF private-network opt-in is limited to RFC 1918 and unique-local addresses; loopback, link-local, multicast,
  reserved, and unspecified targets remain blocked. Rejected Host values are removed from telemetry input.
- Metrics bearer credentials use a bounded ASCII token grammar and fail closed with `401` instead of raising on
  non-ASCII input. Debug pages expose only an exact environment allowlist.
- OpenTelemetry span names use known HTTP method tokens (including `QUERY`) or the stable fallback `HTTP` for
  non-standard methods, preventing attacker-controlled method tokens from creating unbounded trace-name cardinality.
  OpenAPI HTTP authentication schemes must use RFC 9110 token syntax.

### Fixed

- Endpoint binding plans are stored per route, so one callable can safely serve paths with different parameter names.
- OpenTelemetry HTTP URL attributes now carry the real request path and a query whose values are redacted, satisfying
  stable HTTP semantic conventions while preserving route-template span names and grouping. WebSocket URL attributes
  remain template-only, and dynamic routes can be excluded by route template even when the request method is rejected.
- OpenTelemetry HTTP span names treat `QUERY` as a known method and use `HTTP` (not `_OTHER`) as the name placeholder
  for unknown methods, matching stable OpenTelemetry HTTP server span naming rules.
- JWT scope claim names cannot collide with registered identity/lifetime claims, computed `init=False` dataclass
  fields are excluded from request validation schemas, and numeric/boolean literals accept their typed text forms.
- Optional collection unions, numeric/boolean enum text, and comma-separated collection headers now match their
  generated schemas. Duplicate dependency parameters merge requiredness or reject conflicting schemas.
- Bearer helpers advertise their configured valid HTTP authentication scheme instead of always claiming `bearer`;
  non-token prefixes omit automatic metadata rather than producing an inaccurate client contract.
- Static files stream in bounded chunks without blocking the event loop, and `HEAD` requests do not open or read the
  file. Atomic CLI output replaces a destination symlink itself instead of following it to another file.
- Route registration tolerates unresolved postponed annotations that are not needed for request markers. Optional
  upload collections retain submitted files, fixed-length tuples validate and document each position, and streamed
  static responses derive length and validators from the opened file descriptor.

## [0.6.0] - 2026-07-31

### Added

- ASGI WebSocket routing and helpers with pre-accept host, exact-origin, session, and authorization checks; bounded
  messages and per-connection message throttling; strict close/subprotocol handling; and sync/async test sessions.
- ASGI lifespan support through one `@app.lifespan` async generator, process-global `app.state`, and lifecycle-aware
  test-client contexts.
- Response-attached background tasks that run after a successful send with failure isolation and request correlation.
- Locally generated request IDs, optional JSON logging, bounded structured HTTP/WS/lifespan/background events, and
  an authenticated optional Prometheus metrics extra.
- `flasgo routes`, `flasgo openapi`, and `flasgo check`, plus optional Alembic-backed `flasgo db` migration commands.

### Changed

- `app.run()` and `flasgo run` now use Uvicorn for correct HTTP, WebSocket, and lifespan protocol handling.
- Flasgo now supports Python 3.14 and newer only.
- HTTP responses are completely validated before their first ASGI send, and send failures never trigger an invalid
  second response.

### Security

- WebSocket handshakes deny missing origins by default, require exact same-origin or allowlisted origins, validate
  authentication before acceptance, and do not persist session changes.
- Metrics are disabled by default and require a dedicated bearer token of at least 32 characters when enabled.
- Incoming request IDs are ignored by default and must pass a strict bounded format when explicitly trusted.

## [0.5.4] - 2026-07-26

### Changed
Dependency updates

## [0.5.3] - 2026-07-06

### Fixed

- Static file `304 Not Modified` responses now keep their `public` cache-control headers instead of being overwritten by the no-store enforcement, so conditional revalidation preserves client caching.
- CSRF trusted-origin matching now compares the `Origin` scheme case-insensitively, matching the already case-insensitive host comparison.
- Bearer token extraction now matches the authorization scheme case-insensitively per RFC 7235, so `bearer <token>` is accepted alongside `Bearer <token>`.
- OpenAPI output for optional annotations (`X | None`) now emits OpenAPI 3.1-style `anyOf` with `{"type": "null"}` instead of the 3.0-only `nullable: true`.
- OpenAPI generation now resolves deferred (string) type annotations, so handlers using `from __future__ import annotations` produce accurate parameter and response schemas.
- Responses now recompute `content-length` when sent, so bodies mutated by `after_request` middleware no longer produce a stale length header.

## [0.5.2] - 2026-05-27

### Fixed

- Fixed shared-scope rate limiting so multiple rules attached to the same route count each request once, preserve atomic denial behavior, and prune expired bucket entries without dropping data needed by longer-window rules.

## [0.5.1] - 2026-05-06

### Added

- Added per-route rate limiting with `@app.ratelimit(...)` and the standalone `@rate_limit(...)` decorator, including shared scopes, custom key functions, `429 Too Many Requests` responses, and standard rate-limit headers.
- Added `RateLimitRule` and `rate_limit` to the public `flasgo` package API.
- Added documentation for route rate limiting, production deployment notes, and a codebase guide for contributors.
- Added regression coverage for client-IP limits, shared route scopes, custom key functions, and authenticated-user rate-limit keys.

### Changed

- Updated project metadata to point the homepage and documentation URLs at `https://flasgo.dev`.
- Refreshed `uv.lock`.
- Added `releases.astral.sh` to the CI egress allowlist for release tooling.

### Fixed

- Updated the README PyPI badge to use the live PyPI version endpoint so it reflects the latest published `flasgo` release.

## [0.5.0] - 2026-05-04

### Breaking Changes

- Removed `Flasgo.validate_outbound_url()` and `SSRFGuard.validate_url()` in favor of `Flasgo.resolve_outbound_url()` and `SSRFGuard.resolve_url()`, which return a pinned `SSRFResolvedURL` target for safer outbound fetches.

### Added

- Added `SSRFResolvedURL` to the public API so callers can connect to a resolved IP while preserving the original `Host` header.
- Added regression coverage for pinned SSRF targets, invalid outbound URL ports, disabled SSRF behavior, allowed userinfo preservation, docs UI escaping, debug error page escaping, and stricter Host header parsing.

### Changed

- SSRF tests now use Cloudflare's public `1.1.1.1` IPv4 address for public-resolution fixtures.
- Documentation now recommends `resolve_outbound_url()` for user-controlled outbound URLs and explains how to use `target.url` with `target.host_header`.
- Host header validation now handles bracketed IPv6 hosts and rejects malformed host ports.

### Fixed

- Docs UI settings are now escaped in both HTML and JavaScript contexts to prevent reflected injection through `API_TITLE` or `OPENAPI_PATH`.
- Debug-mode template error pages now render with autoescaping enabled to prevent reflected HTML/script execution in development diagnostics.
- SSRF pinned URLs now preserve explicitly allowed userinfo and no longer inspect malformed URLs when SSRF protection is disabled.

## [0.4.1] - 2026-03-13

### Added

- Debug-mode template failures now render a dedicated HTML error page with richer traceback and environment details to improve local development diagnostics (`#20`)

### Changed

- Debug test coverage now uses the built-in `TestClient` consistently, and templating coverage now includes custom template test registration scenarios
- Dependency updates (`#15`, `#16`, `#17`, `#18`, `#19`, `#21`, `#22`, `#23`, `#24`, `#25`): bumped `ty` to `0.0.21`, `ruff` to `0.15.5`, `astral-sh/setup-uv` to `7.4.0`, `github/codeql-action` to `4.32.6`, `step-security/harden-runner` to `2.15.1`, `actions/dependency-review-action` to `4.9.0`, and `actions/upload-artifact` to `7.0.0`

### Fixed

- Template test registration now keeps custom Jinja test callables correctly typed when they are attached to the environment

## [0.4.0] - 2026-03-04

### Added

- Public helper APIs for OpenAPI generation (`Flasgo.openapi_spec()`), dev-server reload control (`build_reload_command()`, `run_with_reload()`), and session signing utilities (`b64encode()`, `b64decode()`, `hmac_digest()`)

### Changed

- Error responses now return clearer, fix-oriented messages for invalid hosts, CSRF failures, malformed JSON, multipart parsing errors, oversized request bodies, auth failures, unsupported methods, and internal server failures
- `405 Method Not Allowed` responses now include an `Allow` header for docs and routed endpoints
- CLI app-loading failures now explain how to fix bad import strings, missing files, and wrong app variable names
- Public API typing and docstrings were tightened for request/session/user proxies and response helpers
- README and migration guide were updated to document the clearer parsing and method-handling behavior

### Fixed

- Dev-server and template code now compile cleanly after correcting the template loader exception syntax
- Security event logging now sanitizes control characters before writing request-derived values to logs
- Tests now assert the new error wording and public helper names directly

## [0.3.1] - 2026-02-28

### Changed

- Dependency update: added `watchfiles==1.1.1`

## [0.3.0] - 2026-02-28

### Added

- Built-in form parsing for `application/x-www-form-urlencoded` and `multipart/form-data`
- Built-in static file support with traversal, dotfile, and symlink escape protections
- Official first-party test client via `flasgo.testing.TestClient` and `app.test_client()`
- Canonical Flask migration guide with official examples for templates, JSON APIs, redirects, forms, static assets, testing, and ASGI deployment
- Automatic reload support for the built-in dev server
- CLI entrypoint: `flasgo run app.py --reload` and `flasgo run package.module:app --reload`
- Redirect helpers via `redirect(...)` and `Response.redirect(...)`

### Changed

- Documentation examples now align on secure defaults for production use, including strong secrets, explicit `ALLOWED_HOSTS`, and secure cookies over HTTPS
- Testing examples explicitly call out when CSRF is disabled for test-only usage
- `release.md` is now process-focused, with release history tracked here

## [0.2.0] - 2026-02-28

### Added

- secure Jinja templating support for HTML rendering
- `JinjaTemplates`, `render_template`, and `Response.template` helpers
- Hardened template loading with path traversal and symlink escape protections
- Template tests covering autoescaping, sandboxing, strict undefined values, and oversized template rejection

### Changed

- Installation and templating documentation were expanded for PyPI usage and the new template API

## [0.1.0] - 2026-02-22

### Added

- Initial public Flasgo framework release with ASGI app core
- Decorator-based routing with Flask-style path converters
- Request and response primitives, sessions, auth helpers, OpenAPI docs, SSRF protections, and a built-in test client
- Built-in development server, packaging metadata, CI, publishing workflow, and baseline test suite
- BSD 3-Clause licensing and project metadata

### Changed

- Project renamed from `fango` to `flasgo` because of a PyPI naming clash
