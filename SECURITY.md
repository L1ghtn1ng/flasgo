## Supported Versions

| Version | Supported |
| --- | --- |
| `main` | ✅ |
| Latest `0.7.x` release | ✅ |
| Older `0.x` releases | ❌ |

Security fixes are made against `main` first and may be backported to the latest release line when practical. If you are running an older release, upgrade to the newest available version before requesting support.

## Reporting a Vulnerability

Please do **not** report security issues in public GitHub issues, pull requests, discussions, or chat threads.

Instead, use one of these private channels:

1. Prefer GitHub's private vulnerability reporting for this repository.
2. If private reporting is unavailable, contact the maintainer through the Twitter address link on the repository owner's GitHub profile and include `flasgo security report` as the header in a DM.

Please include as much of the following as possible:

- A clear description of the issue and the affected Flasgo component.
- The exact Flasgo version, Python version, and deployment setup.
- Whether the issue affects development-only behaviour, production behaviour, or both.
- Reproduction steps, proof-of-concept code, requests, or configuration snippets.
- Impact assessment, including what an attacker can gain or bypass.
- Any suggested remediation or mitigation if you already have one.

## Response Expectations

- Initial acknowledgement target: within 3 business days.
- Triage target: within 7 business days after acknowledgement.
- After triage, we will share whether the report is accepted, needs more information, or is out of scope.
- Fix timing depends on severity, exploitability, release risk, and maintainer availability.

Please avoid public disclosure until a fix or mitigation is available and maintainers have had a reasonable chance to prepare a release.

## Scope and Priorities

Flasgo is an async-first Python web framework with secure defaults. Reports are especially valuable when they affect the framework's built-in protections, including:

- Host allowlist enforcement.
- CSRF protection, including token and origin validation.
- Signed session cookies.
- No-store cache headers for sensitive responses.
- Request size or timeout enforcement and malformed request handling.
- Security event logging and failure throttling.
- SSRF validation helpers for outbound URLs.
- API docs exposure, especially cases where docs become reachable when `ENABLE_DOCS=False`.
- WebSocket origin, host, authentication, message-size, rate, or close-state enforcement.
- Metrics authentication, request-ID trust, and structured log injection.
- Typed body, query, header, cookie, and form validation; JWT claim or algorithm enforcement; and OpenTelemetry data
  leakage or cardinality.

Reports involving bypasses of these defaults, privilege escalation, request smuggling, header injection, path traversal, template escape, session integrity, or SSRF are high priority.

## OWASP Top 10:2025

Flasgo's defaults are designed around the OWASP Top 10:2025 categories: route authorization and deny-before-accept
WebSockets (A01/A07), validated settings and disabled-by-default docs/metrics (A02), pinned dependencies and lockfile
auditing (A03), strong secret and signed-session requirements (A04/A08), bounded parsing plus response/header/log
validation (A05), same-origin WebSocket and SSRF protections (A06), structured security events and request
correlation (A09), and fail-closed lifecycle/auth handling without invalid second responses (A10). Applications still
need their own authorization policy, secret management, dependency updates, monitoring, and deployment controls.

## Safe Harbor for Researchers

We appreciate coordinated, good-faith security research that helps improve Flasgo.

Please:

- Test only against systems you own or are explicitly authorised to assess.
- Minimize data access, retention, and service impact.
- Stop testing and report promptly if you encounter sensitive real-world data.
- Avoid social engineering, physical attacks, spam, denial-of-service, or supply-chain compromise attempts.

## Hardening Guidance for Users

Flasgo ships with security features enabled by default, but deployment still matters. For production deployments:

- Run the latest supported Flasgo release on Python `3.14+`.
- Set a strong `SECRET_KEY` and keep it private.
- Restrict `ALLOWED_HOSTS` to your real application hosts.
- Keep CSRF protections enabled for browser-facing apps.
- Keep signed cookies and secure cookie flags enabled behind HTTPS.
- Leave docs disabled unless you explicitly need them. When they are reachable outside a trusted development
  environment, set `DOCS_AUTH_BACKEND` to a registered authentication backend and keep `DOCS_PATH` and
  `OPENAPI_PATH` distinct.
- Keep WebSocket origin enforcement enabled. Allow only exact trusted origins and do not allow missing origins for
  browser sessions that use cookie authentication.
- Keep WebSocket message and concurrency limits enabled, and apply tighter edge limits for public deployments.
- Keep metrics disabled unless needed; when enabled, use a dedicated 32-character-or-longer bearer-safe ASCII secret
  and restrict the endpoint at the network edge too.
- Keep `MAX_REQUEST_BODY_BYTES`, `MAX_REQUEST_HEAD_BYTES`, `REQUEST_READ_TIMEOUT_SECONDS`, and the validation depth,
  work, and issue budgets enabled. Mirror appropriate limits at the production server and network edge.
- Trust incoming request IDs only when a trusted proxy replaces client-supplied values.
- For `flasgo[jwt]`, use a dedicated random secret of at least 32 bytes, rotate it through a controlled deployment,
  validate a service-specific issuer and audience, keep tokens short-lived, and transmit them only in the
  `Authorization` header. The built-in helper intentionally supports HS256 only; use an audited application-owned
  backend when asymmetric signing or key discovery is required.
- Treat custom `openapi_scheme` values as trusted configuration. Flasgo accepts only local concrete Security Scheme
  Objects, requires HTTPS for OAuth/OpenID endpoints, and does not follow external Security Scheme references. The
  metadata documents a backend but does not implement or verify the advertised OAuth flow.
- Keep OpenTelemetry disabled unless traces are needed. Send OTLP only to a trusted TLS collector, treat exporter
  headers as secrets, exclude sensitive endpoints by exact path or route template, and avoid adding request bodies,
  credentials, or user identifiers as span attributes. Template exclusions apply even when a request receives
  `405 Method Not Allowed`. HTTP URL attributes contain the real request path as required by stable semantic
  conventions, so exclude routes whose path segments carry secrets or sensitive identifiers.
  Flasgo retains query keys but replaces every non-empty query value with `REDACTED` before instrumentation;
  WebSocket URL attributes remain route-template-only. Rejected or ambiguous Host headers are removed before the
  request reaches instrumentation.
- Treat migration files as trusted executable code: review generated revisions before applying them and restrict who
  can modify the migration directory.
- Validate outbound user-controlled URLs with Flasgo's SSRF helpers before fetching them. Prefer pinned targets from
  `resolve_outbound_url()` when your HTTP client supports connecting by IP with the original `Host` header. The
  private-network opt-in permits RFC 1918 and unique-local addresses only; it never permits loopback or link-local
  destinations.
- Put a reverse proxy or edge service in front of the app for TLS termination and network controls.

Thank you for helping keep Flasgo secure.
