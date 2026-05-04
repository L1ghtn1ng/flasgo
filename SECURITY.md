## Supported Versions

| Version | Supported |
| --- | --- |
| `main` | ✅ |
| Latest `0.4.x` release | ✅ |
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

Reports involving bypasses of these defaults, privilege escalation, request smuggling, header injection, path traversal, template escape, session integrity, or SSRF are high priority.

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
- Leave docs disabled unless you explicitly need them, and keep `DOCS_PATH` and `OPENAPI_PATH` distinct.
- Validate outbound user-controlled URLs with Flasgo's SSRF helpers before fetching them. Prefer pinned targets from `resolve_outbound_url()` when your HTTP client supports connecting by IP with the original `Host` header.
- Put a reverse proxy or edge service in front of the app for TLS termination and network controls.

Thank you for helping keep Flasgo secure.
