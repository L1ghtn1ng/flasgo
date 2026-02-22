# Flasgo Project Guidelines

This document defines the engineering baseline for work in this repository.

## Scope

- Project: `flasgo`
- Language/runtime: Python `3.14+`
- Framework style: async-first, strongly typed, security-default

## Core Principles

- Prefer explicit, typed APIs over dynamic behavior.
- Keep the framework small and composable.
- Security defaults must remain enabled unless there is a strong, documented reason.
- Backward-compatible changes are preferred for public API behavior.

## Python 3.14 Best Practices

- Use modern typing syntax:
  - `type` aliases (not `TypeAlias`)
  - `X | Y` unions
  - precise return types for all public functions
- Use `dataclass(slots=True)` for small data containers unless mutation patterns require otherwise.
- Prefer `collections.abc` imports for protocols/types (`Callable`, `Mapping`, etc.).
- Keep functions focused and side effects explicit.
- Use async/await for I/O-facing paths; avoid blocking calls in request handling.

## Repository Tooling

- Dependency and environment management: `uv`
- Linting/format checks: `ruff`
- Type checking: `ty`
- Testing: `pytest`

## Required Local Commands Before Finishing Work

```bash
uv run ruff check .
uv run ty check
uv run pytest
```

All three commands must pass before considering a change complete.

## Dependency Management Rules

- Update dependencies via `uv`.
- Keep runtime dependencies minimal.
- Prefer pinned versions where the project already pins them.
- Do not add large dependencies when stdlib or existing code can solve the task.

## Testing Rules

- Add/adjust tests for every behavior change.
- Keep tests deterministic and isolated.
- For security features, add regression tests for both allow and deny paths.
- Prefer unit-style tests in `tests/` using the in-repo test client.

## Security Baseline (Must Preserve)

Do not weaken these defaults without explicit approval:

- Host allowlist checks
- CSRF protections (token + origin checks)
- Signed session cookies
- No-store cache headers (CWE-524 mitigation)
- Request size/time limits and malformed request handling
- Security event logging and failure throttling
- SSRF validation helpers for outbound URLs (CWE-918)
- Docs disabled by default (`ENABLE_DOCS=False`)

When adding features, assess OWASP Top 10 implications and keep secure-by-default behavior.

## API Docs Behavior

- OpenAPI/Swagger docs are available only when enabled via settings.
- `DOCS_PATH` and `OPENAPI_PATH` must remain distinct and validated.
- New routing features should continue to appear in generated OpenAPI output.

## Release and CI Expectations

- CI workflow must continue to run lint/type/test on PRs and main.
- Tagged releases (`v*`) must keep `uv build` + `uv publish` workflow compatibility.
- Keep `pyproject.toml` version and release tag aligned.

## Contributor Notes

- Keep changes small and focused.
- Prefer clarity over cleverness.
- Update `README.md` for any user-visible behavior/configuration changes.
