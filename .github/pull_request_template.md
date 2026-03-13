## Summary

- Describe the problem this pull request solves.
- Summarize the approach and any notable trade-offs.

## Changes

- List the key code, test, documentation, or workflow changes.
- Mention any public API, settings, or behaviour updates.

## Validation

- [ ] `uv run ruff check .`
- [ ] `uv run ty check`
- [ ] `uv run pytest`
- [ ] Added or updated tests for behaviour changes
- [ ] Any new code is using type annotations

## Security Review

- [ ] No security defaults were weakened without explicit justification
- [ ] Reviewed OWASP-style(2025 spec) implications for the changed area
- [ ] Considered relevant protections when applicable:
  - [ ] Host allowlist checks
  - [ ] CSRF token and origin checks
  - [ ] Signed session cookies
  - [ ] No-store cache headers
  - [ ] Request size/time limits and malformed request handling
  - [ ] Security event logging and failure throttling
  - [ ] SSRF validation helpers for outbound URLs
  - [ ] Docs remain disabled by default unless intentionally changed

## Documentation and API Impact

- [ ] No user-visible behavior changed
- [ ] Updated `README.md` for user-visible behaviour or configuration changes
- [ ] Updated generated docs/OpenAPI behaviour if routing or docs features changed
- [ ] Verified `DOCS_PATH` and `OPENAPI_PATH` remain distinct when docs-related settings changed

## Compatibility and Release Notes

- [ ] Backward-compatible change
- [ ] Breaking change (describe below)
- [ ] CI expectations remain intact (`ruff`, `ty`, `pytest`)
- [ ] Release workflow impact considered (`uv build` / `uv publish`, version/tag alignment)

## Additional Notes

- Link-related issues, follow-ups, migrations, or rollout notes.