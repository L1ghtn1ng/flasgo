# Changelog

All notable changes to `flasgo` are documented in this file.

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
