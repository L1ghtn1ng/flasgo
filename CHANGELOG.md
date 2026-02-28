# Changelog

All notable changes to `flasgo` are documented in this file.

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
