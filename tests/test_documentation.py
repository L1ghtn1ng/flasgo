from __future__ import annotations

import tomllib
from pathlib import Path

import flasgo
from flasgo.settings import Settings


def test_readme_mentions_new_runtime_features() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")

    assert "await request.form()" in readme
    assert "static_folder=" in readme
    assert "app.test_client()" in readme
    assert "MIGRATING_FROM_FLASK.md" in readme
    assert "flasgo run app.py --reload" in readme
    assert "reload=True" in readme
    assert "ALLOWED_HOSTS" in readme
    assert "SECRET_KEY" in readme
    assert "`Header`, `Cookie`" in readme
    assert "DOCS_AUTH_BACKEND" in readme
    assert 'app.register_auth_backend("docs"' in readme
    assert "OpenAPI 3.2" in readme
    assert "openapi_scheme" in readme
    assert "additionalOperations" in readme
    assert "MAX_VALIDATION_WORK" in readme
    assert "bearer-safe ASCII" in readme
    assert "64 KiB chunks" in readme
    assert "unique-local IPv6" in readme
    assert "CORSConfig" in readme
    assert "CORS controls whether browser JavaScript may read a response" in readme
    assert "uv audit --frozen" in readme
    assert "git diff --check" in readme


def test_readme_lists_every_public_export() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")

    missing = [name for name in flasgo.__all__ if f"`{name}`" not in readme]
    assert missing == []


def test_migration_guide_covers_canonical_flask_examples() -> None:
    guide = Path("MIGRATING_FROM_FLASK.md").read_text(encoding="utf-8")

    assert "# Flask to Flasgo migration guide" in guide
    assert "## HTML template route" in guide
    assert "## JSON API route" in guide
    assert "## redirect" in guide
    assert "## form POST handling" in guide
    assert "## static files" in guide
    assert "## testing" in guide
    assert "## ASGI deployment" in guide
    assert "flasgo run app.py --reload" in guide
    assert "ALLOWED_HOSTS" in guide
    assert "SECRET_KEY" in guide
    assert 'Header(alias="x-version")' in guide
    assert "repeated wire headers" in guide


def test_security_and_release_guides_cover_current_hardening() -> None:
    security = Path("SECURITY.md").read_text(encoding="utf-8")
    release = Path("release.md").read_text(encoding="utf-8")

    assert "DOCS_AUTH_BACKEND" in security
    assert "query, header, cookie, and form validation" in security
    assert "MAX_REQUEST_HEAD_BYTES" in security
    assert "never permits loopback or link-local" in security
    assert "uv audit" in release
    assert "API_VERSION" in release
    assert "git diff --check" in release


def test_changelog_tracks_unreleased_and_tagged_releases() -> None:
    changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")

    assert "## [0.3.0] - 2026-02-28" in changelog
    assert "## [0.2.0] - 2026-02-28" in changelog
    assert "## [0.1.0] - 2026-02-22" in changelog
    assert "secure Jinja templating support" in changelog
    assert "Project renamed from `fango` to `flasgo`" in changelog


def test_release_version_is_consistent_across_framework_and_docs() -> None:
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    version = project["project"]["version"]

    assert version == "0.7.0"
    assert Settings.API_VERSION == version
    assert f"current framework release is `{version}`" in Path("README.md").read_text(encoding="utf-8")
    assert f"## [{version}] - 2026-08-08" in Path("CHANGELOG.md").read_text(encoding="utf-8")
    assert "Latest `0.7.x` release" in Path("SECURITY.md").read_text(encoding="utf-8")
