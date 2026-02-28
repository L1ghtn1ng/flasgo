from __future__ import annotations

from pathlib import Path


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


def test_changelog_tracks_unreleased_and_tagged_releases() -> None:
    changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")

    assert "## [0.3.0] - 2026-02-28" in changelog
    assert "## [0.2.0] - 2026-02-28" in changelog
    assert "## [0.1.0] - 2026-02-22" in changelog
    assert "secure Jinja templating support" in changelog
    assert "Project renamed from `fango` to `flasgo`" in changelog
