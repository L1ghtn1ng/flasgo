# Flasgo release process

This file documents how releases are cut and published for `flasgo`.

## Workflow summary

- CI workflow: `.github/workflows/ci.yml`
  - Runs on pushes to `main` and pull requests.
  - Verifies the lockfile, installs the development environment with `--frozen`, and checks dependency consistency.
  - Executes `ruff`, `ty`, the full `pytest` suite, and an OSV dependency audit.
  - Builds both distribution formats and rejects whitespace errors with `git diff --check`.
- Publish workflow: `.github/workflows/release-pypi.yml`
  - Runs on git tags matching `v*`.
  - Verifies tag version equals `pyproject.toml` `project.version`.
  - Builds with `uv build`.
  - Publishes with PyPI Trusted Publishing using `pypa/gh-action-pypi-publish`.

## Required PyPI configuration

- Configure a Trusted Publisher for the `flasgo` PyPI project:
  - Repository: `L1ghtn1ng/flasgo`
  - Workflow: `release-pypi.yml`
  - Environment: `pypi`
- No PyPI API token or GitHub secret is required for publishing.

## Release checklist

1. Move the relevant `CHANGELOG.md` entries from `Unreleased` into a dated `X.Y.Z` section and update any
   version-specific documentation.
2. Update `project.version` in `pyproject.toml` and `API_VERSION` in `flasgo/settings.py` to the same `X.Y.Z` value.
3. Refresh `uv.lock` if project metadata or dependencies changed.
4. Run the same locked verification bundle documented in `README.md`, including the dependency audit and package
   build.
5. Inspect the generated wheel and source distribution to confirm only intended release files are present.
6. Commit and push the focused release changes, then ensure CI is green on `main`.
7. Create and push a tag in `vX.Y.Z` format. The publish workflow rejects a tag that differs from
   `pyproject.toml`.

## Pre-release verification

Run the CI-equivalent checks from a clean checkout before tagging:

```bash
uv lock --check
uv sync --frozen --group dev
uv pip check
uv run --frozen ruff check .
uv run --frozen ty check
uv run --frozen pytest
uv audit --frozen
uv build
git diff --check
```

## Release commands

```bash
# Replace X.Y.Z with the exact version in pyproject.toml.
git tag vX.Y.Z
git push origin vX.Y.Z
```

## Notes

- If tag version and `pyproject.toml` version do not match, publish fails by design.
- Do not use `app.run(...)` for production runtime; release artifacts are for ASGI deployment.
