# Fango Release Notes

This file documents how releases are cut and published for `fango`.

## Workflow summary

- CI workflow: `.github/workflows/ci.yml`
  - Runs on pushes to `main` and pull requests.
  - Executes `ruff`, `ty`, and `pytest`.
- Publish workflow: `.github/workflows/release-pypi.yml`
  - Runs on git tags matching `v*`.
  - Verifies tag version equals `pyproject.toml` `project.version`.
  - Builds with `uv build`.
  - Publishes with `uv publish`.

## Required GitHub secret

- `PYPI_API_TOKEN`: PyPI API token used by `uv publish`.

## Release checklist

1. Update `version` in `pyproject.toml`.
2. Ensure CI is green on `main`.
3. Commit and push the version change.
4. Create and push a tag in `vX.Y.Z` format.

## Release commands

```bash
# example for version 0.1.0
git tag v0.1.0
git push origin v0.1.0
```

## Notes

- If tag version and `pyproject.toml` version do not match, publish fails by design.
- Do not use `app.run(...)` for production runtime; release artifacts are for ASGI deployment.
