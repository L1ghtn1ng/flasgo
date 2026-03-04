from __future__ import annotations

from pathlib import Path

import pytest
from flasgo import Flasgo
from flasgo import cli as cli_module


def test_load_app_from_python_file(tmp_path: Path) -> None:
    app_file = tmp_path / "app.py"
    app_file.write_text(
        "from flasgo import Flasgo\napp = Flasgo(settings={'CSRF_ENABLED': False})\n",
        encoding="utf-8",
    )

    app = cli_module.load_app(str(app_file))

    assert isinstance(app, Flasgo)


def test_load_app_from_import_string() -> None:
    app = cli_module.load_app("flasgo_test_module:custom_app")
    assert isinstance(app, Flasgo)


def test_run_command_defaults_reload_dir_to_script_parent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app_file = tmp_path / "app.py"
    app_file.write_text(
        "from flasgo import Flasgo\napp = Flasgo(settings={'CSRF_ENABLED': False})\n",
        encoding="utf-8",
    )

    seen: dict[str, object] = {}

    def fake_run(self: Flasgo, **kwargs: object) -> None:
        seen.update(kwargs)

    monkeypatch.setattr(Flasgo, "run", fake_run)

    result = cli_module.main(["run", str(app_file), "--host", "0.0.0.0", "--port", "9000", "--reload"])

    assert result == 0
    assert seen["host"] == "0.0.0.0"
    assert seen["port"] == 9000
    assert seen["reload"] is True
    assert seen["reload_dirs"] == [str(tmp_path.resolve())]


def test_run_command_supports_import_strings_without_default_reload_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_run(self: Flasgo, **kwargs: object) -> None:
        seen.update(kwargs)

    monkeypatch.setattr(Flasgo, "run", fake_run)

    result = cli_module.main(["run", "flasgo_test_module:custom_app", "--no-reload"])

    assert result == 0
    assert seen["reload"] is False
    assert seen["reload_dirs"] is None


def test_load_app_exits_for_missing_attr(tmp_path: Path) -> None:
    app_file = tmp_path / "app.py"
    app_file.write_text("value = 1\n", encoding="utf-8")

    with pytest.raises(SystemExit, match="pass `--app` with the correct variable name"):
        cli_module.load_app(str(app_file))


def test_load_app_exits_with_helpful_import_error() -> None:
    with pytest.raises(SystemExit, match="Check that it is on PYTHONPATH and imports cleanly"):
        cli_module.load_app("does_not_exist.module:app")
