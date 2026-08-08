from __future__ import annotations

import json
from pathlib import Path

import pytest
from flasgo import Flasgo
from flasgo import cli as cli_module
from openapi_spec_validator import OpenAPIV32SpecValidator, validate


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


def test_routes_openapi_and_check_commands(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    app_file = tmp_path / "app.py"
    app_file.write_text(
        "\n".join(
            (
                "from flasgo import Flasgo",
                "app = Flasgo(settings={'CSRF_ENABLED': False})",
                "@app.get('/users/<int:user_id>', name='user')",
                "async def user(user_id: int): return {'id': user_id}",
                "@app.websocket('/events', name='events')",
                "async def events(websocket): pass",
            )
        ),
        encoding="utf-8",
    )

    assert cli_module.main(["routes", str(app_file)]) == 0
    routes_output = capsys.readouterr().out
    assert "GET,HEAD" in routes_output
    assert "/users/<int:user_id>" in routes_output
    assert "websocket" in routes_output

    output = tmp_path / "api.json"
    assert cli_module.main(["openapi", str(app_file), "--output", str(output)]) == 0
    document = json.loads(output.read_text(encoding="utf-8"))
    assert "/users/{user_id}" in document["paths"]
    assert document == cli_module.load_app(str(app_file)).openapi_spec()
    validate(document, cls=OpenAPIV32SpecValidator)

    assert cli_module.main(["check", str(app_file)]) == 0
    assert "Flasgo check passed." in capsys.readouterr().out


def test_atomic_write_replaces_symlink_entry_without_following_target(tmp_path: Path) -> None:
    target = tmp_path / "victim.txt"
    target.write_text("keep", encoding="utf-8")
    output = tmp_path / "openapi.json"
    output.symlink_to(target)

    cli_module._atomic_write(output, "generated")

    assert target.read_text(encoding="utf-8") == "keep"
    assert not output.is_symlink()
    assert output.read_text(encoding="utf-8") == "generated"


def test_check_reports_duplicate_routes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    app_file = tmp_path / "bad_app.py"
    app_file.write_text(
        "\n".join(
            (
                "from flasgo import Flasgo",
                "app = Flasgo(settings={'CSRF_ENABLED': False})",
                "@app.get('/duplicate')",
                "async def first(): return 'one'",
                "@app.get('/duplicate')",
                "async def second(): return 'two'",
            )
        ),
        encoding="utf-8",
    )

    assert cli_module.main(["check", str(app_file)]) == 1
    assert "duplicate HTTP route" in capsys.readouterr().err


def test_db_commands_delegate_to_alembic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[object, ...]] = []
    config_path = tmp_path / "alembic.ini"
    config_path.write_text("[alembic]\nscript_location = migrations\n", encoding="utf-8")

    class FakeConfig:
        def __init__(self, filename: str) -> None:
            self.filename = filename

    class FakeCommand:
        def revision(self, config: FakeConfig, *, message: str, autogenerate: bool) -> None:
            calls.append(("revision", config.filename, message, autogenerate))

        def upgrade(self, config: FakeConfig, revision: str, *, sql: bool) -> None:
            calls.append(("upgrade", config.filename, revision, sql))

        def downgrade(self, config: FakeConfig, revision: str, *, sql: bool) -> None:
            calls.append(("downgrade", config.filename, revision, sql))

    monkeypatch.setattr(cli_module, "_load_alembic", lambda: (FakeCommand(), FakeConfig))

    prefix = ["db", "--config", str(config_path)]
    assert cli_module.main([*prefix, "migrate", "-m", "create users"]) == 0
    assert cli_module.main([*prefix, "upgrade"]) == 0
    assert cli_module.main([*prefix, "downgrade", "base", "--sql"]) == 0

    assert calls == [
        ("revision", str(config_path), "create users", True),
        ("upgrade", str(config_path), "head", False),
        ("downgrade", str(config_path), "base", True),
    ]
