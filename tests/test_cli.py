from __future__ import annotations

import json
import sys
from pathlib import Path
from types import ModuleType

import pytest
from flasgo import Flasgo
from flasgo import cli as cli_module
from openapi_spec_validator import OpenAPIV32SpecValidator, validate


def test_load_app_from_python_file(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text("TITLE = 'sibling import'\n", encoding="utf-8")
    app_file = tmp_path / "app.py"
    app_file.write_text(
        "from helpers import TITLE\n"
        "from flasgo import Flasgo\n"
        "app = Flasgo(settings={'API_TITLE': TITLE, 'CSRF_ENABLED': False})\n",
        encoding="utf-8",
    )

    app = cli_module.load_app(str(app_file))

    assert isinstance(app, Flasgo)
    assert app.settings.API_TITLE == "sibling import"


def test_load_app_from_package_file_with_absolute_and_relative_imports(tmp_path: Path) -> None:
    package = tmp_path / "src" / "cli_package_imports"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "models.py").write_text("TITLE = 'package imports'\n", encoding="utf-8")
    app_file = package / "app.py"
    app_file.write_text(
        "from cli_package_imports.models import TITLE as ABSOLUTE_TITLE\n"
        "from .models import TITLE as RELATIVE_TITLE\n"
        "from flasgo import Flasgo\n"
        "app = Flasgo(settings={'API_TITLE': ABSOLUTE_TITLE + ' / ' + RELATIVE_TITLE, 'CSRF_ENABLED': False})\n",
        encoding="utf-8",
    )

    app = cli_module.load_app(str(app_file))

    assert app.settings.API_TITLE == "package imports / package imports"
    assert sys.path[0] == str((tmp_path / "src").resolve())


def test_load_app_from_import_string() -> None:
    app = cli_module.load_app("flasgo_test_module:custom_app")
    assert isinstance(app, Flasgo)


def test_load_app_from_dotted_import_inserts_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    package = tmp_path / "cli_dotted_import"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "app.py").write_text(
        "from flasgo import Flasgo\napp = Flasgo(settings={'CSRF_ENABLED': False})\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "path", [entry for entry in sys.path if entry != str(tmp_path)])

    app = cli_module.load_app("cli_dotted_import.app:app")

    assert isinstance(app, Flasgo)
    assert sys.path[0] == str(tmp_path.resolve())


def test_load_app_accepts_file_attribute_and_extensionless_target(tmp_path: Path) -> None:
    app_file = tmp_path / "target_forms.py"
    app_file.write_text(
        "from flasgo import Flasgo\napp = Flasgo(settings={'CSRF_ENABLED': False})\n",
        encoding="utf-8",
    )

    assert isinstance(cli_module.load_app(f"{app_file}:app"), Flasgo)
    assert isinstance(cli_module.load_app(f"{app_file}:app", app_name="wrong_name"), Flasgo)
    assert isinstance(cli_module.load_app(str(app_file.with_suffix(""))), Flasgo)


def test_load_app_accepts_whitespace_and_nested_attributes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = tmp_path / "cli_nested_target.py"
    module.write_text(
        "from types import SimpleNamespace\n"
        "from flasgo import Flasgo\n"
        "namespace = SimpleNamespace(app=Flasgo(settings={'CSRF_ENABLED': False}))\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    app = cli_module.load_app(" cli_nested_target : namespace.app ")

    assert isinstance(app, Flasgo)


def test_load_app_falls_back_to_application_only_for_default_name(tmp_path: Path) -> None:
    app_file = tmp_path / "application_fallback.py"
    app_file.write_text(
        "from flasgo import Flasgo\napp = object()\napplication = Flasgo(settings={'CSRF_ENABLED': False})\n",
        encoding="utf-8",
    )

    assert isinstance(cli_module.load_app(str(app_file)), Flasgo)
    with pytest.raises(SystemExit, match="Checked 'custom'"):
        cli_module.load_app(str(app_file), app_name="custom")


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


def test_run_command_appends_reload_dirs_to_script_parent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app_file = tmp_path / "reload_app.py"
    app_file.write_text(
        "from flasgo import Flasgo\napp = Flasgo(settings={'CSRF_ENABLED': False})\n",
        encoding="utf-8",
    )
    extra = tmp_path / "generated"
    extra.mkdir()
    seen: dict[str, object] = {}

    def fake_run(self: Flasgo, **kwargs: object) -> None:
        seen.update(kwargs)

    monkeypatch.setattr(Flasgo, "run", fake_run)

    result = cli_module.main(["run", str(app_file), "--reload-dir", str(extra)])

    assert result == 0
    assert seen["reload_dirs"] == [str(tmp_path.resolve()), str(extra)]


def test_run_command_supports_import_strings_without_default_reload_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_run(self: Flasgo, **kwargs: object) -> None:
        seen.update(kwargs)

    monkeypatch.setattr(Flasgo, "run", fake_run)

    result = cli_module.main(["run", "flasgo_test_module:custom_app", "--no-reload"])

    assert result == 0
    assert seen["reload"] is False
    assert seen["reload_dirs"] is None


def test_run_command_adds_cwd_before_import_string_reload_dirs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}
    extra = tmp_path / "extra"
    extra.mkdir()
    monkeypatch.chdir(tmp_path)

    def fake_run(self: Flasgo, **kwargs: object) -> None:
        seen.update(kwargs)

    monkeypatch.setattr(Flasgo, "run", fake_run)

    result = cli_module.main(["run", "flasgo_test_module:custom_app", "--no-reload", "--reload-dir", str(extra)])

    assert result == 0
    assert seen["reload_dirs"] == [str(tmp_path.resolve()), str(extra)]


def test_run_command_watches_package_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    package = tmp_path / "cli_reload_package"
    package.mkdir()
    (package / "__init__.py").write_text(
        "from flasgo import Flasgo\napp = Flasgo(settings={'CSRF_ENABLED': False})\n",
        encoding="utf-8",
    )
    seen: dict[str, object] = {}

    def fake_run(self: Flasgo, **kwargs: object) -> None:
        seen.update(kwargs)

    monkeypatch.setattr(Flasgo, "run", fake_run)

    assert cli_module.main(["run", str(package), "--reload"]) == 0
    assert seen["reload_dirs"] == [str(package.resolve())]


def test_load_app_exits_for_missing_attr(tmp_path: Path) -> None:
    app_file = tmp_path / "app.py"
    app_file.write_text("value = 1\n", encoding="utf-8")

    with pytest.raises(SystemExit, match="pass `--app` with the correct variable name"):
        cli_module.load_app(str(app_file))


def test_load_app_exits_with_helpful_import_error() -> None:
    with pytest.raises(SystemExit, match="Check the target name and path") as exc_info:
        cli_module.load_app("does_not_exist.module:app")
    assert "Traceback" not in str(exc_info.value)


def test_load_app_reports_missing_and_non_python_paths(tmp_path: Path) -> None:
    missing = tmp_path / "missing.py"
    with pytest.raises(SystemExit, match="Python target not found"):
        cli_module.load_app(str(missing))

    non_python = tmp_path / "app.txt"
    non_python.write_text("not python\n", encoding="utf-8")
    with pytest.raises(SystemExit, match=r"Expected a \.py file path"):
        cli_module.load_app(str(non_python))


def test_load_app_import_failure_includes_app_traceback(tmp_path: Path) -> None:
    app_file = tmp_path / "traceback_app.py"
    app_file.write_text("from missing_cli_dependency import value\n", encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        cli_module.load_app(str(app_file))

    message = str(exc_info.value)
    assert "Traceback (most recent call last)" in message
    assert str(app_file) in message
    assert "missing_cli_dependency" in message


def test_load_app_syntax_error_includes_app_traceback(tmp_path: Path) -> None:
    app_file = tmp_path / "syntax_error_app.py"
    app_file.write_text("def broken(:\n", encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        cli_module.load_app(str(app_file))

    message = str(exc_info.value)
    assert "Traceback (most recent call last)" in message
    assert str(app_file) in message
    assert "SyntaxError" in message


def test_load_app_replaces_only_cli_owned_cached_modules(tmp_path: Path) -> None:
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    first_dir.mkdir()
    second_dir.mkdir()
    for directory, title in ((first_dir, "first"), (second_dir, "second")):
        (directory / "cache_app.py").write_text(
            f"from flasgo import Flasgo\napp = Flasgo(settings={{'API_TITLE': '{title}', 'CSRF_ENABLED': False}})\n",
            encoding="utf-8",
        )

    first = cli_module.load_app(str(first_dir / "cache_app.py"))
    second = cli_module.load_app(str(second_dir / "cache_app.py"))

    assert first.settings.API_TITLE == "first"
    assert second.settings.API_TITLE == "second"
    cache_module_file = sys.modules["cache_app"].__file__
    assert cache_module_file is not None
    assert Path(cache_module_file).resolve() == second_dir / "cache_app.py"


def test_load_app_replaces_cli_owned_sibling_modules(tmp_path: Path) -> None:
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    first_dir.mkdir()
    second_dir.mkdir()
    for directory, title in ((first_dir, "first"), (second_dir, "second")):
        (directory / "cli_switch_helper.py").write_text(f"TITLE = {title!r}\n", encoding="utf-8")
        (directory / "sibling_app.py").write_text(
            "from cli_switch_helper import TITLE\n"
            "from flasgo import Flasgo\n"
            "app = Flasgo(settings={'API_TITLE': TITLE, 'CSRF_ENABLED': False})\n",
            encoding="utf-8",
        )
    (first_dir / "other_app.py").write_text(
        "from flasgo import Flasgo\napp = Flasgo(settings={'CSRF_ENABLED': False})\n",
        encoding="utf-8",
    )

    first = cli_module.load_app(str(first_dir / "sibling_app.py"))
    cli_module.load_app(str(first_dir / "other_app.py"))
    second = cli_module.load_app(str(second_dir / "sibling_app.py"))

    assert first.settings.API_TITLE == "first"
    assert second.settings.API_TITLE == "second"
    helper_file = sys.modules["cli_switch_helper"].__file__
    assert helper_file is not None
    assert Path(helper_file).resolve() == second_dir / "cli_switch_helper.py"


def test_load_app_does_not_evict_unrelated_cached_namespace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app_file = tmp_path / "occupied_name.py"
    app_file.write_text(
        "from flasgo import Flasgo\napp = Flasgo(settings={'CSRF_ENABLED': False})\n",
        encoding="utf-8",
    )
    existing = ModuleType("occupied_name")
    existing.__file__ = str(tmp_path / "elsewhere" / "occupied_name.py")
    monkeypatch.setitem(sys.modules, "occupied_name", existing)
    cli_module._CLI_NAMESPACE_ROOTS.pop("occupied_name", None)

    with pytest.raises(SystemExit, match="namespace 'occupied_name' is already imported"):
        cli_module.load_app(str(app_file))

    assert sys.modules["occupied_name"] is existing


def test_load_app_restores_previous_namespace_when_replacement_fails(tmp_path: Path) -> None:
    first_dir = tmp_path / "valid"
    second_dir = tmp_path / "invalid"
    first_dir.mkdir()
    second_dir.mkdir()
    first_file = first_dir / "restore_app.py"
    first_file.write_text(
        "from flasgo import Flasgo\napp = Flasgo(settings={'CSRF_ENABLED': False})\n",
        encoding="utf-8",
    )
    (second_dir / "restore_app.py").write_text("raise RuntimeError('replacement failed')\n", encoding="utf-8")

    cli_module.load_app(str(first_file))
    original_module = sys.modules["restore_app"]

    with pytest.raises(SystemExit, match="replacement failed"):
        cli_module.load_app(str(second_dir / "restore_app.py"))

    assert sys.modules["restore_app"] is original_module


def test_load_app_replaces_cached_package_parent(tmp_path: Path) -> None:
    roots = [tmp_path / "one", tmp_path / "two"]
    for root, title in zip(roots, ("one", "two"), strict=True):
        package = root / "cli_swap_package"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("", encoding="utf-8")
        (package / "app.py").write_text(
            f"from flasgo import Flasgo\napp = Flasgo(settings={{'API_TITLE': '{title}', 'CSRF_ENABLED': False}})\n",
            encoding="utf-8",
        )

    first = cli_module.load_app(str(roots[0] / "cli_swap_package" / "app.py"))
    second = cli_module.load_app(str(roots[1] / "cli_swap_package" / "app.py"))

    assert first.settings.API_TITLE == "one"
    assert second.settings.API_TITLE == "two"
    package_file = sys.modules["cli_swap_package"].__file__
    assert package_file is not None
    assert Path(package_file).resolve() == (roots[1] / "cli_swap_package" / "__init__.py")


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
