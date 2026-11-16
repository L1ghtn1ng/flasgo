import importlib.metadata
import json
import logging
import os
import re
import stat
import sys
import textwrap
import tomllib
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest
from openapi_spec_validator import OpenAPIV32SpecValidator, validate

from flasgo import Flasgo
from flasgo import cli as cli_module


@pytest.fixture(autouse=True)
def _isolate_imports(restore_import_state: None) -> None:
    """Every CLI test imports throwaway modules such as ``app`` that must not leak into later tests."""


def test_load_app_from_python_file(tmp_path: Path) -> None:
    (tmp_path / "helpers.py").write_text("TITLE = 'sibling import'\n", encoding="utf-8")
    app_file = tmp_path / "app.py"
    app_file.write_text(
        "from helpers import TITLE\nfrom flasgo import Flasgo\napp = Flasgo(settings={'API_TITLE': TITLE, 'CSRF_ENABLED': False})\n",
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
        textwrap.dedent(
            """\
            from flasgo import Flasgo
            app = Flasgo(settings={'CSRF_ENABLED': False})
            @app.get('/users/<int:user_id>', name='user')
            async def user(user_id: int): return {'id': user_id}
            @app.websocket('/events', name='events')
            async def events(websocket): pass"""
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
    target.chmod(0o644)
    output = tmp_path / "openapi.json"
    output.symlink_to(target)

    previous = os.umask(0o077)
    try:
        cli_module._atomic_write(output, "generated")
    finally:
        os.umask(previous)

    assert target.read_text(encoding="utf-8") == "keep"
    assert not output.is_symlink()
    assert output.read_text(encoding="utf-8") == "generated"
    # The replacement is a new file under the caller's umask, not a copy of the symlink target's 0644 mode.
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_atomic_write_uses_umask_for_new_files_and_keeps_existing_modes(tmp_path: Path) -> None:
    previous = os.umask(0o022)
    try:
        created = tmp_path / "new.json"
        cli_module._atomic_write(created, "{}")
        assert stat.S_IMODE(created.stat().st_mode) == 0o644

        existing = tmp_path / "existing.json"
        existing.write_text("old", encoding="utf-8")
        existing.chmod(0o640)
        cli_module._atomic_write(existing, "new")
        assert stat.S_IMODE(existing.stat().st_mode) == 0o640
    finally:
        os.umask(previous)


def test_atomic_write_never_exposes_a_private_files_new_contents(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Replacing a 0600 file must not create a group/world-readable temporary copy, even before the chmod."""
    private = tmp_path / "private.json"
    private.write_text("old", encoding="utf-8")
    private.chmod(0o600)
    modes_while_writing: list[int] = []
    real_fsync = cli_module.os.fsync

    def recording_fsync(descriptor: int) -> None:
        modes_while_writing.append(stat.S_IMODE(os.fstat(descriptor).st_mode))
        real_fsync(descriptor)

    monkeypatch.setattr(cli_module.os, "fsync", recording_fsync)
    previous = os.umask(0o022)
    try:
        cli_module._atomic_write(private, "secret")
    finally:
        os.umask(previous)

    assert modes_while_writing == [0o600]
    assert stat.S_IMODE(private.stat().st_mode) == 0o600
    assert private.read_text(encoding="utf-8") == "secret"


def test_atomic_write_removes_the_temporary_file_when_writing_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def failing_fsync(_fd: int) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(cli_module.os, "fsync", failing_fsync)
    with pytest.raises(OSError, match="disk full"):
        cli_module._atomic_write(tmp_path / "out.json", "{}")
    assert list(tmp_path.iterdir()) == []


def test_check_fails_when_app_registration_rejects_duplicate_routes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Report conflicting application routes as a failed check with a useful diagnostic."""
    app_file = tmp_path / "bad_app.py"
    app_file.write_text(
        textwrap.dedent(
            """\
            from flasgo import Flasgo
            app = Flasgo(settings={'CSRF_ENABLED': False})
            @app.get('/duplicate')
            async def first(): return 'one'
            @app.get('/duplicate')
            async def second(): return 'two'"""
        ),
        encoding="utf-8",
    )

    assert cli_module.main(["check", str(app_file)]) == 1
    assert "conflicts with an existing route pattern" in capsys.readouterr().err


@pytest.mark.parametrize("failure", [None, "import", "registration", "attribute"])
def test_check_json_remains_parseable_during_application_loading(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], failure: str | None
) -> None:
    """Keep noisy imports and load failures inside the documented CLI output contract."""
    source = "print('application diagnostic')\nfrom flasgo import Flasgo\napp = Flasgo()\n"
    if failure == "import":
        source += "raise RuntimeError('import failed')\n"
    elif failure == "registration":
        source += "app.get('/duplicate')(lambda: 'one')\napp.get('/duplicate')(lambda: 'two')\n"
    elif failure == "attribute":
        source += (
            "class Container:\n    @property\n    def app(self):\n        raise RuntimeError('attribute failed')\ncontainer = Container()\n"
        )
    target = tmp_path / "noisy_app.py"
    target.write_text(source)
    target_spec = f"{target}:container.app" if failure == "attribute" else str(target)
    assert cli_module.main(["check", target_spec, "--json"]) == int(failure is not None)
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert set(result) == {"passed", "issues", "changes"}
    assert result["passed"] is (failure is None)
    assert result["changes"] == []
    assert "application diagnostic" in captured.err
    if failure is not None:
        assert len(result["issues"]) == 1
        assert result["issues"][0]["code"] == "registration"
        assert result["issues"][0]["severity"] == "error"
        assert result["issues"][0]["message"]


class _FakeAlembicConfig:
    def __init__(self, file_: str | None = None, toml_file: str | None = None) -> None:
        self.file_ = file_
        self.toml_file = toml_file


def _fake_alembic(monkeypatch: pytest.MonkeyPatch) -> list[tuple[object, ...]]:
    calls: list[tuple[object, ...]] = []

    class FakeCommand:
        def init(self, config: _FakeAlembicConfig, directory: str, *, template: str, package: bool) -> None:
            calls.append(("init", config.file_, config.toml_file, directory, template, package))

        def revision(self, config: _FakeAlembicConfig, *, message: str, autogenerate: bool = False) -> None:
            calls.append(("revision", config.file_, config.toml_file, message, autogenerate))

        def upgrade(self, config: _FakeAlembicConfig, revision: str, *, sql: bool) -> None:
            calls.append(("upgrade", config.file_, config.toml_file, revision, sql))

        def downgrade(self, config: _FakeAlembicConfig, revision: str, *, sql: bool) -> None:
            calls.append(("downgrade", config.file_, config.toml_file, revision, sql))

        def current(self, config: _FakeAlembicConfig, *, check_heads: bool, verbose: bool) -> None:
            calls.append(("current", check_heads, verbose))

        def history(self, config: _FakeAlembicConfig, *, rev_range: str | None, verbose: bool, indicate_current: bool) -> None:
            calls.append(("history", rev_range, verbose, indicate_current))

        def stamp(self, config: _FakeAlembicConfig, revision: str, *, sql: bool, purge: bool) -> None:
            calls.append(("stamp", revision, sql, purge))

        def check(self, config: _FakeAlembicConfig) -> None:
            from alembic.util import CommandError

            raise CommandError("New upgrade operations detected: [('add_table', 'users')]")

    monkeypatch.setattr(cli_module, "_load_alembic", lambda: (FakeCommand(), _FakeAlembicConfig))
    return calls


def test_db_commands_delegate_to_alembic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _fake_alembic(monkeypatch)
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "alembic.ini"
    config_path.write_text("[alembic]\nscript_location = migrations\n", encoding="utf-8")

    prefix = ["db", "--config", str(config_path)]
    assert cli_module.main([*prefix, "migrate", "-m", "create users"]) == 0
    assert cli_module.main([*prefix, "upgrade"]) == 0
    assert cli_module.main([*prefix, "downgrade", "base", "--sql"]) == 0

    assert calls == [
        ("revision", str(config_path), None, "create users", True),
        ("upgrade", str(config_path), None, "head", False),
        ("downgrade", str(config_path), None, "base", True),
    ]


def test_db_commands_read_tool_alembic_from_pyproject(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _fake_alembic(monkeypatch)
    monkeypatch.chdir(tmp_path)
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nname = "demo"\n\n[tool.alembic]\nscript_location = "%(here)s/migrations"\n', encoding="utf-8")

    assert cli_module.main(["db", "upgrade"]) == 0
    (tmp_path / "alembic.ini").write_text("[alembic]\nsqlalchemy.url = sqlite://\n", encoding="utf-8")
    assert cli_module.main(["db", "upgrade"]) == 0

    assert calls == [
        ("upgrade", None, str(pyproject), "head", False),
        ("upgrade", str(tmp_path / "alembic.ini"), str(pyproject), "head", False),
    ]


def test_db_ignores_pyproject_without_tool_alembic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _fake_alembic(monkeypatch)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "demo"\n', encoding="utf-8")
    with pytest.raises(SystemExit, match=r"no .*alembic\.ini and no \[tool\.alembic\] table"):
        cli_module.main(["db", "upgrade"])

    (tmp_path / "alembic.ini").write_text("[alembic]\n", encoding="utf-8")
    assert cli_module.main(["db", "upgrade"]) == 0
    assert calls == [("upgrade", str(tmp_path / "alembic.ini"), None, "head", False)]


@pytest.mark.parametrize("flag", ["--config", "--pyproject"])
def test_db_accepts_explicit_pyproject_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flag: str) -> None:
    calls = _fake_alembic(monkeypatch)
    monkeypatch.chdir(tmp_path)
    project = tmp_path / "service"
    project.mkdir()
    pyproject = project / "pyproject.toml"
    pyproject.write_text('[tool.alembic]\nscript_location = "migrations"\n', encoding="utf-8")

    assert cli_module.main(["db", flag, str(pyproject), "migrate", "-m", "init"]) == 0
    assert calls == [("revision", None, str(pyproject), "init", True)]


@pytest.mark.parametrize(
    ("argv", "contents", "message"),
    [
        (["--pyproject", "missing.toml"], None, "pyproject.toml not found"),
        (["--pyproject", "pyproject.toml"], '[project]\nname = "demo"\n', r"No \[tool\.alembic\] table"),
        (["--pyproject", "pyproject.toml"], 'tool = { alembic = "nope" }\n', r"\[tool\.alembic\] .* must be a table"),
        ([], "[tool.alembic\n", "Could not read"),
        (["--config", "missing.ini"], '[tool.alembic]\nscript_location = "m"\n', "Alembic configuration not found"),
        (["--config", "pyproject.toml", "--pyproject", "pyproject.toml"], None, "either --config or --pyproject"),
    ],
)
def test_db_reports_unusable_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, argv: list[str], contents: str | None, message: str
) -> None:
    calls = _fake_alembic(monkeypatch)
    monkeypatch.chdir(tmp_path)
    if contents is not None:
        (tmp_path / "pyproject.toml").write_text(contents, encoding="utf-8")
    with pytest.raises(SystemExit, match=message):
        cli_module.main(["db", *argv, "upgrade"])
    assert calls == []


@pytest.mark.parametrize("template", ["generic", "pyproject", "multidb"])
def test_db_init_passes_template_and_both_config_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], template: str
) -> None:
    calls = _fake_alembic(monkeypatch)
    monkeypatch.chdir(tmp_path)
    argv = ["db", "init"] if template == "generic" else ["db", "init", "--template", template]
    assert cli_module.main(argv) == 0
    assert calls == [("init", str(tmp_path / "alembic.ini"), str(tmp_path / "pyproject.toml"), "migrations", template, True)]
    out = capsys.readouterr().out
    env = Path("migrations", "env.py")
    if template == "multidb":
        assert "Set the URL of each database listed in alembic.ini." in out
        assert f"Map each engine name in target_metadata in {env}" in out
    else:
        assert "Set sqlalchemy.url in alembic.ini" in out
        assert f"Point target_metadata in {env}" in out
    assert '`flasgo db migrate -m "create tables"`, then `flasgo db upgrade`' in out


@pytest.fixture
def restore_logging_config() -> Iterator[None]:
    """Alembic's stock env.py runs logging.config.fileConfig on alembic.ini, which replaces root handlers and disables loggers."""
    root = logging.getLogger()
    root_state = (list(root.handlers), root.level)
    loggers = {
        name: (logger.disabled, list(logger.handlers), logger.level, logger.propagate)
        for name, logger in logging.Logger.manager.loggerDict.items()
        if isinstance(logger, logging.Logger)
    }
    yield
    root.handlers[:], level = root_state
    root.setLevel(level)
    for name, logger in list(logging.Logger.manager.loggerDict.items()):
        if isinstance(logger, logging.Logger) and name in loggers:
            logger.disabled, handlers, logger.level, logger.propagate = loggers[name]
            logger.handlers[:] = handlers


@pytest.mark.usefixtures("restore_logging_config")
def test_db_reports_database_url_problems_in_one_line(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("alembic")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "demo"\n', encoding="utf-8")
    assert cli_module.main(["db", "init", "--template", "pyproject"]) == 0
    ini = tmp_path / "alembic.ini"
    template_ini = ini.read_text(encoding="utf-8")

    def set_url(url: str) -> None:
        ini.write_text(re.sub(r"(?m)^sqlalchemy\.url = .*$", f"sqlalchemy.url = {url}", template_ini), encoding="utf-8")

    # A fresh `db init` leaves Alembic's placeholder URL; online and offline (--sql) runs both name it.
    for argv in (["db", "current"], ["db", "upgrade", "head", "--sql"]):
        with pytest.raises(SystemExit, match=r"^Alembic: sqlalchemy\.url in alembic\.ini is still Alembic's placeholder, driver://"):
            cli_module.main(argv)
    set_url("nosuch://localhost/app")
    with pytest.raises(SystemExit, match=r"^Alembic: sqlalchemy\.url in alembic\.ini names an unknown database dialect: .*nosuch$"):
        cli_module.main(["db", "current"])
    for url in ("://not a url", "postgresql://user:pass@localhost:abc/app"):
        set_url(url)
        for argv in (["db", "current"], ["db", "upgrade", "head", "--sql"]):
            with pytest.raises(SystemExit, match=r"^Alembic: sqlalchemy\.url in alembic\.ini is not a valid database URL: "):
                cli_module.main(argv)
    # With only [tool.alembic], env.py finds no URL at all.
    ini.unlink()
    for argv in (["db", "current"], ["db", "upgrade", "head", "--sql"]):
        with pytest.raises(SystemExit, match=r"^Alembic: no database URL is configured\. Set sqlalchemy\.url in alembic\.ini"):
            cli_module.main(argv)
    # An ini without an [alembic] section is the same as no URL, not a new error from the handler.
    ini.write_text(re.sub(r"(?ms)^\[alembic\]$.*?(?=^\[)", "", template_ini), encoding="utf-8")
    with pytest.raises(SystemExit, match=r"^Alembic: no database URL is configured\."):
        cli_module.main(["db", "current"])


@pytest.mark.parametrize(
    ("env_source", "error"),
    [
        # env.py builds its own engine; the placeholder left in alembic.ini is not the URL that failed.
        ('from sqlalchemy import create_engine\ncreate_engine("postgres://u:p@h/db")\n', "sqlalchemy.dialects:postgres"),
        ('from sqlalchemy import create_engine\ncreate_engine("not a url")\n', "Could not parse SQLAlchemy URL"),
        ('settings = {}\nsettings["url"]\n', "'url'"),
        ('raise RuntimeError("models import failed")\n', "models import failed"),
    ],
)
@pytest.mark.usefixtures("restore_logging_config")
def test_db_keeps_traceback_for_errors_not_caused_by_configured_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, env_source: str, error: str
) -> None:
    pytest.importorskip("alembic")
    monkeypatch.chdir(tmp_path)
    assert cli_module.main(["db", "init"]) == 0
    (tmp_path / "migrations" / "env.py").write_text(env_source, encoding="utf-8")
    with pytest.raises(Exception, match=re.escape(error)) as exc_info:
        cli_module.main(["db", "current"])
    assert not isinstance(exc_info.value, SystemExit)


@pytest.mark.parametrize("unused_section", [False, True])
@pytest.mark.usefixtures("restore_logging_config")
def test_db_placeholder_message_requires_the_placeholder_in_the_ini(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unused_section: bool
) -> None:
    pytest.importorskip("alembic")
    monkeypatch.chdir(tmp_path)
    assert cli_module.main(["db", "init"]) == 0
    ini = tmp_path / "alembic.ini"
    source = re.sub(r"(?m)^sqlalchemy\.url = .*$", "sqlalchemy.url = sqlite://", ini.read_text(encoding="utf-8"))
    if unused_section:
        # A section that is neither [alembic] nor listed in its databases option is never read by env.py.
        source += f"\n[unused]\nsqlalchemy.url = {cli_module._ALEMBIC_PLACEHOLDER_URL}\n"
    ini.write_text(source, encoding="utf-8")
    # env.py reads Alembic's placeholder from somewhere else, such as an unset-up DATABASE_URL; the ini is fine.
    env = tmp_path / "migrations" / "env.py"
    env.write_text(f'from sqlalchemy import create_engine\ncreate_engine("{cli_module._ALEMBIC_PLACEHOLDER_URL}")\n', encoding="utf-8")
    with pytest.raises(Exception, match=r"sqlalchemy\.dialects:driver$") as exc_info:
        cli_module.main(["db", "current"])
    assert not isinstance(exc_info.value, SystemExit)


@pytest.mark.usefixtures("restore_logging_config")
def test_db_reports_multidb_placeholder_in_listed_engine_section(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("alembic")
    monkeypatch.chdir(tmp_path)
    assert cli_module.main(["db", "init", "--template", "multidb"]) == 0
    with pytest.raises(SystemExit, match=r"^Alembic: sqlalchemy\.url in alembic\.ini is still Alembic's placeholder, driver://"):
        cli_module.main(["db", "current"])


def test_db_url_errors_name_the_configured_ini(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("alembic")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "demo"\n', encoding="utf-8")
    assert cli_module.main(["db", "init", "--template", "pyproject"]) == 0
    (tmp_path / "alembic.ini").unlink()
    with (tmp_path / "pyproject.toml").open("a", encoding="utf-8") as project:
        project.write('\n[tool.flasgo.db]\nconfig = "conf/db.ini"\n')
    with pytest.raises(SystemExit, match=rf"Set sqlalchemy\.url in {re.escape(str(Path('conf', 'db.ini')))}, or"):
        cli_module.main(["db", "current"])


def test_db_init_next_steps_repeat_command_line_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _fake_alembic(monkeypatch)
    monkeypatch.chdir(tmp_path)
    assert cli_module.main(["db", "--config", "my conf.ini", "init"]) == 0
    out = capsys.readouterr().out
    assert "Set sqlalchemy.url in my conf.ini" in out
    db = cli_module._shell_join(["flasgo", "db", "--config", "my conf.ini"])
    assert f'`{db} migrate -m "create tables"`, then `{db} upgrade`' in out


@pytest.mark.parametrize(
    ("windows", "expected"),
    [(False, "flasgo db --config 'my conf.ini'"), (True, 'flasgo db --config "my conf.ini"')],
)
def test_next_step_commands_use_the_platform_quoting(windows: bool, expected: str) -> None:
    assert cli_module._shell_join(["flasgo", "db", "--config", "my conf.ini"], windows=windows) == expected


def test_db_runs_real_alembic_with_only_pyproject_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    pytest.importorskip("alembic")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "demo"\n', encoding="utf-8")

    assert cli_module.main(["db", "init", "--template", "pyproject"]) == 0
    # A relative --directory must be recorded relative to pyproject.toml, never as this machine's absolute path.
    assert 'script_location = "%(here)s/migrations"' in (tmp_path / "pyproject.toml").read_text(encoding="utf-8")
    # Mirror a project that moved every Alembic setting into pyproject.toml and deleted alembic.ini.
    (tmp_path / "alembic.ini").unlink()
    env = tmp_path / "migrations" / "env.py"
    source = env.read_text(encoding="utf-8")
    source = source.replace('config.get_main_option("sqlalchemy.url")', '"sqlite://"')
    source = source.replace("config.get_section(config.config_ini_section, {})", '{"sqlalchemy.url": "sqlite://"}')
    source = source.replace("target_metadata = None", "from sqlalchemy import MetaData\ntarget_metadata = MetaData()")
    env.write_text(source, encoding="utf-8")
    capsys.readouterr()

    assert cli_module.main(["db", "migrate", "-m", "create users"]) == 0
    assert len(list((tmp_path / "migrations" / "versions").glob("*_create_users.py"))) == 1
    assert cli_module.main(["db", "upgrade", "--sql"]) == 0
    assert "CREATE TABLE alembic_version" in capsys.readouterr().out
    assert cli_module.main(["db", "history"]) == 0
    assert "create users" in capsys.readouterr().out
    assert cli_module.main(["db", "stamp", "head", "--sql"]) == 0
    assert "INSERT INTO alembic_version" in capsys.readouterr().out
    # The in-memory database is never upgraded, so Alembic refuses; the failure is one line, not a traceback.
    with pytest.raises(SystemExit, match=r"^Alembic: Target database is not up to date\.$"):
        cli_module.main(["db", "check"])
    with pytest.raises(SystemExit, match=r"^Alembic: Directory .*migrations already exists and is not empty$"):
        cli_module.main(["db", "init", "--template", "pyproject"])


@pytest.mark.parametrize("configured", [False, True])
@pytest.mark.usefixtures("restore_logging_config")
def test_db_shows_alembic_messages_without_alembic_ini(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], configured: bool
) -> None:
    pytest.importorskip("alembic")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "demo"\n', encoding="utf-8")
    assert cli_module.main(["db", "init", "--template", "pyproject"]) == 0
    # Without alembic.ini, env.py never calls fileConfig, so nothing would configure Alembic's logger.
    (tmp_path / "alembic.ini").unlink()
    env = tmp_path / "migrations" / "env.py"
    env.write_text(env.read_text(encoding="utf-8").replace('config.get_main_option("sqlalchemy.url")', '"sqlite://"'), encoding="utf-8")
    assert cli_module.main(["db", "revision", "-m", "first"]) == 0
    root = logging.getLogger()
    # pytest installs its own capture handlers on the root logger; a real CLI process starts with none.
    existing = [logging.NullHandler()] if configured else []
    monkeypatch.setattr(root, "handlers", existing)
    capsys.readouterr()

    assert cli_module.main(["db", "stamp", "head", "--sql"]) == 0
    err = capsys.readouterr().err
    if configured:
        # Logging set up by the caller is left alone.
        assert root.handlers == existing
        assert "Running stamp_revision" not in err
    else:
        assert "INFO  [alembic.runtime.migration] Running stamp_revision  -> " in err


def _write_project(tmp_path: Path, tool_flasgo: str) -> None:
    (tmp_path / "pyproject.toml").write_text(f'[project]\nname = "demo"\n\n{tool_flasgo}', encoding="utf-8")
    (tmp_path / "service_app.py").write_text(
        "from flasgo import Flasgo\n"
        "api = Flasgo(settings={'CSRF_ENABLED': False})\n"
        "@api.get('/ping', name='ping')\n"
        "def ping():\n    return 'pong'\n",
        encoding="utf-8",
    )


def _capture_run(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    seen: dict[str, object] = {}

    def fake_run(self: Flasgo, **kwargs: object) -> None:
        seen.update(kwargs)

    monkeypatch.setattr(Flasgo, "run", fake_run)
    return seen


def test_run_reads_defaults_from_tool_flasgo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_project(
        tmp_path,
        '[tool.flasgo]\ntarget = "service_app.py"\napp = "api"\n\n'
        '[tool.flasgo.run]\nhost = "0.0.0.0"\nport = 9000\nreload = true\nreload_dirs = ["templates"]\n',
    )
    seen = _capture_run(monkeypatch)

    assert cli_module.main(["run"]) == 0
    assert seen == {"host": "0.0.0.0", "port": 9000, "reload": True, "reload_dirs": [str(tmp_path.resolve()), "templates"]}


def test_command_line_overrides_tool_flasgo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_project(
        tmp_path,
        '[tool.flasgo]\ntarget = "missing_app.py"\napp = "missing"\n\n'
        '[tool.flasgo.run]\nhost = "0.0.0.0"\nport = 9000\nreload = true\nreload_dirs = ["templates"]\n',
    )
    seen = _capture_run(monkeypatch)

    argv = ["run", "service_app.py:api", "--host", "127.0.0.1", "--port", "8001", "--no-reload", "--reload-dir", "static"]
    assert cli_module.main(argv) == 0
    assert seen == {"host": "127.0.0.1", "port": 8001, "reload": False, "reload_dirs": [str(tmp_path.resolve()), "static"]}


def test_inspection_commands_use_tool_flasgo_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_project(tmp_path, '[tool.flasgo]\ntarget = "service_app.py:api"\n')

    assert cli_module.main(["routes"]) == 0
    assert "/ping" in capsys.readouterr().out
    assert cli_module.main(["openapi"]) == 0
    assert "/ping" in json.loads(capsys.readouterr().out)["paths"]
    assert cli_module.main(["check"]) == 0
    assert "Flasgo check passed." in capsys.readouterr().out


def test_target_is_required_without_tool_flasgo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_project(tmp_path, "[tool.flasgo.run]\nport = 9000\n")
    with pytest.raises(SystemExit) as error:
        cli_module.main(["routes"])
    assert error.value.code == 2
    assert "routes requires a target argument, or a target key in [tool.flasgo]" in capsys.readouterr().err


def test_db_reads_defaults_from_tool_flasgo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _fake_alembic(monkeypatch)
    monkeypatch.chdir(tmp_path)
    _write_project(
        tmp_path,
        '[tool.flasgo.db]\nconfig = "db/alembic.ini"\ndirectory = "db/migrations"\ntemplate = "pyproject_async"\n',
    )
    (tmp_path / "db").mkdir()

    assert cli_module.main(["db", "init"]) == 0
    assert cli_module.main(["db", "init", "--directory", "other", "--template", "generic"]) == 0
    with pytest.raises(SystemExit, match=r"Alembic configuration not found: .*db/alembic\.ini"):
        cli_module.main(["db", "upgrade"])
    (tmp_path / "db" / "alembic.ini").write_text("[alembic]\n", encoding="utf-8")
    assert cli_module.main(["db", "upgrade"]) == 0

    ini, toml = str(tmp_path / "db" / "alembic.ini"), str(tmp_path / "pyproject.toml")
    assert calls == [
        ("init", ini, toml, "db/migrations", "pyproject_async", True),
        ("init", ini, toml, "other", "generic", True),
        ("upgrade", ini, None, "head", False),
    ]


@pytest.mark.parametrize(
    ("flag", "tool_flasgo_db"),
    [
        ("--config", 'pyproject = "pyproject.toml"\n'),
        ("--pyproject", 'config = "pyproject.toml"\n'),
        ("--pyproject", 'config = "db/alembic.ini"\npyproject = "pyproject.toml"\n'),
    ],
)
def test_db_command_line_paths_override_tool_flasgo_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flag: str, tool_flasgo_db: str
) -> None:
    calls = _fake_alembic(monkeypatch)
    monkeypatch.chdir(tmp_path)
    _write_project(tmp_path, f"[tool.flasgo.db]\n{tool_flasgo_db}")
    (tmp_path / "other").mkdir()
    other = tmp_path / "other" / "pyproject.toml"
    other.write_text('[tool.alembic]\nscript_location = "m"\n', encoding="utf-8")

    assert cli_module.main(["db", flag, str(other), "upgrade"]) == 0
    assert calls == [("upgrade", None, str(other), "head", False)]


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        ({"alembic.ini": "[alembic]\n"}, ("alembic.ini", None)),
        ({"pyproject.toml": '[tool.alembic]\nscript_location = "m"\n'}, (None, "pyproject.toml")),
    ],
)
def test_tool_flasgo_db_paths_are_used_only_when_they_hold_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, files: dict[str, str], expected: tuple[str | None, str | None]
) -> None:
    calls = _fake_alembic(monkeypatch)
    monkeypatch.chdir(tmp_path)
    tool_flasgo = '[tool.flasgo.db]\nconfig = "alembic.ini"\npyproject = "pyproject.toml"\n'
    _write_project(tmp_path, files.pop("pyproject.toml", "") + tool_flasgo)
    for name, contents in files.items():
        (tmp_path / name).write_text(contents, encoding="utf-8")

    assert cli_module.main(["db", "upgrade"]) == 0
    ini, toml = (str(tmp_path / name) if name else None for name in expected)
    assert calls == [("upgrade", ini, toml, "head", False)]


def test_db_skips_ini_without_alembic_section(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    calls = _fake_alembic(monkeypatch)
    monkeypatch.chdir(tmp_path)
    # An app's own settings file: handing it to Alembic would make the stock env.py's fileConfig fail.
    (tmp_path / "settings.ini").write_text("[app]\ndebug = true\n", encoding="utf-8")
    _write_project(tmp_path, '[tool.alembic]\nscript_location = "m"\n\n[tool.flasgo.db]\nconfig = "settings.ini"\n')

    assert cli_module.main(["db", "upgrade"]) == 0
    assert calls == [("upgrade", None, str(tmp_path / "pyproject.toml"), "head", False)]
    assert cli_module.main(["config"]) == 0
    assert "settings.ini (no [alembic] section)" in capsys.readouterr().out
    # Named on the command line, the same file is an error rather than silently skipped.
    with pytest.raises(SystemExit, match=r"^No \[alembic\] section in .*settings\.ini\. "):
        cli_module.main(["db", "--config", "settings.ini", "upgrade"])
    (tmp_path / "settings.ini").write_text("not an ini\n", encoding="utf-8")
    with pytest.raises(SystemExit, match=r"^Could not read .*settings\.ini: "):
        cli_module.main(["db", "upgrade"])


def test_tool_flasgo_db_conflicting_pyproject_paths_are_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_alembic(monkeypatch)
    monkeypatch.chdir(tmp_path)
    _write_project(tmp_path, '[tool.flasgo.db]\nconfig = "a/pyproject.toml"\npyproject = "b/pyproject.toml"\n')
    with pytest.raises(SystemExit, match=r"either tool\.flasgo\.db\.config or tool\.flasgo\.db\.pyproject, not both"):
        cli_module.main(["db", "upgrade"])


@pytest.mark.parametrize("flag", ["--config", "--pyproject"])
def test_db_rejects_empty_command_line_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flag: str) -> None:
    _fake_alembic(monkeypatch)
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit, match=f"{flag} must not be empty"):
        cli_module.main(["db", flag, "", "upgrade"])


@pytest.mark.parametrize("argv", [["--help"], ["run", "-h"], ["db", "upgrade", "--help"]])
def test_help_works_with_broken_pyproject(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], argv: list[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_text("[tool\n", encoding="utf-8")
    with pytest.raises(SystemExit) as error:
        cli_module.main(argv)
    assert error.value.code == 0
    assert "usage: flasgo" in capsys.readouterr().out


def test_broken_pyproject_still_fails_other_commands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_text("[tool\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="Could not read"):
        cli_module.main(["routes", "app.py", "--", "--help"])


@pytest.mark.parametrize(
    ("tool_flasgo", "message"),
    [
        ('[tool]\nflasgo = "app.py"\n', r"\[tool\.flasgo\] .* must be a table"),
        ('[tool.flasgo]\ntarget = "app.py"\nhost = "0.0.0.0"\n', r"Unknown key\(s\) in \[tool\.flasgo\] .*: host"),
        ('[tool.flasgo.run]\nreload-dirs = ["x"]\n', r"Unknown key\(s\) in \[tool\.flasgo\.run\] .*: reload-dirs"),
        ("[tool.flasgo]\ntarget = 1\n", "tool.flasgo.target .* must be a string"),
        ("[tool.flasgo]\nrun = 1\n", r"\[tool\.flasgo\.run\] .* must be a table"),
        ('[tool.flasgo.run]\nport = "8000"\n', "tool.flasgo.run.port .* must be an integer"),
        ("[tool.flasgo.run]\nport = true\n", "tool.flasgo.run.port .* must be an integer"),
        ('[tool.flasgo.run]\nreload = "yes"\n', "tool.flasgo.run.reload .* must be a boolean"),
        ('[tool.flasgo.run]\nreload_dirs = "templates"\n', "tool.flasgo.run.reload_dirs .* must be a list of non-empty strings"),
        ('[tool.flasgo.run]\nreload_dirs = ["templates", " "]\n', "tool.flasgo.run.reload_dirs .* must be a list of non-empty strings"),
        ("[tool.flasgo.run]\nport = 65536\n", "tool.flasgo.run.port .* must be between 0 and 65535"),
        ("[tool.flasgo.run]\nport = -1\n", "tool.flasgo.run.port .* must be between 0 and 65535"),
        ('[tool.flasgo.db]\ntemplate = "django"\n', "tool.flasgo.db.template .* must be one of: generic"),
        ('[tool.flasgo]\ntarget = " "\n', "tool.flasgo.target .* must not be empty"),
        ('[tool.flasgo.db]\nconfig = ""\n', "tool.flasgo.db.config .* must not be empty"),
    ],
)
def test_invalid_tool_flasgo_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tool_flasgo: str, message: str) -> None:
    monkeypatch.chdir(tmp_path)
    _write_project(tmp_path, tool_flasgo)
    _capture_run(monkeypatch)
    with pytest.raises(SystemExit, match=message):
        cli_module.main(["run", "service_app.py:api"])


@pytest.mark.parametrize(("port", "message"), [("65536", "port must be between 0 and 65535, not 65536"), ("http", "invalid port: 'http'")])
def test_run_rejects_out_of_range_port_flag(capsys: pytest.CaptureFixture[str], port: str, message: str) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli_module.main(["run", "app.py", "--port", port])
    assert exc_info.value.code == 2
    assert message in capsys.readouterr().err


def test_run_rejects_empty_reload_dir_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli_module.main(["run", "app.py", "--reload-dir", " "])
    assert exc_info.value.code == 2
    assert "argument --reload-dir: must not be empty" in capsys.readouterr().err


def test_db_maintenance_commands_delegate_to_alembic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _fake_alembic(monkeypatch)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "alembic.ini").write_text("[alembic]\n", encoding="utf-8")

    assert cli_module.main(["db", "revision", "-m", "backfill"]) == 0
    assert cli_module.main(["db", "current"]) == 0
    assert cli_module.main(["db", "current", "-v", "--check-heads"]) == 0
    assert cli_module.main(["db", "history"]) == 0
    assert cli_module.main(["db", "history", "-r", "-3:", "-v", "-i"]) == 0
    assert cli_module.main(["db", "stamp", "head"]) == 0
    assert cli_module.main(["db", "stamp", "base", "--sql", "--purge"]) == 0
    with pytest.raises(SystemExit, match=r"^Alembic: New upgrade operations detected"):
        cli_module.main(["db", "check"])

    ini = str(tmp_path / "alembic.ini")
    assert calls == [
        ("revision", ini, None, "backfill", False),
        ("current", False, False),
        ("current", True, True),
        ("history", None, False, False),
        ("history", "-3:", True, True),
        ("stamp", "head", False, False),
        ("stamp", "base", True, True),
    ]


@pytest.mark.parametrize("broken", [False, True])
def test_version_reports_installed_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], broken: bool
) -> None:
    monkeypatch.chdir(tmp_path)
    if broken:
        (tmp_path / "pyproject.toml").write_text("[tool\n", encoding="utf-8")
    with pytest.raises(SystemExit) as error:
        cli_module.main(["--version"])
    assert error.value.code == 0
    assert capsys.readouterr().out == f"flasgo {importlib.metadata.version('flasgo')}\n"


def test_config_reports_values_and_sources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.chdir(tmp_path)
    _write_project(
        tmp_path,
        '[tool.flasgo]\ntarget = "service_app.py"\n\n[tool.flasgo.run]\nport = 9000\n\n'
        '[tool.flasgo.db]\nconfig = "db/alembic.ini"\n\n[tool.alembic]\nscript_location = "m"\n',
    )

    assert cli_module.main(["config", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["pyproject"] == {"path": str(tmp_path / "pyproject.toml"), "status": "[tool.flasgo] found"}
    settings = {row["setting"]: (row["value"], row["source"]) for row in report["settings"]}
    assert settings == {
        "target": ("service_app.py", "pyproject.toml"),
        "app": ("app", "default"),
        "run.host": ("127.0.0.1", "default"),
        "run.port": (9000, "pyproject.toml"),
        "run.reload": (None, "default"),
        "run.reload_dirs": (None, "default"),
        "db.config": ("db/alembic.ini", "pyproject.toml"),
        "db.pyproject": ("pyproject.toml", "default"),
        "db.directory": ("migrations", "default"),
        "db.template": ("generic", "default"),
    }
    assert report["alembic"] == {
        "ini": {"path": str(tmp_path / "db" / "alembic.ini"), "used": False},
        "pyproject": {"path": str(tmp_path / "pyproject.toml"), "used": True},
    }

    assert cli_module.main(["config"]) == 0
    text = capsys.readouterr().out
    assert f"pyproject.toml: {tmp_path / 'pyproject.toml'} ([tool.flasgo] found)" in text
    assert re.search(r"^run\.port\s+9000\s+pyproject\.toml$", text, re.MULTILINE)
    assert re.search(r"^run\.reload\s+\(app DEBUG setting\)\s+default$", text, re.MULTILINE)
    assert re.search(r"^  alembic\.ini\s+.*db/alembic\.ini \(not found\)$", text, re.MULTILINE)
    assert re.search(r"^  \[tool\.alembic\]\s+.*pyproject\.toml \(used\)$", text, re.MULTILINE)


def test_config_without_pyproject_shows_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    assert cli_module.main(["config", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["pyproject"]["status"] == "not found"
    assert {row["source"] for row in report["settings"]} == {"default"}


def test_config_distinguishes_missing_file_from_missing_table(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    assert cli_module.main(["config"]) == 0
    assert re.search(r"^  \[tool\.alembic\]\s+.*pyproject\.toml \(not found\)$", capsys.readouterr().out, re.MULTILINE)
    _write_project(tmp_path, "")
    assert cli_module.main(["config"]) == 0
    text = capsys.readouterr().out
    assert "(no [tool.flasgo] table)" in text
    assert re.search(r"^  \[tool\.alembic\]\s+.*pyproject\.toml \(no \[tool\.alembic\] table\)$", text, re.MULTILINE)


_SCHEMA_PATH = Path(cli_module.__file__).with_name("tool-flasgo.schema.json")


def _schema_shape(schema: dict[str, object]) -> dict[str, object]:
    json_types = {"string": str, "integer": int, "boolean": bool, "array": list}
    properties = schema["properties"]
    assert isinstance(properties, dict)
    return {key: _schema_shape(value) if value["type"] == "object" else json_types[value["type"]] for key, value in properties.items()}


def test_tool_flasgo_schema_matches_cli_settings() -> None:
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    assert _schema_shape(schema) == cli_module._PROJECT_SCHEMA
    assert schema["properties"]["db"]["properties"]["template"]["enum"] == list(cli_module._ALEMBIC_TEMPLATES)
    for table, fields in cli_module._CLI_DEFAULTS.items():
        entries = fields.items() if isinstance(fields, dict) else [(None, fields)]
        for field, default in entries:
            prop = schema["properties"][table] if field is None else schema["properties"][table]["properties"][field]
            assert prop.get("default") == default, f"{table}.{field}"


@pytest.mark.parametrize(
    "tool_flasgo",
    [
        '[tool.flasgo]\ntarget = "app.py:api"\napp = "api"\n',
        '[tool.flasgo.run]\nhost = "0.0.0.0"\nport = 9000\nreload = false\nreload_dirs = ["templates"]\n',
        '[tool.flasgo.db]\nconfig = "a.ini"\npyproject = "pyproject.toml"\ndirectory = "m"\ntemplate = "pyproject"\n',
        '[tool.flasgo]\nhost = "0.0.0.0"\n',
        "[tool.flasgo]\ntarget = 1\n",
        '[tool.flasgo]\ntarget = " "\n',
        "[tool.flasgo]\nrun = 1\n",
        '[tool.flasgo.run]\nport = "8000"\n',
        "[tool.flasgo.run]\nport = true\n",
        '[tool.flasgo.run]\nreload_dirs = "templates"\n',
        "[tool.flasgo.run]\nreload_dirs = [1]\n",
        '[tool.flasgo.run]\nreload_dirs = [""]\n',
        "[tool.flasgo.run]\nport = 0\n",
        "[tool.flasgo.run]\nport = 65535\n",
        "[tool.flasgo.run]\nport = 65536\n",
        "[tool.flasgo.run]\nport = -1\n",
        '[tool.flasgo.db]\ntemplate = "django"\n',
        '[tool.flasgo.db]\nconfig = ""\n',
    ],
)
def test_tool_flasgo_schema_agrees_with_cli_validation(tmp_path: Path, tool_flasgo: str) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    path = tmp_path / "pyproject.toml"
    path.write_text(tool_flasgo, encoding="utf-8")
    table = tomllib.loads(tool_flasgo)["tool"]["flasgo"]
    try:
        cli_module.load_project_settings(path)
    except SystemExit:
        cli_accepts = False
    else:
        cli_accepts = True
    schema_accepts = jsonschema.Draft7Validator(json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))).is_valid(table)
    assert schema_accepts == cli_accepts


@pytest.mark.parametrize("option", ["-o", "--output"])
def test_routes_output_is_valid_json_despite_app_import_output(tmp_path: Path, capsys: pytest.CaptureFixture[str], option: str) -> None:
    app_file = tmp_path / "noisy_app.py"
    app_file.write_text("print('application startup')\nfrom flasgo import Flasgo\napp = Flasgo()\n")
    output = tmp_path / "snapshots" / "policy.json"
    assert cli_module.main(["routes", str(app_file), "--json", option, str(output)]) == 0
    document = output.read_text()
    assert json.loads(document)["schema_version"] == 1
    assert document.endswith("\n")
    assert capsys.readouterr().out == "application startup\n"
    assert cli_module.main(["check", str(app_file), "--against", str(output), "--json"]) == 0


@pytest.mark.parametrize("flags", [[], ["--policy"]])
def test_routes_output_requires_json_before_loading_app(tmp_path: Path, flags: list[str]) -> None:
    output = tmp_path / "policy.json"
    output.write_text("existing")
    with pytest.raises(SystemExit) as error:
        cli_module.main(["routes", "does_not_exist.py", *flags, "--output", str(output)])
    assert error.value.code == 2
    assert output.read_text() == "existing"


def test_routes_output_failure_preserves_baseline_and_removes_temporary_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output = tmp_path / "policy.json"
    output.write_text("existing")
    monkeypatch.setattr(cli_module, "load_app", lambda *args, **kwargs: Flasgo())

    def fail_replace(*args: object) -> None:
        raise OSError("replacement failed")

    monkeypatch.setattr(cli_module.os, "replace", fail_replace)
    with pytest.raises(OSError, match="replacement failed"):
        cli_module.main(["routes", "unused", "--json", "--output", str(output)])
    assert output.read_text() == "existing"
    assert list(tmp_path.iterdir()) == [output]
