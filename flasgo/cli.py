import argparse
import configparser
import importlib
import importlib.metadata
import json
import logging
import os
import re
import secrets
import shlex
import stat
import subprocess
import sys
import tomllib
import traceback
from collections.abc import Callable, Mapping
from contextlib import nullcontext, redirect_stdout
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

from .app import Flasgo
from .policy import compare_policy, deployment_issues


@dataclass(frozen=True, slots=True)
class _ResolvedTarget:
    module_name: str
    import_root: Path
    source: Path | None
    watch_dir: Path | None
    attr_name: str | None


_CLI_NAMESPACE_ROOTS: dict[str, Path] = {}
_CLI_ROOT_MODULES: dict[Path, dict[str, ModuleType]] = {}
_MISSING = object()
_DEFAULT_ALEMBIC_INI = "alembic.ini"
_DEFAULT_PYPROJECT = "pyproject.toml"
_MIN_PORT = 0
_MAX_PORT = 65535
_ALEMBIC_TEMPLATES = ("generic", "async", "multidb", "pyproject", "pyproject_async")
# The [tool.flasgo] keys each command accepts: a type for a value, or a nested dict for a sub-table.
_PROJECT_SCHEMA: dict[str, Any] = {
    "target": str,
    "app": str,
    "run": {"host": str, "port": int, "reload": bool, "reload_dirs": list},
    "db": {"config": str, "pyproject": str, "directory": str, "template": str},
}
_TOML_TYPE_NAMES: dict[type, str] = {str: "a string", int: "an integer", bool: "a boolean"}
# Built-in value of every [tool.flasgo] key, shared by the parser, `flasgo config`, and the schema tests.
# None means the command decides at run time, as described in _RUNTIME_DEFAULT_LABELS.
_CLI_DEFAULTS: dict[str, Any] = {
    "target": None,
    "app": "app",
    "run": {"host": "127.0.0.1", "port": 8000, "reload": None, "reload_dirs": None},
    "db": {"config": _DEFAULT_ALEMBIC_INI, "pyproject": _DEFAULT_PYPROJECT, "directory": "migrations", "template": "generic"},
}
_RUNTIME_DEFAULT_LABELS = {
    "target": "(none: pass a target)",
    "run.reload": "(app DEBUG setting)",
    "run.reload_dirs": "(target directory only)",
}


def build_parser(project_settings: Mapping[str, Any] | None = None) -> argparse.ArgumentParser:
    """
    Create the Flasgo CLI argument parser.

    Parameters:
        project_settings (Mapping[str, Any] | None): A validated ``[tool.flasgo]`` table, as returned by
            ``load_project_settings``. Its values become option defaults, and command-line flags still override them.
    """

    settings = project_settings or {}
    target_defaults = {key: settings[key] for key in ("target", "app") if key in settings}
    run_settings = dict(settings.get("run", {}))
    db_settings = dict(settings.get("db", {}))

    parser = argparse.ArgumentParser(prog="flasgo", suggest_on_error=True)
    parser.add_argument("--version", action="version", version=f"%(prog)s {_flasgo_version()}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run a Flasgo application")
    _add_target_arguments(run_parser, target_defaults)
    run_parser.add_argument("--host", default=_CLI_DEFAULTS["run"]["host"], help="Host interface to bind")
    run_parser.add_argument("--port", type=_port_argument, default=_CLI_DEFAULTS["run"]["port"], help="Port to bind")
    run_parser.add_argument(
        "--reload",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable or disable automatic reload. Defaults to app settings DEBUG when omitted.",
    )
    run_parser.add_argument(
        "--reload-dir",
        dest="reload_dirs",
        action="append",
        type=_non_empty_argument,
        default=None,
        help="Additional directory to watch for reload. Can be specified multiple times; replaces run.reload_dirs from pyproject.toml.",
    )
    # Configured reload directories live apart from --reload-dir, so passing the flag replaces them instead of appending.
    configured_reload_dirs = run_settings.pop("reload_dirs", None)
    run_parser.set_defaults(handler=_run_command, configured_reload_dirs=configured_reload_dirs, **run_settings)

    routes_parser = subparsers.add_parser("routes", help="List registered HTTP and WebSocket routes")
    _add_target_arguments(routes_parser, target_defaults)
    routes_parser.add_argument("--policy", action="store_true", help="Explain effective route security policies")
    routes_parser.add_argument("--json", action="store_true", help="Emit a versioned policy snapshot as JSON")
    routes_parser.add_argument("-o", "--output", help="Write the JSON policy snapshot atomically to this file")
    routes_parser.set_defaults(handler=_routes_command)

    openapi_parser = subparsers.add_parser("openapi", help="Render the application's OpenAPI document")
    _add_target_arguments(openapi_parser, target_defaults)
    openapi_parser.add_argument("-o", "--output", help="Write atomically to this file instead of stdout")
    openapi_parser.set_defaults(handler=_openapi_command)

    check_parser = subparsers.add_parser("check", help="Validate routes and application configuration")
    _add_target_arguments(check_parser, target_defaults)
    check_parser.add_argument("--deploy", action="store_true", help="Check production security settings and declared access")
    check_parser.add_argument("--json", action="store_true", help="Emit structured issues and policy changes")
    check_parser.add_argument("--against", help="Compare with a routes --json policy snapshot; fail on any change")
    check_parser.set_defaults(handler=_check_command)

    config_parser = subparsers.add_parser(
        "config", help=f"Show the CLI settings in effect and whether each comes from {_DEFAULT_PYPROJECT}"
    )
    config_parser.add_argument("--json", action="store_true", help="Emit the settings and Alembic files as JSON")
    config_parser.set_defaults(handler=_config_command)

    db_parser = subparsers.add_parser("db", help="Manage optional Alembic database migrations")
    db_parser.add_argument(
        "--config",
        default=None,
        help=f"Alembic .ini file (default {_DEFAULT_ALEMBIC_INI}); a path named pyproject.toml is treated like --pyproject",
    )
    db_parser.add_argument(
        "--pyproject",
        default=None,
        help=f"pyproject.toml file whose [tool.alembic] table configures Alembic (default {_DEFAULT_PYPROJECT})",
    )
    # Configured paths stay apart from --config/--pyproject: typed flags must override them, and only a typed path must exist.
    db_parser.set_defaults(configured_db_config=db_settings.get("config"), configured_db_pyproject=db_settings.get("pyproject"))
    db_subparsers = db_parser.add_subparsers(dest="db_command", required=True)

    db_init = db_subparsers.add_parser("init", help="Create an Alembic migration environment")
    db_init.add_argument("--directory", default=_CLI_DEFAULTS["db"]["directory"], help="Migration script directory")
    db_init.add_argument(
        "--template",
        choices=_ALEMBIC_TEMPLATES,
        default=_CLI_DEFAULTS["db"]["template"],
        help="Alembic environment template; pyproject and pyproject_async keep settings in [tool.alembic]",
    )
    db_init.set_defaults(handler=_db_command, **{key: db_settings[key] for key in ("directory", "template") if key in db_settings})

    db_migrate = db_subparsers.add_parser("migrate", help="Autogenerate a migration revision")
    db_migrate.add_argument("-m", "--message", required=True, help="Migration description")
    db_migrate.set_defaults(handler=_db_command)

    db_revision = db_subparsers.add_parser("revision", help="Create an empty migration revision to write by hand")
    db_revision.add_argument("-m", "--message", required=True, help="Migration description")
    db_revision.set_defaults(handler=_db_command)

    for command_name, default_revision in (("upgrade", "head"), ("downgrade", "-1")):
        db_move = db_subparsers.add_parser(command_name, help=f"{command_name.title()} the database")
        db_move.add_argument("revision", nargs="?", default=default_revision, help="Alembic revision target")
        db_move.add_argument("--sql", action="store_true", help="Print SQL without changing the database")
        db_move.set_defaults(handler=_db_command)

    db_current = db_subparsers.add_parser("current", help="Show the revision the database is at")
    db_current.add_argument("-v", "--verbose", action="store_true", help="Show full revision details")
    db_current.add_argument("--check-heads", action="store_true", help="Fail unless every head revision is applied")
    db_current.set_defaults(handler=_db_command)

    db_history = db_subparsers.add_parser("history", help="List migration revisions")
    db_history.add_argument("-r", "--rev-range", help="Revision range such as base:head or -3:")
    db_history.add_argument("-v", "--verbose", action="store_true", help="Show full revision details")
    db_history.add_argument("-i", "--indicate-current", action="store_true", help="Mark the database's current revision")
    db_history.set_defaults(handler=_db_command)

    db_stamp = db_subparsers.add_parser("stamp", help="Record a revision in the database without running migrations")
    db_stamp.add_argument("revision", help="Revision to record, such as head")
    db_stamp.add_argument("--sql", action="store_true", help="Print SQL without changing the database")
    db_stamp.add_argument("--purge", action="store_true", help="Clear the version table before stamping")
    db_stamp.set_defaults(handler=_db_command)

    db_check = db_subparsers.add_parser("check", help="Fail if the models have changes that no migration covers")
    db_check.set_defaults(handler=_db_command)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the Flasgo CLI entrypoint."""

    try:
        settings = load_project_settings(Path(_DEFAULT_PYPROJECT))
    except SystemExit:
        # A broken pyproject.toml must not hide --help or --version; every other command still reports it.
        if not _wants_help_or_version(sys.argv[1:] if argv is None else argv):
            raise
        settings = {}
    parser = build_parser(settings)
    args = parser.parse_args(argv)
    if getattr(args, "target", _MISSING) is None:
        parser.error(f"{args.command} requires a target argument, or a target key in [tool.flasgo] in {_DEFAULT_PYPROJECT}")
    if args.command == "routes" and args.output is not None and not args.json:
        parser.error("routes --output requires --json")
    handler = args.handler
    return int(handler(args))


def _wants_help_or_version(argv: list[str]) -> bool:
    for arg in argv:
        if arg == "--":
            return False
        if arg in {"-h", "--help", "--version"}:
            return True
    return False


def _flasgo_version() -> str:
    try:
        return importlib.metadata.version("flasgo")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _config_command(args: argparse.Namespace) -> int:
    """
    Show each [tool.flasgo] setting's effective value and source, plus the Alembic files `flasgo db` would read.

    Returns:
        int: Zero after printing the report.
    """
    path = Path(_DEFAULT_PYPROJECT).resolve()
    settings = load_project_settings(path)
    rows = []
    for key, default in _flatten_settings(_CLI_DEFAULTS).items():
        configured = _flatten_settings(settings).get(key, _MISSING)
        source = _DEFAULT_PYPROJECT if configured is not _MISSING else "default"
        rows.append({"setting": key, "value": default if configured is _MISSING else configured, "source": source})
    db_settings = settings.get("db", {})
    files = _alembic_files(
        argparse.Namespace(
            config=None,
            pyproject=None,
            configured_db_config=db_settings.get("config"),
            configured_db_pyproject=db_settings.get("pyproject"),
        )
    )
    alembic = {
        "ini": {"path": str(files.ini), "used": _has_alembic_ini(files.ini, required=False)},
        "pyproject": {"path": str(files.toml), "used": _has_tool_alembic(files.toml, required=False)},
    }
    status = ("[tool.flasgo] found" if settings else "no [tool.flasgo] table") if path.is_file() else "not found"
    if args.json:
        report = {"pyproject": {"path": str(path), "status": status}, "settings": rows, "alembic": alembic}
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    print(f"{_DEFAULT_PYPROJECT}: {path} ({status})\n")
    print(f"{'SETTING':<17} {'VALUE':<32} SOURCE")
    for row in rows:
        value = _RUNTIME_DEFAULT_LABELS.get(row["setting"], "-") if row["value"] is None else json.dumps(row["value"])
        print(f"{row['setting']:<17} {value:<32} {row['source']}")
    print("\nAlembic configuration for `flasgo db`:")
    ini_missing = "no [alembic] section" if files.ini.is_file() else "not found"
    toml_missing = "no [tool.alembic] table" if files.toml.is_file() else "not found"
    for label, entry, missing in (("alembic.ini", alembic["ini"], ini_missing), ("[tool.alembic]", alembic["pyproject"], toml_missing)):
        print(f"  {label:<15} {entry['path']} ({'used' if entry['used'] else missing})")
    return 0


def _flatten_settings(table: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    flat: dict[str, Any] = {}
    for key, value in table.items():
        if isinstance(value, dict):
            flat.update(_flatten_settings(value, f"{prefix}{key}."))
        else:
            flat[f"{prefix}{key}"] = value
    return flat


def load_project_settings(path: Path) -> dict[str, Any]:
    """
    Read and validate the ``[tool.flasgo]`` table of a pyproject.toml file.

    Parameters:
        path (Path): The pyproject.toml file; a missing file means no project settings.

    Returns:
        dict[str, Any]: The validated table, or an empty dict when the file or table is absent.
    """
    if not path.is_file():
        return {}
    tool = _read_toml(path).get("tool")
    settings = tool.get("flasgo") if isinstance(tool, dict) else None
    if settings is None:
        return {}
    _validate_project_table(settings, _PROJECT_SCHEMA, "tool.flasgo", path)
    port = settings.get("run", {}).get("port")
    if port is not None and not _MIN_PORT <= port <= _MAX_PORT:
        raise SystemExit(f"tool.flasgo.run.port in {path} must be between {_MIN_PORT} and {_MAX_PORT}.")
    template = settings.get("db", {}).get("template")
    if template is not None and template not in _ALEMBIC_TEMPLATES:
        raise SystemExit(f"tool.flasgo.db.template in {path} must be one of: {', '.join(_ALEMBIC_TEMPLATES)}.")
    return settings


def _validate_project_table(table: object, schema: Mapping[str, Any], name: str, path: Path) -> None:
    if not isinstance(table, dict):
        raise SystemExit(f"[{name}] in {path} must be a table.")
    unknown = sorted(set(table) - set(schema))
    if unknown:
        raise SystemExit(f"Unknown key(s) in [{name}] in {path}: {', '.join(unknown)}. Supported keys: {', '.join(schema)}.")
    for key, value in table.items():
        expected = schema[key]
        if isinstance(expected, dict):
            _validate_project_table(value, expected, f"{name}.{key}", path)
        elif expected is list:
            if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
                raise SystemExit(f"{name}.{key} in {path} must be a list of non-empty strings.")
        # TOML booleans are Python bools, which are also ints, so a port of `true` must not pass as 1.
        elif not isinstance(value, expected) or (expected is int and isinstance(value, bool)):
            raise SystemExit(f"{name}.{key} in {path} must be {_TOML_TYPE_NAMES[expected]}.")
        elif expected is str and not value.strip():
            raise SystemExit(f"{name}.{key} in {path} must not be empty.")


def _non_empty_argument(value: str) -> str:
    if not value.strip():
        raise argparse.ArgumentTypeError("must not be empty")
    return value


def _port_argument(value: str) -> int:
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid port: {value!r}") from None
    if not _MIN_PORT <= port <= _MAX_PORT:
        raise argparse.ArgumentTypeError(f"port must be between {_MIN_PORT} and {_MAX_PORT}, not {port}")
    return port


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as source:
            return tomllib.load(source)
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise SystemExit(f"Could not read {path.resolve()}: {exc}") from None


def _run_command(args: argparse.Namespace) -> int:
    app, resolved = _load_app_target(args.target, app_name=args.app)
    extra_dirs = args.reload_dirs if args.reload_dirs is not None else args.configured_reload_dirs
    reload_dirs = _reload_dirs(resolved, extra_dirs)
    app.run(
        host=args.host,
        port=args.port,
        reload=args.reload,
        reload_dirs=reload_dirs,
    )
    return 0


def _add_target_arguments(parser: argparse.ArgumentParser, defaults: Mapping[str, str]) -> None:
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Python file path or import string such as app.py or package.module:app (default: target in [tool.flasgo])",
    )
    parser.add_argument("--app", default=_CLI_DEFAULTS["app"], help="Application variable name when loading from a Python file")
    parser.set_defaults(**defaults)


def _routes_command(args: argparse.Namespace) -> int:
    """
    List the application's registered HTTP and WebSocket routes or emit its policy snapshot.

    Returns:
        int: Zero after successfully displaying or writing the route information.
    """
    app = load_app(args.target, app_name=args.app)
    if args.json or args.policy:
        snapshot = app.policy_snapshot()
        if args.json:
            document = json.dumps(snapshot, indent=2, sort_keys=True, allow_nan=False) + "\n"
            if args.output is None:
                print(document, end="")
            else:
                _atomic_write(Path(args.output), document)
        else:
            print(snapshot["scope"])
            for route in snapshot["routes"]:
                print(json.dumps(route, sort_keys=True, allow_nan=False))
        return 0
    print("PROTOCOL  METHODS      PATH                      NAME")
    for route in app._routes:
        methods = ",".join(sorted(route.methods))
        print(f"http      {methods:<12} {route.raw_path:<25} {route.name or '-'}")
    for route in app._websocket_routes:
        print(f"websocket {'-':<12} {route.raw_path:<25} {route.name or '-'}")
    return 0


def _openapi_command(args: argparse.Namespace) -> int:
    app = load_app(args.target, app_name=args.app)
    document = json.dumps(app.openapi_spec(), indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.output is None:
        print(document, end="")
    else:
        _atomic_write(Path(args.output), document)
    return 0


def _check_command(args: argparse.Namespace) -> int:
    """Validate registered routes, authentication configuration, internal endpoint conflicts, deployment settings, and policy changes.

    Parameters:
        args (argparse.Namespace): Command-line options specifying the application target and enabled checks.

    Returns:
        int: 1 if validation issues or policy changes are found, otherwise 0.
    """
    try:
        with redirect_stdout(sys.stderr) if args.json else nullcontext():
            app = load_app(args.target, app_name=args.app)
    except (SystemExit, Exception) as exc:
        if args.json:
            print(
                json.dumps(
                    {"passed": False, "issues": [{"code": "registration", "severity": "error", "message": str(exc)}], "changes": []},
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            print(str(exc), file=sys.stderr)
        return 1
    errors: list[str] = []
    seen_http: set[tuple[str, str]] = set()
    seen_ws: set[str] = set()
    seen_names: set[str] = set()

    for route in app._routes:
        for method in route.methods:
            key = route.raw_path, method
            if key in seen_http:
                errors.append(f"duplicate HTTP route: {method} {route.raw_path}")
            seen_http.add(key)
        if route.name:
            if route.name in seen_names:
                errors.append(f"duplicate route name: {route.name}")
            seen_names.add(route.name)

    for route in app._websocket_routes:
        if route.raw_path in seen_ws:
            errors.append(f"duplicate WebSocket route: {route.raw_path}")
        seen_ws.add(route.raw_path)
        if route.name:
            if route.name in seen_names:
                errors.append(f"duplicate route name: {route.name}")
            seen_names.add(route.name)

    errors.extend(
        f"missing authentication backend: {auth.backend}" for auth in app._route_auth.values() if auth.backend not in app._auth_backends
    )

    internal_paths: set[str] = set()
    if app.settings.ENABLE_DOCS:
        internal_paths.update((app.settings.DOCS_PATH, app.settings.OPENAPI_PATH))
    if app.settings.METRICS_ENABLED:
        internal_paths.add(app.settings.METRICS_PATH)
    errors.extend(
        f"route conflicts with enabled internal endpoint: {route.raw_path}" for route in app._routes if route.raw_path in internal_paths
    )

    issues = [{"code": "registration", "severity": "error", "message": error} for error in sorted(set(errors))]
    if args.deploy:
        issues.extend(issue.to_dict() for issue in deployment_issues(app))
    changes = []
    if args.against:
        try:
            with Path(args.against).open("rb") as source:
                raw = source.read(2_097_153)
            if len(raw) > 2_097_152:
                raise ValueError("Policy snapshot exceeds 2 MiB.")
            changes = compare_policy(json.loads(raw), app.policy_snapshot())
        except (OSError, ValueError, RecursionError) as exc:
            issues.append({"code": "policy_snapshot", "severity": "error", "message": str(exc)})
    failed = bool(issues or changes)
    if args.json:
        print(json.dumps({"passed": not failed, "issues": issues, "changes": changes}, indent=2, sort_keys=True))
    else:
        for issue in issues:
            print(f"{issue['severity']}: {issue['code']}: {issue['message']}", file=sys.stderr)
        for change in changes:
            target = change.get("route")
            detail = f"{change['section']} {target}" if target else change["section"]
            print(f"policy changed: {detail}", file=sys.stderr)
        if not failed:
            print("Flasgo check passed.")
    return int(failed)


def _atomic_write(path: Path, value: str) -> None:
    """
    Atomically write text content to a file.

    Parameters:
        path (Path): Destination file path.
        value (str): Text content to write.
    """
    expanded = path.expanduser()
    absolute = expanded if expanded.is_absolute() else Path.cwd() / expanded
    parent = absolute.parent.resolve()
    parent.mkdir(parents=True, exist_ok=True)
    destination = parent / absolute.name
    try:
        entry = destination.lstat()
    except FileNotFoundError:
        entry = None
    # A symlink is replaced by a regular file, so treat it as new: inheriting the *target's* mode could make
    # output public that the caller's umask would keep private.
    existing_mode = stat.S_IMODE(entry.st_mode) if entry is not None and not stat.S_ISLNK(entry.st_mode) else None
    temporary: Path | None = None
    try:
        # A replacement starts with the destination's own mode, so a private (0600) file's new contents are never
        # readable by others, even briefly. A new file uses 0o666 and the kernel applies the current umask; reading
        # or changing the process umask would widen permissions for files other threads create meanwhile.
        initial_mode = existing_mode if existing_mode is not None else 0o666
        temporary, descriptor = _create_temporary(parent, destination.name, mode=initial_mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        if existing_mode is not None:
            # Restore any bits the umask stripped at creation; this never widens access beyond the destination's.
            temporary.chmod(existing_mode)
        temporary.replace(destination)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _create_temporary(parent: Path, name: str, *, mode: int) -> tuple[Path, int]:
    """Exclusively create a hidden sibling file for an atomic replace, with ``mode`` masked by the umask."""
    for _attempt in range(100):
        candidate = parent / f".{name}.{secrets.token_hex(8)}"
        try:
            return candidate, os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        except FileExistsError:
            continue
    raise FileExistsError(f"Could not create a temporary file next to {parent / name}.")


def _db_command(args: argparse.Namespace) -> int:
    command, config_type = _load_alembic()
    files = _alembic_files(args)
    if args.db_command == "init":
        # Alembic writes alembic.ini for every template, and pyproject templates also add [tool.alembic] to pyproject.toml.
        config = config_type(file_=str(files.ini), toml_file=str(files.toml))
        # A relative directory stays relative so Alembic records a portable "%(here)s/..." script_location.
        directory = Path(args.directory).expanduser()
        try:
            command.init(config, str(directory), template=args.template, package=True)
        except _alembic_command_error() as exc:
            raise SystemExit(f"Alembic: {exc}") from None
        print(_db_init_next_steps(files.ini, directory, args))
        return 0
    config_kwargs = _alembic_config_kwargs(files)
    if config_kwargs["file_"] is None:
        _configure_default_alembic_logging()
    config = config_type(**config_kwargs)
    try:
        _DB_ACTIONS[args.db_command](command, config, args)
    except _alembic_command_error() as exc:
        # Alembic's expected failures (existing directory, unapplied heads, model drift) read best as one line, as in its own CLI.
        raise SystemExit(f"Alembic: {exc}") from None
    except Exception as exc:
        # env.py turns an unset or placeholder sqlalchemy.url into a deep SQLAlchemy traceback; name the setting instead.
        message = _database_url_error(exc, config, files.ini)
        if message is None:
            raise
        raise SystemExit(message) from None
    return 0


def _configure_default_alembic_logging() -> None:
    """
    Show Alembic's progress messages when no alembic.ini supplies a logging configuration.

    Alembic keeps logging settings in alembic.ini even for pyproject templates, and env.py only calls fileConfig when
    that file is in use, so a pyproject-only setup would run stamp and upgrade silently. This mirrors the ini's
    defaults: alembic at INFO, everything else at WARNING, on stderr. Logging configured elsewhere is left alone.
    """
    root = logging.getLogger()
    if root.handlers:
        return
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(levelname)-5.5s [%(name)s] %(message)s"))
    root.addHandler(handler)
    root.setLevel(logging.WARNING)
    logging.getLogger("alembic").setLevel(logging.INFO)


# The sqlalchemy.url that `alembic init` writes into alembic.ini for every template.
_ALEMBIC_PLACEHOLDER_URL = "driver://user:pass@localhost/dbname"


def _db_init_next_steps(ini: Path, directory: Path, args: argparse.Namespace) -> str:
    ini = _display_path(ini)
    env = directory / "env.py"
    if args.template == "multidb":
        url_step = f"Set the URL of each database listed in {ini}."
        metadata_step = f"Map each engine name in target_metadata in {env} to that database's MetaData"
    else:
        url_step = f"Set sqlalchemy.url in {ini} to your database URL, or have {env} supply one."
        metadata_step = f"Point target_metadata in {env} at your models' MetaData"
    # Paths typed on the command line must be repeated; [tool.flasgo.db] paths are picked up again automatically.
    db = _shell_join(
        ["flasgo", "db"]
        + [part for flag, value in (("--config", args.config), ("--pyproject", args.pyproject)) if value for part in (flag, value)]
    )
    return (
        "Next steps:\n"
        f"  1. {url_step}\n"
        f"  2. {metadata_step} so autogenerate can compare them.\n"
        f'  3. Run `{db} migrate -m "create tables"`, then `{db} upgrade`.'
    )


def _shell_join(parts: list[str], *, windows: bool = os.name == "nt") -> str:
    """Quote ``parts`` as one copyable command line: double quotes on Windows, where shells do not group with single quotes."""
    return subprocess.list2cmdline(parts) if windows else shlex.join(parts)


def _display_path(path: Path) -> Path:
    try:
        return path.resolve().relative_to(Path.cwd().resolve())
    except ValueError:
        return path


def _database_url_error(exc: Exception, config: Any, ini: Path) -> str | None:
    """
    Return a one-line message when ``exc`` comes from a missing or unusable configured ``sqlalchemy.url``, else None.

    Only errors that SQLAlchemy or Alembic raised while reading the URL qualify, and an invalid URL must fail the same
    way when re-checked, so an env.py that builds its own engine (from ``DATABASE_URL``, say) keeps its traceback.
    """
    try:
        from sqlalchemy.engine import make_url
        from sqlalchemy.exc import NoSuchModuleError
    except ImportError:
        return None
    try:
        url = config.get_main_option("sqlalchemy.url")
    except Exception:
        # An ini without an [alembic] section, or an uninterpolatable value, must not replace the original error.
        url = None
    source = _display_path(ini)
    # Online, engine_from_config pops a missing "url" key; offline (--sql), Alembic's context.configure gets url=None.
    missing_online = isinstance(exc, KeyError) and exc.args == ("url",) and _raised_in(exc, "sqlalchemy.")
    missing_offline = (
        type(exc) is Exception and str(exc) == "Connection, url, or dialect_name is required." and _raised_in(exc, "alembic.runtime.")
    )
    if (missing_online or missing_offline) and not url:
        return f"Alembic: no database URL is configured. Set sqlalchemy.url in {source}, or have env.py supply one."
    # multidb keeps one sqlalchemy.url per engine section, so look for the placeholder in every section, and only blame
    # the ini when it really holds one: env.py may have read the same placeholder from somewhere else.
    if (
        isinstance(exc, NoSuchModuleError)
        and str(exc).endswith("sqlalchemy.dialects:driver")
        and _ALEMBIC_PLACEHOLDER_URL in _ini_database_urls(config)
    ):
        return (
            f"Alembic: sqlalchemy.url in {source} is still Alembic's placeholder, {_ALEMBIC_PLACEHOLDER_URL}. Set it to your database URL."
        )
    if not url or not _raised_in(exc, "sqlalchemy."):
        return None
    try:
        make_url(url).get_dialect()
    except Exception as url_error:
        # Blame the setting only when it reproduces the failure exactly; otherwise the URL came from somewhere else.
        if type(url_error) is not type(exc) or str(url_error) != str(exc):
            return None
        problem = "names an unknown database dialect" if isinstance(exc, NoSuchModuleError) else "is not a valid database URL"
        return f"Alembic: sqlalchemy.url in {source} {problem}: {exc}"
    return None


def _ini_database_urls(config: Any) -> set[str]:
    """Return the raw sqlalchemy.url of every section of the ini file Alembic read, or an empty set without one."""
    if config.config_file_name is None:
        return set()
    try:
        parser = config.file_config
        return {url for section in parser.sections() if (url := parser.get(section, "sqlalchemy.url", raw=True, fallback=None))}
    except Exception:
        return set()


def _raised_in(exc: BaseException, module_prefix: str) -> bool:
    """Return whether the innermost frame of ``exc``'s traceback belongs to a module under ``module_prefix``."""
    tb = exc.__traceback__
    if tb is None:
        return False
    while tb.tb_next is not None:
        tb = tb.tb_next
    return str(tb.tb_frame.f_globals.get("__name__", "")).startswith(module_prefix)


_DB_ACTIONS: dict[str, Callable[[Any, Any, argparse.Namespace], object]] = {
    "migrate": lambda command, config, args: command.revision(config, message=args.message, autogenerate=True),
    "revision": lambda command, config, args: command.revision(config, message=args.message),
    "upgrade": lambda command, config, args: command.upgrade(config, args.revision, sql=args.sql),
    "downgrade": lambda command, config, args: command.downgrade(config, args.revision, sql=args.sql),
    "current": lambda command, config, args: command.current(config, check_heads=args.check_heads, verbose=args.verbose),
    "history": lambda command, config, args: command.history(
        config, rev_range=args.rev_range, verbose=args.verbose, indicate_current=args.indicate_current
    ),
    "stamp": lambda command, config, args: command.stamp(config, args.revision, sql=args.sql, purge=args.purge),
    "check": lambda command, config, args: command.check(config),
}


def _alembic_command_error() -> type[Exception]:
    from alembic.util import CommandError

    return CommandError


@dataclass(frozen=True, slots=True)
class _AlembicFiles:
    ini: Path
    toml: Path
    # Only a path typed on the command line must exist; defaults and [tool.flasgo.db] paths are used when they hold settings.
    ini_required: bool
    toml_required: bool


def _alembic_files(args: argparse.Namespace) -> _AlembicFiles:
    """
    Resolve the Alembic .ini and pyproject.toml paths.

    Command-line flags win over [tool.flasgo.db], which wins over the alembic.ini and pyproject.toml defaults. In either
    source, a path named pyproject.toml given as ``config`` is treated as the pyproject path, as the alembic command does.
    """
    cli_ini, cli_toml = _split_alembic_paths(args.config, args.pyproject, names=("--config", "--pyproject"))
    configured_ini, configured_toml = _split_alembic_paths(
        args.configured_db_config, args.configured_db_pyproject, names=("tool.flasgo.db.config", "tool.flasgo.db.pyproject")
    )
    return _AlembicFiles(
        ini=Path(cli_ini or configured_ini or _DEFAULT_ALEMBIC_INI).expanduser().resolve(),
        toml=Path(cli_toml or configured_toml or _DEFAULT_PYPROJECT).expanduser().resolve(),
        ini_required=cli_ini is not None,
        toml_required=cli_toml is not None,
    )


def _split_alembic_paths(config: str | None, pyproject: str | None, *, names: tuple[str, str]) -> tuple[str | None, str | None]:
    for value, name in ((config, names[0]), (pyproject, names[1])):
        if value is not None and not value.strip():
            raise SystemExit(f"{name} must not be empty.")
    if config is not None and Path(config).name == _DEFAULT_PYPROJECT:
        if pyproject is not None:
            raise SystemExit(f"Pass pyproject.toml with either {names[0]} or {names[1]}, not both.")
        return None, config
    return config, pyproject


def _alembic_config_kwargs(files: _AlembicFiles) -> dict[str, str | None]:
    """
    Choose which existing configuration files Alembic should read.

    Alembic merges an .ini file with the [tool.alembic] table of pyproject.toml, and either may be used alone.

    Returns:
        dict[str, str | None]: ``file_`` and ``toml_file`` keyword arguments for ``alembic.config.Config``.
    """
    has_ini = _has_alembic_ini(files.ini, required=files.ini_required)
    has_toml = _has_tool_alembic(files.toml, required=files.toml_required)
    if not has_ini and not has_toml:
        raise SystemExit(
            f"Alembic configuration not found: no {files.ini} and no [tool.alembic] table in {files.toml}. "
            "Run `flasgo db init` first, or check config and pyproject in [tool.flasgo.db]."
        )
    return {"file_": str(files.ini) if has_ini else None, "toml_file": str(files.toml) if has_toml else None}


def _has_alembic_ini(path: Path, *, required: bool) -> bool:
    """
    Report whether ``path`` is an ini file with an [alembic] section, failing loudly when it was named explicitly.

    Alembic needs that section in any ini it is given, and the stock env.py also reads its logging sections, so an
    unrelated ini (an app's settings.ini, say) is skipped rather than handed to Alembic.
    """
    if not path.is_file():
        if required:
            raise SystemExit(f"Alembic configuration not found: {path}. Run `flasgo db init` first.")
        return False
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with path.open(encoding="utf-8") as source:
            parser.read_file(source)
    except (OSError, UnicodeDecodeError, configparser.Error) as exc:
        raise SystemExit(f"Could not read {path.resolve()}: {exc}") from None
    has_section = parser.has_section("alembic")
    if not has_section and required:
        raise SystemExit(f"No [alembic] section in {path}. Run `flasgo db init` to create an Alembic configuration.")
    return has_section


def _has_tool_alembic(path: Path, *, required: bool) -> bool:
    """Report whether ``path`` is a pyproject.toml with a [tool.alembic] table, failing loudly when it was named explicitly."""
    if not path.is_file():
        if required:
            raise SystemExit(f"pyproject.toml not found: {path}.")
        return False
    tool = _read_toml(path).get("tool")
    section = tool.get("alembic") if isinstance(tool, dict) else None
    if section is not None and not isinstance(section, dict):
        raise SystemExit(f"[tool.alembic] in {path} must be a table.")
    if section is None and required:
        raise SystemExit(f"No [tool.alembic] table in {path}. Run `flasgo db init --template pyproject` to create one.")
    return section is not None


def _load_alembic() -> tuple[Any, type[Any]]:
    try:
        from alembic import command
        from alembic.config import Config
    except ImportError as exc:
        raise SystemExit("Database migrations require the optional dependency: install `flasgo[db]`.") from exc
    return command, Config


def load_app(target: str, *, app_name: str = "app") -> Flasgo:
    """Load an app while transactionally replacing CLI-owned path modules."""

    app, _ = _load_app_target(target, app_name=app_name)
    return app


def _load_app_target(target: str, *, app_name: str) -> tuple[Flasgo, _ResolvedTarget]:
    resolved = _resolve_target(target)
    try:
        module = _import_target(resolved)
    except ModuleNotFoundError as exc:
        if exc.name is not None and (resolved.module_name == exc.name or resolved.module_name.startswith(f"{exc.name}.")):
            raise SystemExit(
                f"Could not import target module '{resolved.module_name}' from import root "
                f"'{resolved.import_root}'. Check the target name and path."
            ) from None
        raise SystemExit(
            f"Error while importing target module '{resolved.module_name}' from import root "
            f"'{resolved.import_root}':\n\n{traceback.format_exc()}"
        ) from None
    except Exception:
        raise SystemExit(
            f"Error while importing target module '{resolved.module_name}' from import root "
            f"'{resolved.import_root}':\n\n{traceback.format_exc()}"
        ) from None

    names = [resolved.attr_name or app_name]
    if resolved.attr_name is None and app_name == "app":
        names.append("application")
    for name in names:
        candidate = _resolve_app_attr(module, name)
        if isinstance(candidate, Flasgo):
            return candidate, resolved

    checked = " and ".join(repr(name) for name in names)
    raise SystemExit(
        f"Target '{target}' did not resolve to a Flasgo app. Checked {checked}. "
        "Define a `Flasgo()` instance with that name or pass `--app` with the correct variable name."
    )


def _parse_target(target: str) -> tuple[str, str | None]:
    parts = re.split(r":(?![\\/])", target.strip(), maxsplit=1)
    module_token = parts[0].strip()
    if not module_token:
        raise SystemExit("Import target must include a module path before ':'. Example: package.module:app")
    attr_name = parts[1].strip() if len(parts) == 2 else ""
    return module_token, attr_name or None


def _resolve_target(target: str) -> _ResolvedTarget:
    module_token, attr_name = _parse_target(target)
    path = Path(module_token).expanduser()
    if path.is_file():
        if path.suffix != ".py":
            raise SystemExit(f"Expected a .py file path, got: {path.resolve()}. Use package.module:app for imports.")
        return _resolve_path_target(path, attr_name)

    inferred_file = Path(f"{module_token}.py").expanduser()
    if inferred_file.is_file():
        return _resolve_path_target(inferred_file, attr_name)

    if path.is_dir():
        resolved_path = path.resolve()
        module_name, import_root = _prepare_import(resolved_path)
        return _ResolvedTarget(module_name, import_root, resolved_path, resolved_path, attr_name)

    if _looks_like_path(module_token):
        raise SystemExit(
            f"Python target not found: {path.resolve()}. Pass an existing .py file, package directory, "
            "or an import string like package.module:app."
        )

    import_root = Path.cwd().resolve()
    _insert_sys_path(import_root)
    return _ResolvedTarget(module_token, import_root, None, None, attr_name)


def _resolve_path_target(path: Path, attr_name: str | None) -> _ResolvedTarget:
    resolved_path = path.resolve()
    module_name, import_root = _prepare_import(resolved_path)
    return _ResolvedTarget(module_name, import_root, resolved_path, resolved_path.parent, attr_name)


def _prepare_import(path: Path) -> tuple[str, Path]:
    module_path = path.with_suffix("") if path.suffix == ".py" else path
    if module_path.name == "__init__":
        module_path = module_path.parent

    names: list[str] = []
    current = module_path
    while True:
        names.append(current.name)
        parent = current.parent
        if not (parent / "__init__.py").is_file():
            break
        current = parent

    _insert_sys_path(parent)
    return ".".join(reversed(names)), parent


def _insert_sys_path(path: Path) -> None:
    value = str(path)
    if not sys.path or sys.path[0] != value:
        sys.path.insert(0, value)


def _looks_like_path(target: str) -> bool:
    return target.endswith(".py") or Path(target).is_absolute() or "/" in target or "\\" in target


def _import_target(target: _ResolvedTarget) -> ModuleType:
    if target.source is None:
        return importlib.import_module(target.module_name)

    namespace = target.module_name.partition(".")[0]
    previous_root = _CLI_NAMESPACE_ROOTS.get(namespace)
    cached_namespace = sys.modules.get(namespace)
    if (
        cached_namespace is not None
        and not _namespace_matches_target(cached_namespace, target)
        and (previous_root is None or not _module_belongs_to_root(cached_namespace, previous_root))
    ):
        location = _module_location(cached_namespace)
        raise SystemExit(
            f"Cannot load '{target.source}' as '{target.module_name}' because namespace '{namespace}' "
            f"is already imported from '{location or 'an unknown location'}'. Rename the target or package."
        )

    snapshot = _namespace_snapshot(namespace)
    modules_before = dict(sys.modules)
    if cached_namespace is not None and not _namespace_matches_target(cached_namespace, target):
        _clear_namespace(namespace)
    evicted_modules = _evict_cli_owned_modules(previous_root) if previous_root is not None and previous_root != target.import_root else {}

    try:
        module = importlib.import_module(target.module_name)
        if not _module_matches_source(module, target.source):
            location = _module_location(module)
            raise ImportError(f"resolved to '{location or 'an unknown location'}' instead of the requested '{target.source}'")
    except BaseException:
        _restore_namespace(namespace, snapshot)
        sys.modules.update(evicted_modules)
        if previous_root is None:
            _CLI_NAMESPACE_ROOTS.pop(namespace, None)
        else:
            _CLI_NAMESPACE_ROOTS[namespace] = previous_root
        raise

    previously_owned = _CLI_ROOT_MODULES.get(target.import_root, {})
    newly_owned = {
        name: module
        for name, module in sys.modules.items()
        if modules_before.get(name) is not module and _module_belongs_to_root(module, target.import_root)
    }
    _CLI_ROOT_MODULES[target.import_root] = {
        **{name: module for name, module in previously_owned.items() if sys.modules.get(name) is module},
        **newly_owned,
    }
    if previous_root is not None and previous_root != target.import_root:
        _CLI_ROOT_MODULES.pop(previous_root, None)
    _CLI_NAMESPACE_ROOTS[namespace] = target.import_root
    return module


def _namespace_matches_target(module: ModuleType, target: _ResolvedTarget) -> bool:
    if target.source is None:
        raise RuntimeError("A namespace target must be resolved from a source file.")
    if "." not in target.module_name:
        return _module_matches_source(module, target.source)
    expected_directory = target.import_root / target.module_name.partition(".")[0]
    location = _module_location(module)
    if location is not None:
        return expected_directory in {location, location.parent}
    return any(Path(value).resolve() == expected_directory for value in getattr(module, "__path__", ()))


def _module_matches_source(module: ModuleType, source: Path) -> bool:
    location = _module_location(module)
    if source.is_file():
        return location == source
    if (source / "__init__.py").is_file():
        return location == source / "__init__.py"
    return any(Path(value).resolve() == source for value in getattr(module, "__path__", ()))


def _module_belongs_to_root(module: ModuleType, root: Path) -> bool:
    location = _module_location(module)
    if location is not None:
        return location.is_relative_to(root)
    return any(Path(value).resolve().is_relative_to(root) for value in getattr(module, "__path__", ()))


def _evict_cli_owned_modules(root: Path) -> dict[str, ModuleType]:
    evicted: dict[str, ModuleType] = {}
    for name, module in _CLI_ROOT_MODULES.get(root, {}).items():
        if sys.modules.get(name) is module:
            evicted[name] = module
            sys.modules.pop(name, None)
    return evicted


def _module_location(module: ModuleType) -> Path | None:
    value = getattr(module, "__file__", None)
    return Path(value).resolve() if value is not None else None


def _namespace_snapshot(namespace: str) -> dict[str, ModuleType]:
    prefix = f"{namespace}."
    return {name: module for name, module in sys.modules.items() if name == namespace or name.startswith(prefix)}


def _clear_namespace(namespace: str) -> None:
    prefix = f"{namespace}."
    for name in tuple(sys.modules):
        if name == namespace or name.startswith(prefix):
            sys.modules.pop(name, None)


def _restore_namespace(namespace: str, snapshot: dict[str, ModuleType]) -> None:
    _clear_namespace(namespace)
    sys.modules.update(snapshot)


def _resolve_app_attr(module: ModuleType, name: str) -> object:
    candidate: object = module
    for part in name.split("."):
        if not part:
            return _MISSING
        candidate = getattr(candidate, part, _MISSING)
        if candidate is _MISSING:
            return _MISSING
    return candidate


def _reload_dirs(target: _ResolvedTarget, extra_dirs: list[str] | None) -> list[str] | None:
    if target.watch_dir is None and extra_dirs is None:
        return None
    default = target.watch_dir or Path.cwd().resolve()
    return [str(default), *(extra_dirs or [])]


if __name__ == "__main__":
    raise SystemExit(main())
