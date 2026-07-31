from __future__ import annotations

import argparse
import importlib
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any

from .app import Flasgo


def build_parser() -> argparse.ArgumentParser:
    """Create the Flasgo CLI argument parser."""

    parser = argparse.ArgumentParser(prog="flasgo")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run a Flasgo application")
    _add_target_arguments(run_parser)
    run_parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind")
    run_parser.add_argument("--port", type=int, default=8000, help="Port to bind")
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
        default=None,
        help="Additional directory to watch for reload. Can be specified multiple times.",
    )
    run_parser.set_defaults(handler=_run_command)

    routes_parser = subparsers.add_parser("routes", help="List registered HTTP and WebSocket routes")
    _add_target_arguments(routes_parser)
    routes_parser.set_defaults(handler=_routes_command)

    openapi_parser = subparsers.add_parser("openapi", help="Render the application's OpenAPI document")
    _add_target_arguments(openapi_parser)
    openapi_parser.add_argument("-o", "--output", help="Write atomically to this file instead of stdout")
    openapi_parser.set_defaults(handler=_openapi_command)

    check_parser = subparsers.add_parser("check", help="Validate routes and application configuration")
    _add_target_arguments(check_parser)
    check_parser.set_defaults(handler=_check_command)

    db_parser = subparsers.add_parser("db", help="Manage optional Alembic database migrations")
    db_parser.add_argument("--config", default="alembic.ini", help="Alembic configuration file")
    db_subparsers = db_parser.add_subparsers(dest="db_command", required=True)

    db_init = db_subparsers.add_parser("init", help="Create an Alembic migration environment")
    db_init.add_argument("--directory", default="migrations", help="Migration script directory")
    db_init.set_defaults(handler=_db_command)

    db_migrate = db_subparsers.add_parser("migrate", help="Autogenerate a migration revision")
    db_migrate.add_argument("-m", "--message", required=True, help="Migration description")
    db_migrate.set_defaults(handler=_db_command)

    for command_name, default_revision in (("upgrade", "head"), ("downgrade", "-1")):
        db_revision = db_subparsers.add_parser(command_name, help=f"{command_name.title()} the database")
        db_revision.add_argument("revision", nargs="?", default=default_revision, help="Alembic revision target")
        db_revision.add_argument("--sql", action="store_true", help="Print SQL without changing the database")
        db_revision.set_defaults(handler=_db_command)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the Flasgo CLI entrypoint."""

    parser = build_parser()
    args = parser.parse_args(argv)
    handler = args.handler
    return int(handler(args))


def _run_command(args: argparse.Namespace) -> int:
    app = load_app(args.target, app_name=args.app)
    reload_dirs = args.reload_dirs
    if Path(args.target).suffix == ".py" and reload_dirs is None:
        reload_dirs = [str(Path(args.target).expanduser().resolve().parent)]
    app.run(
        host=args.host,
        port=args.port,
        reload=args.reload,
        reload_dirs=reload_dirs,
    )
    return 0


def _add_target_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("target", help="Python file path or import string such as app.py or package.module:app")
    parser.add_argument("--app", default="app", help="Application variable name when loading from a Python file")


def _routes_command(args: argparse.Namespace) -> int:
    app = load_app(args.target, app_name=args.app)
    print("PROTOCOL  METHODS      PATH                      NAME")
    for route in app._routes:
        methods = ",".join(sorted(route.methods))
        print(f"http      {methods:<12} {route.raw_path:<25} {route.name or '-'}")
    for route in app._websocket_routes:
        print(f"websocket {'-':<12} {route.raw_path:<25} {route.name or '-'}")
    return 0


def _openapi_command(args: argparse.Namespace) -> int:
    app = load_app(args.target, app_name=args.app)
    document = json.dumps(app.openapi_spec(), indent=2, sort_keys=True) + "\n"
    if args.output is None:
        print(document, end="")
    else:
        _atomic_write(Path(args.output), document)
    return 0


def _check_command(args: argparse.Namespace) -> int:
    app = load_app(args.target, app_name=args.app)
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

    for auth in app._route_auth.values():
        if auth.backend not in app._auth_backends:
            errors.append(f"missing authentication backend: {auth.backend}")

    internal_paths: set[str] = set()
    if app.settings.ENABLE_DOCS:
        internal_paths.update((app.settings.DOCS_PATH, app.settings.OPENAPI_PATH))
    if app.settings.METRICS_ENABLED:
        internal_paths.add(app.settings.METRICS_PATH)
    for route in app._routes:
        if route.raw_path in internal_paths:
            errors.append(f"route conflicts with enabled internal endpoint: {route.raw_path}")

    if errors:
        for error in sorted(set(errors)):
            print(f"error: {error}", file=sys.stderr)
        return 1
    print("Flasgo check passed.")
    return 0


def _atomic_write(path: Path, value: str) -> None:
    resolved = path.expanduser().resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=resolved.parent,
            prefix=f".{resolved.name}.",
            delete=False,
        ) as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
            temporary = Path(handle.name)
        os.replace(temporary, resolved)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _db_command(args: argparse.Namespace) -> int:
    command, config_type = _load_alembic()
    config_path = Path(args.config).expanduser().resolve()
    if args.db_command != "init" and not config_path.is_file():
        raise SystemExit(f"Alembic configuration not found: {config_path}. Run `flasgo db init` first.")
    config = config_type(str(config_path))
    if args.db_command == "init":
        command.init(config, str(Path(args.directory).expanduser().resolve()), package=True)
    elif args.db_command == "migrate":
        command.revision(config, message=args.message, autogenerate=True)
    elif args.db_command == "upgrade":
        command.upgrade(config, args.revision, sql=args.sql)
    else:
        command.downgrade(config, args.revision, sql=args.sql)
    return 0


def _load_alembic() -> tuple[Any, type[Any]]:
    try:
        from alembic import command
        from alembic.config import Config
    except ImportError as exc:
        raise SystemExit("Database migrations require the optional dependency: install `flasgo[db]`.") from exc
    return command, Config


def load_app(target: str, *, app_name: str = "app") -> Flasgo:
    """Load a :class:`Flasgo` app from a file path or import string."""

    if ":" in target:
        module_path, attr_name = target.split(":", 1)
        if not module_path.strip():
            raise SystemExit("Import target must include a module path before ':'. Example: package.module:app")
        try:
            module = importlib.import_module(module_path)
        except Exception as exc:
            raise SystemExit(
                f"Could not import module '{module_path}'. Check that it is on PYTHONPATH and imports cleanly. "
                f"Original error: {exc}"
            ) from exc
        resolved_name = attr_name.strip() or app_name
    elif target.endswith(".py"):
        module = _load_module_from_path(Path(target))
        resolved_name = app_name
    else:
        try:
            module = importlib.import_module(target)
        except Exception as exc:
            raise SystemExit(
                f"Could not import module '{target}'. Check that it is on PYTHONPATH and imports cleanly. "
                f"Original error: {exc}"
            ) from exc
        resolved_name = app_name

    candidate = getattr(module, resolved_name, None)
    if not isinstance(candidate, Flasgo):
        msg = (
            f"Target '{target}' did not resolve to a Flasgo app named '{resolved_name}'. "
            f"Define `Flasgo()` as `{resolved_name}` or pass `--app` with the correct variable name."
        )
        raise SystemExit(msg)
    return candidate


def _load_module_from_path(path: Path) -> ModuleType:
    resolved = path.expanduser().resolve()
    if not resolved.exists():
        raise SystemExit(
            f"Python file not found: {resolved}. Pass an existing file or an import string like package.module:app."
        )
    if resolved.suffix != ".py":
        raise SystemExit(f"Expected a .py file path, got: {resolved}. Use package.module:app for module imports.")
    module_name = f"_flasgo_cli_{resolved.stem}_{abs(hash(resolved))}"
    spec = importlib.util.spec_from_file_location(module_name, resolved)
    if spec is None or spec.loader is None:
        raise SystemExit(f"Could not load module from: {resolved}. Check that the file is readable and valid Python.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise SystemExit(
            f"Could not import Flasgo app from {resolved}. Fix the import error in that file and retry. "
            f"Original error: {exc}"
        ) from exc
    return module


if __name__ == "__main__":
    raise SystemExit(main())
