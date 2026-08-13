from __future__ import annotations

import argparse
import importlib
import json
import os
import re
import sys
import tempfile
import traceback
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

from .app import Flasgo


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
    app, resolved = _load_app_target(args.target, app_name=args.app)
    reload_dirs = _reload_dirs(resolved, args.reload_dirs)
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
    expanded = path.expanduser()
    absolute = expanded if expanded.is_absolute() else Path.cwd() / expanded
    parent = absolute.parent.resolve()
    parent.mkdir(parents=True, exist_ok=True)
    destination = parent / absolute.name
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=parent,
            prefix=f".{destination.name}.",
            delete=False,
        ) as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
            temporary = Path(handle.name)
        os.replace(temporary, destination)
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
    """Load an app while transactionally replacing CLI-owned path modules."""

    app, _ = _load_app_target(target, app_name=app_name)
    return app


def _load_app_target(target: str, *, app_name: str) -> tuple[Flasgo, _ResolvedTarget]:
    resolved = _resolve_target(target)
    try:
        module = _import_target(resolved)
    except ModuleNotFoundError as exc:
        if exc.name is not None and (
            resolved.module_name == exc.name or resolved.module_name.startswith(f"{exc.name}.")
        ):
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
    if cached_namespace is not None and not _namespace_matches_target(cached_namespace, target):
        if previous_root is None or not _module_belongs_to_root(cached_namespace, previous_root):
            location = _module_location(cached_namespace)
            raise SystemExit(
                f"Cannot load '{target.source}' as '{target.module_name}' because namespace '{namespace}' "
                f"is already imported from '{location or 'an unknown location'}'. Rename the target or package."
            )

    snapshot = _namespace_snapshot(namespace)
    modules_before = dict(sys.modules)
    if cached_namespace is not None and not _namespace_matches_target(cached_namespace, target):
        _clear_namespace(namespace)
    evicted_modules = (
        _evict_cli_owned_modules(previous_root)
        if previous_root is not None and previous_root != target.import_root
        else {}
    )

    try:
        module = importlib.import_module(target.module_name)
        if not _module_matches_source(module, target.source):
            location = _module_location(module)
            raise ImportError(
                f"resolved to '{location or 'an unknown location'}' instead of the requested '{target.source}'"
            )
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
    assert target.source is not None
    if "." not in target.module_name:
        return _module_matches_source(module, target.source)
    expected_directory = target.import_root / target.module_name.partition(".")[0]
    location = _module_location(module)
    if location is not None:
        return location == expected_directory or location.parent == expected_directory
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
