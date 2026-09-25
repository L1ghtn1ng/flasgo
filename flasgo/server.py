from __future__ import annotations

import os
import shlex
import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

import uvicorn

from .types import ASGIApp

if TYPE_CHECKING:
    from watchfiles import Change

type ReloadChanges = set[tuple[Change, str]]
_RELOAD_ENV = "FLASGO_RUN_MAIN"
_WATCHFILES_MISSING = "Reload support requires the 'watchfiles' package. Install project dependencies and retry."


async def run_dev_server(
    app: ASGIApp,
    host: str,
    port: int,
    *,
    reload: bool = False,
    reload_dirs: Sequence[str | Path] | None = None,
    websocket_max_message_bytes: int = 65_536,
    limit_concurrency: int = 1_000,
    max_request_head_bytes: int = 16_384,
) -> None:
    """Run Flasgo on Uvicorn while retaining the existing file reloader."""

    if reload and os.environ.get(_RELOAD_ENV) != "true":
        # watchfiles registers a SIGTERM handler, which Python only allows on the main thread, so the reloader
        # must run on the event loop rather than in a worker thread.
        await arun_with_reload(reload_dirs=reload_dirs)
        return

    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        access_log=False,
        lifespan="on",
        proxy_headers=False,
        http="h11",
        h11_max_incomplete_event_size=max_request_head_bytes,
        # The legacy "websockets" implementation is deprecated; sansio still supports the websocket.http.response
        # extension that WebSocket.deny() relies on.
        ws="websockets-sansio",
        ws_max_size=websocket_max_message_bytes,
        ws_ping_interval=20.0,
        ws_ping_timeout=20.0,
        ws_per_message_deflate=False,
        limit_concurrency=limit_concurrency,
        server_header=False,
    )
    await uvicorn.Server(config).serve()


def run_with_reload(
    *,
    reload_dirs: Sequence[str | Path] | None = None,
) -> None:
    """Run the current command under the file reloader, blocking until it exits.

    ``watchfiles`` installs a SIGTERM handler, so this must be called from the main thread. Inside a running
    event loop use :func:`arun_with_reload` instead.
    """
    try:
        from watchfiles import run_process
    except ImportError as exc:
        raise RuntimeError(_WATCHFILES_MISSING) from exc

    with _reload_environment(reload_dirs) as (watch_paths, command):
        run_process(
            *watch_paths,
            target=command,
            target_type="command",
            callback=log_reload_changes,
            ignore_permission_denied=True,
        )


async def arun_with_reload(
    *,
    reload_dirs: Sequence[str | Path] | None = None,
) -> None:
    """Run the current command under the file reloader from the event loop thread."""
    try:
        from watchfiles import arun_process
    except ImportError as exc:
        raise RuntimeError(_WATCHFILES_MISSING) from exc

    with _reload_environment(reload_dirs) as (watch_paths, command):
        await arun_process(
            *watch_paths,
            target=command,
            target_type="command",
            callback=log_reload_changes,
            ignore_permission_denied=True,
        )


@contextmanager
def _reload_environment(reload_dirs: Sequence[str | Path] | None) -> Iterator[tuple[tuple[str, ...], str]]:
    watch_paths = tuple(str(resolve_reload_dir(path)) for path in (reload_dirs or (Path.cwd(),)))
    command = build_reload_command()
    previous = os.environ.get(_RELOAD_ENV)
    os.environ[_RELOAD_ENV] = "true"
    try:
        print(f"Flasgo reloader watching {', '.join(watch_paths)}")
        yield watch_paths, command
    finally:
        if previous is None:
            os.environ.pop(_RELOAD_ENV, None)
        else:
            os.environ[_RELOAD_ENV] = previous


def resolve_reload_dir(path: str | Path) -> Path:
    resolved = Path(path).expanduser().resolve()
    if not resolved.exists():
        msg = f"Reload directory does not exist: {resolved}"
        raise ValueError(msg)
    if not resolved.is_dir():
        msg = f"Reload directory is not a directory: {resolved}"
        raise ValueError(msg)
    return resolved


def build_reload_command() -> str:
    argv = list(getattr(sys, "orig_argv", []))
    if not argv:
        argv = [sys.executable, *sys.argv]
    if len(argv) < 2 and not Path(argv[0]).exists():
        raise RuntimeError("Reload support requires starting Flasgo from a Python script or module import, not an interactive shell.")
    return shlex.join(argv)


def log_reload_changes(changes: ReloadChanges) -> None:
    changed_paths = ", ".join(sorted(path for _, path in changes))
    if changed_paths:
        print(f"Flasgo reload triggered by changes in: {changed_paths}")
