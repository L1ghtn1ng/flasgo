import asyncio
import os
import shlex
import signal
import subprocess
import sys
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import TYPE_CHECKING, Any

import uvicorn

from ._paths import require_directory
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
    """Run the current command under the file reloader from the event loop thread.

    The child server is always stopped when this returns, including on cancellation (Ctrl+C) and SIGTERM.
    ``watchfiles.arun_process`` skips that cleanup when cancelled, which could orphan a server holding its port.
    """
    try:
        from watchfiles import awatch
    except ImportError as exc:
        raise RuntimeError(_WATCHFILES_MISSING) from exc

    with _reload_environment(reload_dirs) as (watch_paths, command), _cancel_on_sigterm():
        process = await _start_reload_child_async(command)
        try:
            async for changes in awatch(*watch_paths, ignore_permission_denied=True):
                log_reload_changes(changes)
                await _stop_reload_child_async(process)
                process = await _start_reload_child_async(command)
        finally:
            await _stop_reload_child_async(process)


async def _start_reload_child_async(command: str) -> subprocess.Popen[bytes]:
    """Start a child in a worker thread without ever losing it to cancellation.

    Cancelling ``await asyncio.to_thread(...)`` does not stop the thread, which would still spawn a child that no
    caller holds. On cancellation the child is stopped, by this task if it already exists or by the worker as soon
    as it has spawned, and this waits for that before re-raising so the port is free when the reloader returns.
    """
    handoff = _ChildHandoff()
    start = asyncio.ensure_future(asyncio.to_thread(handoff.start, command))
    try:
        return await asyncio.shield(start)
    except asyncio.CancelledError:
        process = handoff.abandon()
        # Still spawning: the worker thread stops the child itself, so waiting for `start` covers the cleanup.
        cleanup = start if process is None else asyncio.ensure_future(asyncio.to_thread(_stop_reload_child, process))
        await _finish_despite_cancellation(cleanup)
        raise


async def _stop_reload_child_async(process: subprocess.Popen[bytes]) -> None:
    """Stop a child off the event loop, finishing even if the caller is cancelled again meanwhile."""
    await _finish_despite_cancellation(asyncio.ensure_future(asyncio.to_thread(_stop_reload_child, process)))


async def _finish_despite_cancellation(cleanup: asyncio.Future[Any]) -> None:
    """Wait for child cleanup without blocking the loop; repeated cancellations (a second SIGTERM) cannot cut it short.

    A caller being cancelled is re-raised by the caller itself once the cleanup is done.
    """
    cancelled = False
    while not cleanup.done():
        try:
            # asyncio.wait() neither cancels `cleanup` when we are cancelled nor raises its error here.
            await asyncio.wait({cleanup})
        except asyncio.CancelledError:
            cancelled = True
    if (error := cleanup.exception()) is not None:
        # Never let a failed stop hide behind the cancellation: the child may still be running and hold its port.
        raise RuntimeError("Could not stop the development server child process; it may still hold its port.") from error
    if cancelled:
        raise asyncio.CancelledError


class _ChildHandoff:
    """Hands a child spawned in a worker thread to the event loop, or stops it if the loop stopped waiting."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._abandoned = False
        self._process: subprocess.Popen[bytes] | None = None

    def start(self, command: str) -> subprocess.Popen[bytes]:
        process = _start_reload_child(command)
        with self._lock:
            self._process = process
            abandoned = self._abandoned
        if abandoned:
            _stop_reload_child(process)
        return process

    def abandon(self) -> subprocess.Popen[bytes] | None:
        """Mark the child abandoned. Returns it if already spawned (the caller stops it); otherwise the worker will."""
        with self._lock:
            self._abandoned = True
            return self._process


def _start_reload_child(command: str) -> subprocess.Popen[bytes]:
    # The command is this process's own argv (see build_reload_command), not external input.
    return subprocess.Popen(shlex.split(command))  # noqa: S603


def _stop_reload_child(process: subprocess.Popen[bytes], *, grace_seconds: float = 5) -> None:
    """Ask the child to shut down like Ctrl+C would, then kill it if it does not exit in time."""
    if process.poll() is not None:
        return
    try:
        process.send_signal(signal.SIGINT)
    except ProcessLookupError:
        return  # exited between poll() and the signal
    except OSError:
        # SIGINT could not be delivered; fall back to SIGKILL rather than leaving the child running.
        process.kill()
        process.wait()
        return
    try:
        process.wait(grace_seconds)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


@contextmanager
def _cancel_on_sigterm() -> Iterator[None]:
    """Turn SIGTERM (docker stop, IDE stop buttons) into cancellation so reload cleanup runs."""
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    installed = False
    if task is not None:
        # Not available on Windows event loops or outside the main thread; the default SIGTERM handling applies.
        with suppress(NotImplementedError, RuntimeError, ValueError):
            loop.add_signal_handler(signal.SIGTERM, task.cancel)
            installed = True
    try:
        yield
    finally:
        if installed:
            loop.remove_signal_handler(signal.SIGTERM)


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
    return require_directory(path, "Reload")


def build_reload_command() -> str:
    argv = list(sys.orig_argv)
    if not argv:
        argv = [sys.executable, *sys.argv]
    if len(argv) < 2 and not Path(argv[0]).exists():
        raise RuntimeError("Reload support requires starting Flasgo from a Python script or module import, not an interactive shell.")
    return shlex.join(argv)


def log_reload_changes(changes: ReloadChanges) -> None:
    changed_paths = ", ".join(sorted(path for _, path in changes))
    if changed_paths:
        print(f"Flasgo reload triggered by changes in: {changed_paths}")
