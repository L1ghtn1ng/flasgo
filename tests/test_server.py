import asyncio
import os
import subprocess
import sys
import threading
import types
from collections.abc import AsyncIterator, Coroutine
from pathlib import Path
from typing import Any

import pytest

from flasgo import Flasgo
from flasgo import server as server_module


def test_build_reload_command_uses_current_process_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server_module.sys, "orig_argv", ["/usr/bin/python3", "-m", "example.app"], raising=False)
    command = server_module.build_reload_command()
    assert command == "/usr/bin/python3 -m example.app"


def test_run_with_reload_spawns_current_command(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: dict[str, object] = {}

    def fake_run_process(
        *paths: str,
        target: str,
        target_type: str,
        callback: object,
        ignore_permission_denied: bool,
    ) -> int:
        calls["paths"] = paths
        calls["target"] = target
        calls["target_type"] = target_type
        calls["env"] = os.environ.get(server_module._RELOAD_ENV)
        calls["ignore_permission_denied"] = ignore_permission_denied
        return 0

    monkeypatch.setitem(server_module.sys.modules, "watchfiles", types.SimpleNamespace(run_process=fake_run_process))
    monkeypatch.setattr(server_module.sys, "orig_argv", ["/usr/bin/python3", "app.py"], raising=False)

    server_module.run_with_reload(reload_dirs=[tmp_path])

    assert calls["paths"] == (str(tmp_path.resolve()),)
    assert calls["target"] == "/usr/bin/python3 app.py"
    assert calls["target_type"] == "command"
    assert calls["env"] == "true"
    assert calls["ignore_permission_denied"] is True


def test_dev_server_reload_watches_on_the_loop_and_restarts_the_child(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The reloader runs on the event loop thread and restarts (then finally stops) the server child."""
    events: list[tuple[str, object]] = []

    async def fake_awatch(*paths: str, ignore_permission_denied: bool) -> AsyncIterator[set[tuple[int, str]]]:
        events.append(("watch", (paths, threading.current_thread() is threading.main_thread(), ignore_permission_denied)))
        yield {(1, str(tmp_path / "app.py"))}

    def fake_start(command: str) -> str:
        events.append(("start", (command, os.environ.get(server_module._RELOAD_ENV))))
        return f"child-{sum(kind == 'start' for kind, _ in events)}"

    def fake_stop(process: object, **_: object) -> None:
        events.append(("stop", process))

    monkeypatch.setitem(server_module.sys.modules, "watchfiles", types.SimpleNamespace(awatch=fake_awatch))
    monkeypatch.setattr(server_module, "_start_reload_child", fake_start)
    monkeypatch.setattr(server_module, "_stop_reload_child", fake_stop)
    monkeypatch.setattr(server_module.sys, "orig_argv", ["/usr/bin/python3", "app.py"], raising=False)
    monkeypatch.delenv(server_module._RELOAD_ENV, raising=False)

    asyncio.run(server_module.run_dev_server(Flasgo(), "127.0.0.1", 0, reload=True, reload_dirs=[tmp_path]))

    assert events == [
        ("start", ("/usr/bin/python3 app.py", "true")),
        ("watch", ((str(tmp_path.resolve()),), True, True)),
        ("stop", "child-1"),
        ("start", ("/usr/bin/python3 app.py", "true")),
        ("stop", "child-2"),
    ]
    assert server_module._RELOAD_ENV not in os.environ


def test_cancelling_the_reloader_stops_the_server_child(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """watchfiles.arun_process skipped child cleanup on cancellation, leaving a server holding its port."""
    started: list[subprocess.Popen[bytes]] = []
    child_running = threading.Event()
    real_start = server_module._start_reload_child

    def start(command: str) -> subprocess.Popen[bytes]:
        process = real_start(command)
        started.append(process)
        child_running.set()
        return process

    async def idle_awatch(*paths: str, ignore_permission_denied: bool) -> AsyncIterator[set[tuple[int, str]]]:
        await asyncio.Event().wait()
        yield set()

    monkeypatch.setitem(server_module.sys.modules, "watchfiles", types.SimpleNamespace(awatch=idle_awatch))
    monkeypatch.setattr(server_module, "_start_reload_child", start)
    monkeypatch.setattr(server_module.sys, "orig_argv", [sys.executable, "-c", "import time; time.sleep(60)"], raising=False)
    monkeypatch.delenv(server_module._RELOAD_ENV, raising=False)

    async def run() -> None:
        task = asyncio.create_task(server_module.arun_with_reload(reload_dirs=[tmp_path]))
        assert await asyncio.to_thread(child_running.wait, 10)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    assert started[0].poll() is not None


@pytest.mark.parametrize("cancellations", [1, 2])
def test_cancelling_the_reloader_while_a_child_is_starting_stops_that_child(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, cancellations: int
) -> None:
    """Cancellation during the worker-thread spawn, even repeated (two SIGTERMs), must not orphan the child."""
    started: list[subprocess.Popen[bytes]] = []
    spawning = threading.Event()
    release = threading.Event()
    real_start = server_module._start_reload_child

    def slow_start(command: str) -> subprocess.Popen[bytes]:
        spawning.set()
        release.wait(10)
        process = real_start(command)
        started.append(process)
        return process

    async def idle_awatch(*paths: str, ignore_permission_denied: bool) -> AsyncIterator[set[tuple[int, str]]]:
        await asyncio.Event().wait()
        yield set()

    monkeypatch.setitem(server_module.sys.modules, "watchfiles", types.SimpleNamespace(awatch=idle_awatch))
    monkeypatch.setattr(server_module, "_start_reload_child", slow_start)
    monkeypatch.setattr(server_module.sys, "orig_argv", [sys.executable, "-c", "import time; time.sleep(60)"], raising=False)
    monkeypatch.delenv(server_module._RELOAD_ENV, raising=False)

    async def run() -> None:
        task = asyncio.create_task(server_module.arun_with_reload(reload_dirs=[tmp_path]))
        assert await asyncio.to_thread(spawning.wait, 10)
        for _ in range(cancellations):
            task.cancel()
            await asyncio.sleep(0)
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())  # also waits for the worker thread, which stops a child it spawned after cancellation
    assert len(started) == 1
    assert started[0].poll() is not None


def test_app_run_uses_debug_reload_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    app = Flasgo(settings={"DEBUG": True})
    seen: dict[str, Any] = {}

    async def fake_run_dev_server(*args: object, **kwargs: object) -> None:
        seen["args"] = args
        seen["kwargs"] = kwargs

    def fake_asyncio_run(coro: Coroutine[Any, Any, None]) -> None:
        try:
            coro.send(None)
        except StopIteration:
            return

    monkeypatch.setattr("flasgo.app.run_dev_server", fake_run_dev_server)
    monkeypatch.setattr("flasgo.app.asyncio.run", fake_asyncio_run)

    app.run()

    assert seen["kwargs"]["reload"] is True


def test_dev_server_uses_hardened_uvicorn_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})
    seen: dict[str, object] = {}

    class FakeConfig:
        def __init__(self, configured_app: object, **kwargs: object) -> None:
            seen["app"] = configured_app
            seen.update(kwargs)

    class FakeServer:
        def __init__(self, config: object) -> None:
            seen["config"] = config

        async def serve(self) -> None:
            seen["served"] = True

    monkeypatch.setattr(server_module.uvicorn, "Config", FakeConfig)
    monkeypatch.setattr(server_module.uvicorn, "Server", FakeServer)

    asyncio.run(
        server_module.run_dev_server(
            app,
            "127.0.0.1",
            8000,
            websocket_max_message_bytes=4096,
            limit_concurrency=100,
            max_request_head_bytes=8192,
        )
    )

    assert seen["lifespan"] == "on"
    assert seen["proxy_headers"] is False
    assert seen["http"] == "h11"
    assert seen["h11_max_incomplete_event_size"] == 8192
    assert seen["ws_max_size"] == 4096
    assert seen["ws_per_message_deflate"] is False
    assert seen["limit_concurrency"] == 100
    assert seen["ws"] == "websockets-sansio"
    assert seen["server_header"] is False


def test_dev_server_websocket_implementation_loads_without_deprecation_warnings() -> None:
    import warnings

    import uvicorn

    config = uvicorn.Config(Flasgo(), ws="websockets-sansio", lifespan="off", server_header=False)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        config.load()
    assert config.ws_protocol_class is not None


def test_abandoning_a_started_child_does_not_block_the_event_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    """A child that ignores SIGINT must not freeze the event loop for the stop grace period on cancellation."""
    stopping = threading.Event()
    release = threading.Event()
    stopped: list[object] = []

    def slow_stop(process: object) -> None:
        stopping.set()
        release.wait(10)
        stopped.append(process)

    monkeypatch.setattr(server_module, "_start_reload_child", lambda command: "child")
    monkeypatch.setattr(server_module, "_stop_reload_child", slow_stop)
    handoff = server_module._ChildHandoff()
    assert handoff.start("cmd") == "child"

    handoff.abandon()  # returns immediately even though stopping is still in progress
    assert stopping.wait(10)
    assert stopped == []
    release.set()
    for thread in threading.enumerate():
        if thread.name == "flasgo-reload-stop":
            thread.join(10)
    assert stopped == ["child"]
