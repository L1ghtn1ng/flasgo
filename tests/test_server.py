from __future__ import annotations

import os
import types
from collections.abc import Coroutine
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
