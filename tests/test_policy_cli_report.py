import json
from pathlib import Path

import pytest
from flasgo import Flasgo, cli


def test_text_policy_report_identifies_each_changed_route_and_global_section(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    app = Flasgo()
    baseline = tmp_path / "policy.json"
    baseline.write_text(json.dumps(app.policy_snapshot()))
    app.get("/items", public=True)(lambda: "ok")
    app.post("/items", public=True)(lambda: "ok")
    app.websocket("/events")(lambda socket: None)
    app.security.csrf_enabled = False
    monkeypatch.setattr(cli, "load_app", lambda *args, **kwargs: app)

    assert cli.main(["check", "unused", "--against", str(baseline)]) == 1
    lines = capsys.readouterr().err.splitlines()
    assert "policy changed: controls" in lines
    identifiers = [
        json.loads(line.removeprefix("policy changed: routes "))
        for line in lines
        if line.startswith("policy changed: routes ")
    ]
    assert len(identifiers) == 3
    assert ["http", "/items", ["GET", "HEAD"]] in identifiers
    assert ["http", "/items", ["POST"]] in identifiers
    assert any(protocol == "websocket" and path == "/events" for protocol, path, _ in identifiers)
