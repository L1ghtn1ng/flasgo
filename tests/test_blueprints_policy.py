import json
from pathlib import Path

import pytest
from flasgo import Flasgo, HasScope, IsAuthenticated, cli
from flasgo.policy import compare_policy, deployment_issues


def test_policy_omits_secrets_and_detects_permission_change() -> None:
    app = Flasgo(settings={"SECRET_KEY": "do-not-export-this-secret-value-123456789"})

    @app.get("/private")
    @app.authorize(IsAuthenticated(), HasScope("read"))
    def private() -> str:
        return "ok"

    before = app.policy_snapshot()
    assert app.security.secret_key not in json.dumps(before)
    app.authorize(IsAuthenticated())(private)
    assert compare_policy(before, app.policy_snapshot())[0]["section"] == "routes"
    with pytest.raises(ValueError):
        compare_policy({"schema_version": 2}, app.policy_snapshot())


def test_deployment_check_distinguishes_declared_public_routes() -> None:
    app = Flasgo()
    app.get("/public", public=True)(lambda: "ok")
    assert deployment_issues(app) == []
    app.get("/implicit")(lambda: "ok")
    assert [issue.code for issue in deployment_issues(app)] == ["FG011"]


def test_cli_policy_snapshot_and_comparison(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    app = Flasgo()
    app.get("/", public=True)(lambda: "ok")
    monkeypatch.setattr(cli, "load_app", lambda *args, **kwargs: app)
    assert cli.main(["routes", "unused", "--json"]) == 0
    snapshot = capsys.readouterr().out
    file = tmp_path / "policy.json"
    file.write_text(snapshot)
    assert cli.main(["check", "unused", "--deploy", "--against", str(file), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["passed"]
    app.security.csrf_enabled = False
    assert cli.main(["check", "unused", "--against", str(file), "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["changes"]
