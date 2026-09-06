import json
from pathlib import Path

import pytest
from flasgo import Blueprint, Depends, Flasgo, HasScope, IsAuthenticated, RateLimitRule, User, cli
from flasgo.policy import compare_policy, deployment_issues


def test_nested_blueprints_preserve_auth_dependencies_and_url_generation() -> None:
    calls = []

    def audit() -> None:
        calls.append("audit")

    app = Flasgo(settings={"CSRF_ENABLED": False})
    app.register_auth_backend("users", lambda req: User(id="u", is_authenticated=True, scopes=frozenset({"read"})))
    api = Blueprint("api", url_prefix="/api", permissions=[IsAuthenticated()], backend="users")
    reports = Blueprint(
        "reports",
        url_prefix="/reports",
        permissions=[HasScope("read")],
        backend="users",
        dependencies=[Depends(audit)],
        rate_limits=[RateLimitRule(2, 60)],
    )

    @reports.get("/<int:report_id>", name="detail")
    def report(report_id: int) -> dict:
        return {"id": report_id}

    api.register_blueprint(reports)
    app.register_blueprint(api)
    assert app.url_for("api.reports.detail", report_id=3, q="a&b") == "/api/reports/3?q=a%26b"
    client = app.test_client()
    assert client.get("/api/reports/3").json() == {"id": 3}
    assert calls == ["audit"]
    app.register_auth_backend("users", lambda req: User(id="u", is_authenticated=True))
    assert client.get("/api/reports/3").status_code == 403
    assert calls == ["audit"]
    policy = app.policy_snapshot()["routes"][0]
    assert policy["permissions"] == [{"kind": "authenticated"}, {"kind": "scope", "scope": "read"}]


def test_blueprint_registration_is_atomic_and_does_not_modify_original_endpoint() -> None:
    app = Flasgo()
    group = Blueprint("private", permissions=[IsAuthenticated()])

    @group.get("/first")
    def first() -> str:
        return "first"

    @group.get("/second", public=True)
    def second() -> str:
        return "second"

    with pytest.raises(ValueError, match="public"):
        app.register_blueprint(group)
    assert app._routes == []
    assert app._route_auth == {}
    assert not hasattr(first, "__flasgo_rate_limits__")


def test_blueprint_cycles_and_duplicates_fail_without_partial_registration() -> None:
    group = Blueprint("api")
    child = Blueprint("child")
    group.register_blueprint(child)
    with pytest.raises(ValueError, match="cycles"):
        child.register_blueprint(group)
    group.get("/", public=True)(lambda: "ok")
    app = Flasgo()
    app.register_blueprint(group)
    before = app.policy_snapshot()
    with pytest.raises(ValueError, match="duplicate"):
        app.register_blueprint(group)
    assert app.policy_snapshot() == before


@pytest.mark.parametrize("value", ["../secret", "//evil.test", "a\\b", ".", "a/../b"])
def test_url_for_rejects_ambiguous_path_values(value: str) -> None:
    app = Flasgo()
    app.get("/<path:value>", name="file")(lambda value: value)
    with pytest.raises(ValueError):
        app.url_for("file", value=value)


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
