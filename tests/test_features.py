from __future__ import annotations

from pathlib import Path

from flasgo import Flasgo, Request, Response, TestClient, redirect, session


def test_urlencoded_form_parsing_support() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.post("/submit")
    async def submit(request: Request) -> dict[str, object]:
        form = await request.form()
        return {
            "name": form.get("name"),
            "tags": form.getlist("tags"),
            "empty": form.get("empty"),
        }

    client = app.test_client()
    response = client.post(
        "/submit",
        data={
            "name": "alice",
            "tags": ["one", "two"],
            "empty": "",
        },
    )

    assert response.status_code == 200
    assert response.json() == {"name": "alice", "tags": ["one", "two"], "empty": ""}


def test_multipart_form_parsing_supports_files() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.post("/upload")
    async def upload(request: Request) -> dict[str, object]:
        form = await request.form()
        uploaded = form.file("avatar")
        assert uploaded is not None
        return {
            "title": form.get("title"),
            "filename": uploaded.filename,
            "content_type": uploaded.content_type,
            "size": uploaded.size,
            "text": uploaded.text(),
        }

    client = app.test_client()
    response = client.post(
        "/upload",
        data={"title": "Profile"},
        files={"avatar": ("me.txt", "hello", "text/plain")},
    )

    assert response.status_code == 200
    assert response.json() == {
        "title": "Profile",
        "filename": "me.txt",
        "content_type": "text/plain",
        "size": 5,
        "text": "hello",
    }


def test_form_parsing_rejects_missing_multipart_boundary() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.post("/upload")
    async def upload(request: Request) -> dict[str, str]:
        await request.form()
        return {"ok": "true"}

    client = app.test_client()
    response = client.post(
        "/upload",
        body=b"--invalid\r\n",
        headers={"content-type": "multipart/form-data"},
    )

    assert response.status_code == 400
    assert "Include a boundary in the Content-Type header" in response.text


def test_static_files_serve_assets_with_caching_headers(tmp_path: Path) -> None:
    static_dir = tmp_path / "static"
    static_dir.mkdir()
    asset = static_dir / "site.css"
    asset.write_text("body{color:black;}", encoding="utf-8")

    app = Flasgo(settings={"CSRF_ENABLED": False}, static_folder=static_dir, static_cache_max_age=86400)
    client = app.test_client()

    response = client.get("/static/site.css")

    assert response.status_code == 200
    assert response.headers["content-type"] == "text/css"
    assert response.headers["cache-control"] == "public, max-age=86400"
    assert "etag" in response.headers
    assert response.body == b"body{color:black;}"

    head_response = client.head("/static/site.css")
    assert head_response.status_code == 200
    assert head_response.body == b""
    assert head_response.headers["content-length"] == str(len(response.body))


def test_static_files_support_conditional_get(tmp_path: Path) -> None:
    static_dir = tmp_path / "static"
    static_dir.mkdir()
    (static_dir / "app.js").write_text("console.log('ok')", encoding="utf-8")

    app = Flasgo(settings={"CSRF_ENABLED": False}, static_folder=static_dir)
    client = app.test_client()

    initial = client.get("/static/app.js")
    cached = client.get("/static/app.js", headers={"if-none-match": initial.headers["etag"]})

    assert initial.status_code == 200
    assert cached.status_code == 304
    assert cached.body == b""


def test_static_files_block_path_escape_and_hidden_files(tmp_path: Path) -> None:
    static_dir = tmp_path / "static"
    static_dir.mkdir()
    (static_dir / ".env").write_text("secret", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    (static_dir / "escape.txt").symlink_to(outside)

    app = Flasgo(settings={"CSRF_ENABLED": False}, static_folder=static_dir)
    client = app.test_client()

    assert client.get("/static/../outside.txt").status_code == 404
    assert client.get("/static/.env").status_code == 404
    assert client.get("/static/escape.txt").status_code == 404


def test_official_test_client_persists_cookies_and_follows_redirects() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.get("/counter")
    def counter() -> dict[str, int]:
        current_session = session()
        count = int(current_session.get("count", 0)) + 1
        current_session["count"] = count
        return {"count": count}

    @app.post("/login")
    def login() -> Response:
        return redirect("/welcome")

    @app.get("/welcome")
    def welcome(request: Request) -> dict[str, str]:
        return {"method": request.method}

    client = app.test_client()
    first = client.get("/counter")
    second = client.get("/counter")
    redirected = client.post("/login", json={"username": "alice"}, follow_redirects=True)

    assert isinstance(client, TestClient)
    assert first.json() == {"count": 1}
    assert second.json() == {"count": 2}
    assert redirected.status_code == 200
    assert redirected.json() == {"method": "GET"}
    assert len(redirected.history) == 1
