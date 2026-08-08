from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest
from flasgo import Flasgo, Request, Response, TestClient, redirect, session
from flasgo import staticfiles as staticfiles_module
from flasgo.debug import Debug
from jinja2 import TemplateError


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

    app = Flasgo(static_folder=static_dir, static_cache_max_age=86400)
    client = app.test_client()

    response = client.get("/static/site.css")

    assert response.status_code == 200
    assert response.headers["content-type"] == "text/css"
    assert response.headers["cache-control"] == "public, max-age=86400"
    assert "etag" in response.headers
    assert response.body == b"body{color:black;}"
    assert "set-cookie" not in response.headers

    head_response = client.head("/static/site.css")
    assert head_response.status_code == 200
    assert head_response.body == b""
    assert head_response.headers["content-length"] == str(len(response.body))
    assert "set-cookie" not in head_response.headers


def test_public_cache_response_does_not_persist_framework_cookies() -> None:
    app = Flasgo()

    @app.get("/public")
    def public() -> Response:
        session()["value"] = "must-not-be-cached"
        return Response(
            body=b"public",
            headers={"cache-control": "public, max-age=60"},
            allow_public_cache=True,
        )

    response = app.test_client().get("/public")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "public, max-age=60"
    assert "set-cookie" not in response.headers


def test_static_head_does_not_open_or_read_the_asset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    static_dir = tmp_path / "static"
    static_dir.mkdir()
    asset = static_dir / "large.bin"
    asset.write_bytes(b"contents")
    app = Flasgo(settings={"CSRF_ENABLED": False}, static_folder=static_dir)

    original_open = Path.open
    asset_opens = 0

    def tracked_open(path: Path, *args: object, **kwargs: object):
        nonlocal asset_opens
        if path == asset:
            asset_opens += 1
        return cast(Any, original_open)(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", tracked_open)
    response = app.test_client().head("/static/large.bin")

    assert response.status_code == 200
    assert response.body == b""
    assert response.headers["content-length"] == str(len(b"contents"))
    assert asset_opens == 0


def test_static_get_streams_without_path_read_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    static_dir = tmp_path / "static"
    static_dir.mkdir()
    asset = static_dir / "asset.bin"
    asset.write_bytes(b"streamed")
    app = Flasgo(settings={"CSRF_ENABLED": False}, static_folder=static_dir)

    def reject_read_bytes(path: Path) -> bytes:
        raise AssertionError(f"read_bytes must not buffer static files: {path}")

    monkeypatch.setattr(Path, "read_bytes", reject_read_bytes)
    response = app.test_client().get("/static/asset.bin")

    assert response.status_code == 200
    assert response.body == b"streamed"


def test_static_get_reads_bounded_chunks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    static_dir = tmp_path / "static"
    static_dir.mkdir()
    payload = b"x" * (staticfiles_module._STREAM_CHUNK_SIZE + 1)
    (static_dir / "large.bin").write_bytes(payload)
    observed_sizes: list[int] = []
    original_read = staticfiles_module._read_static_chunk

    def tracked_read(handle: Any) -> bytes:
        chunk = original_read(handle)
        observed_sizes.append(len(chunk))
        return chunk

    monkeypatch.setattr(staticfiles_module, "_read_static_chunk", tracked_read)
    response = Flasgo(settings={"CSRF_ENABLED": False}, static_folder=static_dir).test_client().get("/static/large.bin")

    assert response.body == payload
    assert observed_sizes == [staticfiles_module._STREAM_CHUNK_SIZE, 1, 0]


def test_static_get_uses_metadata_from_the_streamed_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    static_dir = tmp_path / "static"
    static_dir.mkdir()
    asset = static_dir / "asset.bin"
    asset.write_bytes(b"old")
    app = Flasgo(settings={"CSRF_ENABLED": False}, static_folder=static_dir)
    original_open = staticfiles_module._open_static_file
    replacement = b"replacement-contents"

    def replace_then_open(path: Path):
        asset.write_bytes(replacement)
        return original_open(path)

    monkeypatch.setattr(staticfiles_module, "_open_static_file", replace_then_open)
    response = app.test_client().get("/static/asset.bin")
    stat = asset.stat()

    assert response.status_code == 200
    assert response.body == replacement
    assert response.headers["content-length"] == str(len(replacement))
    assert response.headers["etag"] == f'"{stat.st_mtime_ns:x}-{stat.st_size:x}"'


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
    assert cached.headers["cache-control"] == initial.headers["cache-control"]
    assert "set-cookie" not in initial.headers
    assert "set-cookie" not in cached.headers
    assert cached.headers["cache-control"].startswith("public")
    assert "pragma" not in cached.headers


def test_content_length_tracks_body_mutated_by_after_request() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.get("/greet")
    def greet() -> str:
        return "hi"

    @app.after_request
    def rewrite(request: Request, response: Response) -> Response:
        _ = request
        response.body = b"hello world"
        return response

    client = app.test_client()
    response = client.get("/greet")

    assert response.status_code == 200
    assert response.body == b"hello world"
    assert response.headers["content-length"] == str(len(b"hello world"))


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


def test_debug_environment_filter_uses_exact_non_secret_names(monkeypatch: pytest.MonkeyPatch) -> None:
    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    monkeypatch.setenv("LANG", "en_GB.UTF-8")
    monkeypatch.setenv("LANGSMITH_API_KEY", "must-not-leak")
    monkeypatch.setenv("USER_PASSWORD", "must-not-leak")
    request = Request({"type": "http", "method": "GET", "path": "/broken", "headers": []}, receive)
    response = Debug.render_template_debug_error(request, TemplateError("broken"), True)

    assert response is not None
    assert b"LANG=en_GB.UTF-8" in response.body
    assert b"must-not-leak" not in response.body


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
