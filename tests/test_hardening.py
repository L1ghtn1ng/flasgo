from __future__ import annotations

import asyncio
import json
import time

import pytest
from fango import Fango, HTTPException, Request, User
from fango.security import build_set_cookie
from fango.session import SessionSigner, _b64encode, _hmac_digest
from fango.testing import TestClient


def _extract_cookie(set_cookie_header: str, name: str) -> str | None:
    for line in set_cookie_header.split("\n"):
        raw = line.strip()
        if raw.startswith(f"{name}="):
            return raw.split(";", 1)[0].split("=", 1)[1]
    return None


def test_authorize_defaults_to_is_authenticated() -> None:
    app = Fango(settings={"CSRF_ENABLED": False})

    def header_backend(req: Request) -> User | None:
        user_id = req.headers.get("x-user")
        if not user_id:
            return None
        return User(id=user_id, is_authenticated=True)

    app.register_auth_backend("headers", header_backend)

    @app.get("/private")
    @app.authorize(backend="headers")
    def private() -> str:
        return "ok"

    client = TestClient(app)
    denied = client.get("/private")
    allowed = client.get("/private", headers={"x-user": "alice"})
    assert denied.status_code == 401
    assert allowed.status_code == 200


def test_request_body_stops_on_disconnect() -> None:
    async def receive() -> dict[str, object]:
        return {"type": "http.disconnect"}

    req = Request(scope={"type": "http", "headers": []}, receive=receive)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(req.body())
    assert exc.value.status_code == 400


def test_csrf_rejects_same_host_with_wrong_scheme() -> None:
    app = Fango()

    @app.get("/seed")
    def seed() -> str:
        return "seed"

    @app.post("/submit")
    def submit() -> str:
        return "ok"

    client = TestClient(app)
    seed_response = client.get("/seed", scheme="https")
    csrf_token = _extract_cookie(seed_response.headers.get("set-cookie", ""), "fango-csrf")
    assert csrf_token is not None

    rejected = client.post(
        "/submit",
        scheme="https",
        headers={
            "cookie": f"fango-csrf={csrf_token}",
            "x-csrf-token": csrf_token,
            "origin": "http://localhost",
        },
    )
    allowed = client.post(
        "/submit",
        scheme="https",
        headers={
            "cookie": f"fango-csrf={csrf_token}",
            "x-csrf-token": csrf_token,
            "origin": "https://localhost",
        },
    )
    assert rejected.status_code == 403
    assert allowed.status_code == 200


@pytest.mark.parametrize("cookie_value", ["bad;value", "bad,value", "bad value", "bad\tvalue"])
def test_build_set_cookie_rejects_unsafe_value_separators(cookie_value: str) -> None:
    with pytest.raises(ValueError):
        build_set_cookie("session", cookie_value)


def _build_signed_token(signer: SessionSigner, payload: dict[str, object], issued_at: int) -> str:
    encoded_payload = _b64encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    token_payload = f"{encoded_payload}.{issued_at}".encode("ascii")
    signature = _hmac_digest(signer.secret_key, token_payload)
    return f"{encoded_payload}.{issued_at}.{signature}"


def test_session_rejects_far_future_timestamp() -> None:
    signer = SessionSigner("s" * 32)
    issued_at = int(time.time()) + 3600
    token = _build_signed_token(signer, {"user_id": "alice"}, issued_at)
    assert signer.loads(token, max_age=3600) is None


def test_session_allows_small_clock_skew() -> None:
    signer = SessionSigner("s" * 32, max_clock_skew_seconds=300)
    issued_at = int(time.time()) + 120
    token = _build_signed_token(signer, {"ok": True}, issued_at)
    assert signer.loads(token, max_age=3600) == {"ok": True}
