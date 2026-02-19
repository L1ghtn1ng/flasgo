from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from urllib.parse import urlsplit

from .types import ASGIApp, Message, Scope


@dataclass(slots=True)
class TestResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes

    @property
    def text(self) -> str:
        return self.body.decode("utf-8")

    def json(self) -> object:
        return json.loads(self.body)


class TestClient:
    __test__ = False

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
        scheme: str = "http",
    ) -> TestResponse:
        return asyncio.run(self.arequest(method, path, headers=headers, body=body, scheme=scheme))

    def get(self, path: str, *, headers: dict[str, str] | None = None, scheme: str = "http") -> TestResponse:
        return self.request("GET", path, headers=headers, scheme=scheme)

    def post(
        self,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
        scheme: str = "http",
    ) -> TestResponse:
        return self.request("POST", path, headers=headers, body=body, scheme=scheme)

    async def arequest(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
        scheme: str = "http",
    ) -> TestResponse:
        parsed = urlsplit(path)
        normalized_headers = {"host": "localhost", **(headers or {})}
        raw_headers = [
            (key.lower().encode("latin-1"), value.encode("latin-1")) for key, value in normalized_headers.items()
        ]
        scope: Scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": method.upper(),
            "scheme": scheme.lower(),
            "path": parsed.path or "/",
            "raw_path": (parsed.path or "/").encode("latin-1"),
            "query_string": parsed.query.encode("latin-1"),
            "headers": raw_headers,
            "client": ("127.0.0.1", 50000),
            "server": ("localhost", 80),
        }

        queue: list[Message] = [{"type": "http.request", "body": body, "more_body": False}]
        start_message: Message | None = None
        body_chunks: list[bytes] = []

        async def receive() -> Message:
            if queue:
                return queue.pop(0)
            return {"type": "http.disconnect"}

        async def send(message: Message) -> None:
            nonlocal start_message
            if message["type"] == "http.response.start":
                start_message = message
            elif message["type"] == "http.response.body":
                body_chunks.append(bytes(message.get("body", b"")))

        await self.app(scope, receive, send)

        if start_message is None:
            raise RuntimeError("No response start message from application")

        decoded_headers: dict[str, str] = {}
        for key_raw, value_raw in start_message.get("headers", []):
            key = key_raw.decode("latin-1").lower()
            value = value_raw.decode("latin-1")
            if key in decoded_headers:
                decoded_headers[key] = f"{decoded_headers[key]}\n{value}"
            else:
                decoded_headers[key] = value
        return TestResponse(
            status_code=int(start_message["status"]),
            headers=decoded_headers,
            body=b"".join(body_chunks),
        )
