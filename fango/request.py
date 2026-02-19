from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from urllib.parse import parse_qs

from .exceptions import HTTPException
from .types import Receive, Scope


def _decode_headers(raw_headers: list[tuple[bytes, bytes]]) -> dict[str, str]:
    return {key.decode("latin-1").lower(): value.decode("latin-1") for key, value in raw_headers}


def _parse_cookies(cookie_header: str | None) -> dict[str, str]:
    if not cookie_header:
        return {}
    cookies: dict[str, str] = {}
    for chunk in cookie_header.split(";"):
        item = chunk.strip()
        if not item or "=" not in item:
            continue
        key, value = item.split("=", 1)
        cookies[key.strip()] = value.strip()
    return cookies


@dataclass(slots=True)
class Request:
    scope: Scope
    receive: Receive
    headers: dict[str, str] = field(init=False)
    _body: bytes | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        self.headers = _decode_headers(self.scope.get("headers", []))

    @property
    def method(self) -> str:
        return str(self.scope.get("method", "GET")).upper()

    @property
    def path(self) -> str:
        return str(self.scope.get("path", "/"))

    @property
    def query_string(self) -> str:
        return bytes(self.scope.get("query_string", b"")).decode("latin-1")

    @property
    def scheme(self) -> str:
        raw = self.scope.get("scheme", "http")
        if not isinstance(raw, str):
            return "http"
        normalized = raw.strip().lower()
        return normalized or "http"

    @property
    def query_params(self) -> Mapping[str, list[str]]:
        return parse_qs(self.query_string, keep_blank_values=True)

    @property
    def cookies(self) -> dict[str, str]:
        return _parse_cookies(self.headers.get("cookie"))

    @property
    def client_ip(self) -> str | None:
        client = self.scope.get("client")
        if not client:
            return None
        return str(client[0])

    @property
    def session(self) -> object | None:
        return self.scope.get("session")

    @property
    def user(self) -> object | None:
        return self.scope.get("user")

    async def body(self) -> bytes:
        if self._body is not None:
            return self._body

        max_body = self.scope.get("max_request_body_bytes")
        body_limit = int(max_body) if isinstance(max_body, int) else None
        chunks: list[bytes] = []
        seen = 0
        while True:
            message = await self.receive()
            message_type = message.get("type")
            if message_type == "http.disconnect":
                raise HTTPException(400, "Client disconnected")
            if message_type != "http.request":
                continue
            piece = bytes(message.get("body", b""))
            seen += len(piece)
            if body_limit is not None and seen > body_limit:
                raise HTTPException(413, "Payload Too Large")
            chunks.append(piece)
            if not message.get("more_body", False):
                break
        self._body = b"".join(chunks)
        return self._body

    async def text(self, encoding: str = "utf-8") -> str:
        return (await self.body()).decode(encoding)

    async def json(self) -> object:
        return json.loads(await self.body())
