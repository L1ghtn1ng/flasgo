from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    missing_padding = (-len(value)) % 4
    return base64.urlsafe_b64decode(value + ("=" * missing_padding))


def _hmac_digest(secret: str, payload: bytes) -> str:
    digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest()
    return _b64encode(digest)


@dataclass(slots=True)
class Session:
    data: dict[str, Any]
    modified: bool = False

    def __getitem__(self, key: str) -> Any:
        return self.data[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.data[key] = value
        self.modified = True

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def pop(self, key: str, default: Any = None) -> Any:
        self.modified = True
        return self.data.pop(key, default)

    def clear(self) -> None:
        self.modified = True
        self.data.clear()


class SessionSigner:
    def __init__(
        self,
        secret_key: str,
        *,
        salt: str = "fango.session",
        max_clock_skew_seconds: int = 300,
    ) -> None:
        if max_clock_skew_seconds < 0:
            msg = "max_clock_skew_seconds must be non-negative."
            raise ValueError(msg)
        self.secret_key = f"{salt}:{secret_key}"
        self.max_clock_skew_seconds = max_clock_skew_seconds

    def dumps(self, payload: dict[str, Any]) -> str:
        json_payload = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        timestamp = str(int(time.time())).encode("ascii")
        encoded_payload = _b64encode(json_payload).encode("ascii")
        token_payload = b".".join((encoded_payload, timestamp))
        signature = _hmac_digest(self.secret_key, token_payload).encode("ascii")
        return b".".join((encoded_payload, timestamp, signature)).decode("ascii")

    def loads(self, token: str, *, max_age: int) -> dict[str, Any] | None:
        try:
            encoded_payload, timestamp_raw, signature = token.split(".", 2)
            token_payload = f"{encoded_payload}.{timestamp_raw}".encode("ascii")
            expected = _hmac_digest(self.secret_key, token_payload)
            if not hmac.compare_digest(signature, expected):
                return None

            issued_at = int(timestamp_raw)
            now = int(time.time())
            if issued_at > now + self.max_clock_skew_seconds:
                return None
            if now - issued_at > max_age:
                return None

            payload = json.loads(_b64decode(encoded_payload).decode("utf-8"))
            if not isinstance(payload, dict):
                return None
            return payload
        except Exception:
            return None
