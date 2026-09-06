from __future__ import annotations

import asyncio
import hashlib
import importlib
import math
import re
import time
from typing import Any, Protocol


class StoreUnavailable(Exception):
    """Shared storage failed; callers must not fall back to uncoordinated state."""


class SessionStore(Protocol):
    async def get(self, key: str) -> bytes | None: ...
    async def create(self, key: str, value: bytes, ttl: int) -> bool: ...
    async def replace(self, key: str, expected: bytes, value: bytes, ttl: int) -> bool: ...
    async def rotate(self, key: str, expected: bytes, new_key: str, value: bytes, ttl: int) -> bool: ...
    async def delete(self, key: str) -> None: ...


class MemoryStore:
    """Bounded process-local session storage for development and tests."""

    def __init__(self, *, max_keys: int = 10_000) -> None:
        if isinstance(max_keys, bool) or not isinstance(max_keys, int) or max_keys <= 0:
            raise ValueError("max_keys must be a positive integer.")
        self.max_keys = max_keys
        self._values: dict[str, tuple[bytes, float]] = {}
        self._lock = asyncio.Lock()

    def _get(self, key: str) -> bytes | None:
        item = self._values.get(key)
        if item is None:
            return None
        if item[1] <= time.monotonic():
            self._values.pop(key, None)
            return None
        return item[0]

    async def get(self, key: str) -> bytes | None:
        async with self._lock:
            return self._get(key)

    async def create(self, key: str, value: bytes, ttl: int) -> bool:
        async with self._lock:
            if self._get(key) is not None:
                return False
            if len(self._values) >= self.max_keys:
                for existing in tuple(self._values):
                    self._get(existing)
                if len(self._values) >= self.max_keys:
                    raise StoreUnavailable("Session store capacity reached.")
            self._values[key] = (value, time.monotonic() + ttl)
            return True

    async def replace(self, key: str, expected: bytes, value: bytes, ttl: int) -> bool:
        async with self._lock:
            if self._get(key) != expected:
                return False
            self._values[key] = (value, time.monotonic() + ttl)
            return True

    async def rotate(self, key: str, expected: bytes, new_key: str, value: bytes, ttl: int) -> bool:
        async with self._lock:
            if self._get(key) != expected or self._get(new_key) is not None:
                return False
            self._values[new_key] = (value, time.monotonic() + ttl)
            del self._values[key]
            return True

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._values.pop(key, None)


class RedisStore:
    """Redis/Valkey adapter. A supplied client remains owned by the application.

    Use a dedicated namespace and a noeviction storage policy for security state.
    All keys share a cluster hash slot so compare-and-swap and rotation are atomic.
    """

    def __init__(
        self, client: Any, *, namespace: str = "flasgo", timeout: float = 2, max_value_bytes: int = 65_536
    ) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", namespace):
            raise ValueError("Store namespace must contain 1-64 ASCII letters, digits, underscores or hyphens.")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Store timeout must be finite and greater than zero.")
        if isinstance(max_value_bytes, bool) or not isinstance(max_value_bytes, int) or max_value_bytes <= 0:
            raise ValueError("max_value_bytes must be a positive integer.")
        self.client = client
        self.prefix = "{" + namespace + "}:"
        self.timeout = timeout
        self.max_value_bytes = max_value_bytes
        self._owns_client = False

    @classmethod
    def from_url(cls, url: str, *, namespace: str = "flasgo", timeout: float = 2) -> RedisStore:
        try:
            redis = importlib.import_module("redis.asyncio")
        except ImportError as exc:
            raise ImportError("Redis storage requires the optional extra: install 'flasgo[redis]'.") from exc
        client = redis.Redis.from_url(url, socket_connect_timeout=timeout, socket_timeout=timeout, max_connections=100)
        store = cls(client, namespace=namespace, timeout=timeout)
        store._owns_client = True
        return store

    async def aclose(self) -> None:
        if self._owns_client:
            await self.client.aclose()

    def key(self, value: str) -> str:
        return self.prefix + hashlib.sha256(value.encode("utf-8")).hexdigest()

    async def evaluate(self, script: str, keys: list[str], args: list[Any]) -> Any:
        try:
            async with asyncio.timeout(self.timeout):
                return await self.client.eval(script, len(keys), *keys, *args)
        except Exception as exc:
            raise StoreUnavailable("Shared storage is unavailable.") from exc

    def _value(self, value: bytes) -> bytes:
        if not isinstance(value, bytes) or len(value) > self.max_value_bytes:
            raise ValueError("Stored values must be bytes within max_value_bytes.")
        return value

    async def get(self, key: str) -> bytes | None:
        result = await self.evaluate(
            "if redis.call('STRLEN', KEYS[1]) > tonumber(ARGV[1]) then return redis.error_reply('value too large') end "
            "return redis.call('GET', KEYS[1])",
            [self.key(key)],
            [self.max_value_bytes],
        )
        if result is None or result is False:
            return None
        if isinstance(result, str):
            return result.encode("utf-8")
        if not isinstance(result, bytes):
            raise StoreUnavailable("Shared storage returned invalid data.")
        return result

    async def create(self, key: str, value: bytes, ttl: int) -> bool:
        return bool(
            await self.evaluate(
                "return redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2], 'NX')",
                [self.key(key)],
                [self._value(value), ttl],
            )
        )

    async def replace(self, key: str, expected: bytes, value: bytes, ttl: int) -> bool:
        return bool(
            await self.evaluate(
                "if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end "
                "redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3]); return 1",
                [self.key(key)],
                [expected, self._value(value), ttl],
            )
        )

    async def rotate(self, key: str, expected: bytes, new_key: str, value: bytes, ttl: int) -> bool:
        return bool(
            await self.evaluate(
                "if redis.call('GET', KEYS[1]) ~= ARGV[1] or redis.call('EXISTS', KEYS[2]) == 1 then return 0 end "
                "redis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[3]); redis.call('DEL', KEYS[1]); return 1",
                [self.key(key), self.key(new_key)],
                [expected, self._value(value), ttl],
            )
        )

    async def delete(self, key: str) -> None:
        await self.evaluate("return redis.call('DEL', KEYS[1])", [self.key(key)], [])
