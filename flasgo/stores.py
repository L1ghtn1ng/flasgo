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
    async def get(self, key: str) -> bytes | None:
        """Retrieve the value associated with a key.

        Returns:
            bytes | None: The unexpired value, or `None` if the key is absent or expired.
        """
        ...

    async def create(self, key: str, value: bytes, ttl: int) -> bool:
        """Create a session entry only when the key is absent.

        Parameters:
            key (str): Key identifying the session entry.
            value (bytes): Session data to store.
            ttl (int): Lifetime of the entry in seconds.

        Returns:
            bool: `True` if the entry was created, `False` if the key already exists.
        """
        ...

    async def replace(self, key: str, expected: bytes, value: bytes, ttl: int) -> bool:
        """Replace a stored value only when it matches the expected value.

        Parameters:
            key (str): The key identifying the stored value.
            expected (bytes): The value that must currently be stored.
            value (bytes): The replacement value.
            ttl (int): The replacement value's lifetime in seconds.

        Returns:
            bool: `true` if the value was replaced, `false` if the key was absent or its value differed from `expected`.
        """
        ...

    async def rotate(self, key: str, expected: bytes, new_key: str, value: bytes, ttl: int) -> bool:
        """Atomically move a session value to a new key when the expected value matches.

        Parameters:
            key (str): The current session key.
            expected (bytes): The value required at the current key.
            new_key (str): The destination session key.
            value (bytes): The value to store at the destination.
            ttl (int): The lifetime of the destination value in seconds.

        Returns:
            bool: `true` if the rotation succeeds, `false` otherwise.
        """
        ...

    async def delete(self, key: str) -> None:
        """Delete the stored value for a key if it exists.

        Parameters:
            key (str): The key identifying the stored value.
        """
        ...


class MemoryStore:
    """Bounded process-local session storage for development and tests."""

    def __init__(self, *, max_keys: int = 10_000) -> None:
        """Initialize a bounded in-memory session store.

        Parameters:
            max_keys (int): Maximum number of entries the store can contain.
        """
        if isinstance(max_keys, bool) or not isinstance(max_keys, int) or max_keys <= 0:
            raise ValueError("max_keys must be a positive integer.")
        self.max_keys = max_keys
        self._values: dict[str, tuple[bytes, float]] = {}
        self._lock = asyncio.Lock()

    def _get(self, key: str) -> bytes | None:
        """
        Retrieve an unexpired value for a key.

        Returns:
            bytes | None: The stored value, or `None` if the key is missing or expired.
        """
        item = self._values.get(key)
        if item is None:
            return None
        if item[1] <= time.monotonic():
            self._values.pop(key, None)
            return None
        return item[0]

    async def get(self, key: str) -> bytes | None:
        """Retrieve an unexpired value for a key.

        Parameters:
            key (str): The key to retrieve.

        Returns:
            bytes | None: The stored value, or `None` if the key is absent or expired.
        """
        async with self._lock:
            return self._get(key)

    async def create(self, key: str, value: bytes, ttl: int) -> bool:
        """
        Create a session entry if the key is unused and capacity is available.

        Parameters:
            key (str): Key for the session entry.
            value (bytes): Session data to store.
            ttl (int): Lifetime of the entry in seconds.

        Returns:
            bool: `true` if the entry was created, `false` if the key already exists.

        Raises:
            StoreUnavailable: If the store remains at capacity after expired entries are removed.
        """
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
        """Replace a stored value when its current value matches the expected value.

        Parameters:
            key (str): The key whose value should be replaced.
            expected (bytes): The value currently expected for the key.
            value (bytes): The replacement value.
            ttl (int): The replacement value's time-to-live in seconds.

        Returns:
            bool: `True` if the value was replaced, `False` if the current value differs from `expected`.
        """
        async with self._lock:
            if self._get(key) != expected:
                return False
            self._values[key] = (value, time.monotonic() + ttl)
            return True

    async def rotate(self, key: str, expected: bytes, new_key: str, value: bytes, ttl: int) -> bool:
        """Atomically move a value to a new key when the expected value matches.

        Parameters:
            expected (bytes): The value that must currently be stored under `key`.
            new_key (str): The destination key.

        Returns:
            bool: `true` if the value was moved, `false` if the expected value did not match or the destination key was already in use.
        """
        async with self._lock:
            if self._get(key) != expected or self._get(new_key) is not None:
                return False
            self._values[new_key] = (value, time.monotonic() + ttl)
            del self._values[key]
            return True

    async def delete(self, key: str) -> None:
        """Delete a session value by key."""
        async with self._lock:
            self._values.pop(key, None)


class RedisStore:
    """Redis/Valkey adapter. A supplied client remains owned by the application.

    Use a dedicated namespace and a noeviction storage policy for security state.
    All keys share a cluster hash slot so compare-and-swap and rotation are atomic.
    """

    def __init__(self, client: Any, *, namespace: str = "flasgo", timeout: float = 2, max_value_bytes: int = 65_536) -> None:
        """
        Configure a Redis-backed session store.

        Parameters:
            namespace (str): Namespace used to prefix stored keys.
            timeout (float): Maximum duration in seconds for Redis operations.
            max_value_bytes (int): Maximum permitted size of a stored value in bytes.

        Raises:
            ValueError: If the namespace, timeout, or maximum value size is invalid.
        """
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
        """Create a Redis-backed session store from a connection URL.

        Parameters:
            url (str): Redis connection URL.
            namespace (str): Namespace used to isolate stored keys.
            timeout (float): Connection and operation timeout in seconds.

        Returns:
            RedisStore: A store configured with a client created from the URL.

        Raises:
            ImportError: If the Redis optional dependency is not installed.
        """
        try:
            redis = importlib.import_module("redis.asyncio")
        except ImportError as exc:
            raise ImportError("Redis storage requires the optional extra: install 'flasgo[redis]'.") from exc
        client = redis.Redis.from_url(url, socket_connect_timeout=timeout, socket_timeout=timeout, max_connections=100)
        store = cls(client, namespace=namespace, timeout=timeout)
        store._owns_client = True
        return store

    async def aclose(self) -> None:
        """Close the Redis client when it is owned by this store."""
        if self._owns_client:
            await self.client.aclose()

    def key(self, value: str) -> str:
        """
        Create a namespaced storage key from a string value.

        Parameters:
            value (str): The value to transform into a storage key.

        Returns:
            str: The namespaced SHA-256 hexadecimal key.
        """
        return self.prefix + hashlib.sha256(value.encode("utf-8")).hexdigest()

    async def evaluate(self, script: str, keys: list[str], args: list[Any]) -> Any:
        """Execute a storage script and raise StoreUnavailable if it cannot be completed.

        Parameters:
            script (str): The script to execute.
            keys (list[str]): Keys passed to the script.
            args (list[Any]): Additional arguments passed to the script.

        Returns:
            Any: The result produced by the script.
        """
        try:
            async with asyncio.timeout(self.timeout):
                return await self.client.eval(script, len(keys), *keys, *args)
        except Exception as exc:
            raise StoreUnavailable("Shared storage is unavailable.") from exc

    def _value(self, value: bytes) -> bytes:
        """
        Validate a stored value against the configured type and size limits.

        Parameters:
            value (bytes): Value to validate.

        Returns:
            bytes: The validated value.

        Raises:
            ValueError: If the value is not bytes or exceeds the maximum size.
        """
        if not isinstance(value, bytes) or len(value) > self.max_value_bytes:
            raise ValueError("Stored values must be bytes within max_value_bytes.")
        return value

    async def get(self, key: str) -> bytes | None:
        """Retrieve a session value from shared storage.

        Parameters:
            key (str): The session key to retrieve.

        Returns:
            bytes | None: The stored value as bytes, or `None` if the key is absent.
        """
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
        """
        Atomically create a session entry if the key is unused.

        Parameters:
            key (str): The session key.
            value (bytes): The value to store.
            ttl (int): The lifetime of the entry in seconds.

        Returns:
            bool: `true` if the entry was created, `false` if the key already exists.
        """
        return bool(
            await self.evaluate(
                "return redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2], 'NX')",
                [self.key(key)],
                [self._value(value), ttl],
            )
        )

    async def replace(self, key: str, expected: bytes, value: bytes, ttl: int) -> bool:
        """
        Atomically replace a stored value when it matches the expected value.

        Parameters:
            key (str): Key identifying the stored value.
            expected (bytes): Current value required for replacement.
            value (bytes): New value to store.
            ttl (int): Lifetime of the new value in seconds.

        Returns:
            bool: `True` if the value was replaced, `False` if the stored value did not match `expected`.
        """
        return bool(
            await self.evaluate(
                "if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3]); return 1",
                [self.key(key)],
                [expected, self._value(value), ttl],
            )
        )

    async def rotate(self, key: str, expected: bytes, new_key: str, value: bytes, ttl: int) -> bool:
        """Atomically move a session value to a new key when its expected value matches and the destination is unused.

        Parameters:
            key (str): The existing session key.
            expected (bytes): The value that must currently be stored under `key`.
            new_key (str): The destination session key.
            value (bytes): The value to store under `new_key`.
            ttl (int): The lifetime of the new value in seconds.

        Returns:
            bool: `True` if the value was moved, `False` if the expected value did not match or the destination key was already in use.
        """
        return bool(
            await self.evaluate(
                "if redis.call('GET', KEYS[1]) ~= ARGV[1] or redis.call('EXISTS', KEYS[2]) == 1 then return 0 end "
                "redis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[3]); redis.call('DEL', KEYS[1]); return 1",
                [self.key(key), self.key(new_key)],
                [expected, self._value(value), ttl],
            )
        )

    async def delete(self, key: str) -> None:
        """Delete a session value by key."""
        await self.evaluate("return redis.call('DEL', KEYS[1])", [self.key(key)], [])
