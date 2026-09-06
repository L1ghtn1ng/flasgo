import asyncio
import os
import shutil
import subprocess
import time
from uuid import uuid4

import pytest
from flasgo import (
    Flasgo,
    MemoryStore,
    RedisRateLimiter,
    RedisStore,
    ServerSideSessions,
    Session,
    StoreUnavailable,
    session,
)
from flasgo.exceptions import HTTPException
from flasgo.ratelimit import RateLimitRule
from flasgo.request import Request


@pytest.fixture(scope="module")
def redis_url(tmp_path_factory: pytest.TempPathFactory):
    """
    Provide a Redis connection URL for integration tests.

    Parameters:
        tmp_path_factory (pytest.TempPathFactory): Factory used to create isolated temporary Redis server storage.

    Yields:
        str: The configured Redis URL or a URL for a temporary Unix-socket Redis server.

    Raises:
        pytest.skip.Exception: If no Redis or Valkey server executable is available.
    """
    configured = os.environ.get("FLASGO_TEST_REDIS_URL")
    if configured:
        yield configured
        return
    executable = shutil.which("redis-server") or shutil.which("valkey-server")
    if executable is None:
        pytest.skip("Install redis-server/valkey-server or set FLASGO_TEST_REDIS_URL for integration tests.")
    directory = tmp_path_factory.mktemp("redis")
    socket = directory / "redis.sock"
    process = subprocess.Popen(
        [
            executable,
            "--port",
            "0",
            "--unixsocket",
            str(socket),
            "--unixsocketperm",
            "700",
            "--save",
            "",
            "--appendonly",
            "no",
            "--dir",
            str(directory),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 5
        while not socket.exists():
            if process.poll() is not None or time.monotonic() > deadline:
                pytest.fail("Isolated Redis server failed to start; check local socket permissions.")
            time.sleep(0.01)
        yield "unix://" + str(socket)
    finally:
        process.terminate()
        process.wait(timeout=5)


def request_for(identity: str = "127.0.0.1") -> Request:
    """
    Create a minimal GET request for the specified client identity.

    Parameters:
        identity (str): Client address to associate with the request.

    Returns:
        Request: A GET request targeting the root path.
    """

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request({"type": "http", "path": "/", "method": "GET", "client": (identity, 80)}, receive)


def test_server_sessions_revoke_rotate_and_reject_stale_updates() -> None:
    async def run() -> None:
        backend = ServerSideSessions(MemoryStore())
        original = Session({"user": "alice"}, modified=True)
        first = await backend.save(original, max_age=60)
        assert first is not None and "alice" not in first
        stale = await backend.load(first)
        original.regenerate()
        second = await backend.save(original, max_age=60)
        assert second and second != first
        assert (await backend.load(first)).data == {}
        stale["user"] = "revived"
        with pytest.raises(HTTPException) as error:
            await backend.save(stale, max_age=60)
        assert error.value.status_code == 409
        await backend.revoke(second)
        assert (await backend.load(second)).data == {}

    asyncio.run(run())


def test_server_sessions_concurrent_updates_do_not_overwrite_or_resurrect() -> None:
    async def run() -> None:
        backend = ServerSideSessions(MemoryStore())
        token = await backend.save(Session({"user": "alice"}, modified=True), max_age=60)
        one, two = await asyncio.gather(backend.load(token), backend.load(token))
        one["value"] = 1
        two["value"] = 2
        await backend.save(one, max_age=60)
        with pytest.raises(HTTPException):
            await backend.save(two, max_age=60)
        assert (await backend.load(token)).data == {"user": "alice", "value": 1}

    asyncio.run(run())


def test_session_backend_integrates_cookies_csrf_and_logout() -> None:
    backend = ServerSideSessions(MemoryStore())
    app = Flasgo(session_backend=backend)

    @app.get("/login")
    def login() -> str:
        """
        Authenticate Alice by storing her identity in the session and regenerating the session identifier.

        Returns:
                str: The string "ok".
        """
        session["user"] = "alice"
        session.regenerate()
        return "ok"

    @app.post("/logout")
    def logout() -> str:
        """
        Clear the current session and confirm the logout operation.

        Returns:
                str: The confirmation string "ok".
        """
        session.clear()
        return "ok"

    client = app.test_client()
    login_response = client.get("/login")
    cookies = login_response.headers["set-cookie"]
    assert "alice" not in cookies
    assert "HttpOnly" in cookies and "Secure" in cookies
    assert client.post("/logout").status_code == 403
    token = client.cookies["flasgo-csrf"]
    response = client.post("/logout", headers={"x-csrf-token": token, "origin": "http://localhost"})
    assert response.status_code == 200
    assert "Max-Age=0" in response.headers["set-cookie"]


def test_storage_outage_fails_closed_without_exposing_backend_details() -> None:
    class Unavailable(MemoryStore):
        async def get(self, key: str) -> bytes | None:
            """
            Retrieve the value associated with a key from storage.

            Returns:
                bytes | None: The stored value, or `None` when the key does not exist.

            Raises:
                StoreUnavailable: If the storage backend cannot be accessed.
            """
            raise StoreUnavailable("redis://password@private.example")

    app = Flasgo(session_backend=ServerSideSessions(Unavailable()))
    app.get("/")(lambda: "must not run")
    response = app.test_client().get("/", headers={"cookie": "flasgo-session=" + "a" * 43})
    assert response.status_code == 503
    assert "password" not in response.text
    assert "set-cookie" not in response.headers or "flasgo-session" not in response.headers["set-cookie"]


def test_redis_sessions_use_real_atomic_storage(redis_url: str) -> None:
    async def run() -> None:
        """Verify Redis session rotation, stale-update rejection, data preservation, expiration, and cleanup."""
        store = RedisStore.from_url(redis_url, namespace="test-" + uuid4().hex)
        backend = ServerSideSessions(store)
        try:
            session = Session({"user": "alice"}, modified=True)
            token = await backend.save(session, max_age=1)
            stale = await backend.load(token)
            session.regenerate()
            rotated = await backend.save(session, max_age=1)
            assert rotated and rotated != token
            stale["value"] = 1
            with pytest.raises(HTTPException):
                await backend.save(stale, max_age=1)
            assert (await backend.load(rotated)).data == {"user": "alice"}
            await asyncio.sleep(1.05)
            assert (await backend.load(rotated)).data == {}
        finally:
            await store.aclose()

    asyncio.run(run())


def test_redis_quota_is_shared_across_app_instances_and_atomic(redis_url: str) -> None:
    """
    Verifies shared Redis rate-limit quotas and atomic enforcement across application instances.
    """

    async def run() -> None:
        namespace = "test-" + uuid4().hex
        first = RedisStore.from_url(redis_url, namespace=namespace)
        second = RedisStore.from_url(redis_url, namespace=namespace)
        try:
            apps = [Flasgo(rate_limiter=RedisRateLimiter(store)) for store in (first, second)]
            for app in apps:

                @app.get("/")
                @app.ratelimit(5, per=60)
                def endpoint() -> str:
                    return "ok"

            replies = await asyncio.gather(*(apps[index % 2].test_client().arequest("GET", "/") for index in range(20)))
            assert sum(reply.status_code == 200 for reply in replies) == 5
            assert sum(reply.status_code == 429 for reply in replies) == 15
            limiter = RedisRateLimiter(first)
            req = request_for("other")
            restrictive = RateLimitRule(1, 60, scope="restricted")
            generous = RateLimitRule(10, 60, scope="generous")
            assert (await limiter.check(restrictive, req, endpoint_id="r")).allowed
            result = await limiter.check_batch([(generous, "g"), (restrictive, "r")], req)
            assert not result[1].allowed
            assert (await limiter.check(generous, req, endpoint_id="g")).remaining == 9
        finally:
            await first.aclose()
            await second.aclose()

    asyncio.run(run())


def test_redis_capacity_pressure_preserves_active_quotas(redis_url: str) -> None:
    async def run() -> None:
        store = RedisStore.from_url(redis_url, namespace="test-" + uuid4().hex)
        limiter = RedisRateLimiter(store, max_keys=1)
        rule = RateLimitRule(1, 60)
        try:
            assert (await limiter.check(rule, request_for("one"), endpoint_id="route")).allowed
            assert not (await limiter.check(rule, request_for("two"), endpoint_id="route")).allowed
            assert not (await limiter.check(rule, request_for("one"), endpoint_id="route")).allowed
        finally:
            await store.aclose()

    asyncio.run(run())


def test_redis_timeouts_are_bounded_and_fail_closed() -> None:
    class Client:
        async def eval(self, *args):
            """
            Wait indefinitely until the operation is cancelled.
            """
            await asyncio.Event().wait()

    async def run() -> None:
        store = RedisStore(Client(), timeout=0.01)
        with pytest.raises(StoreUnavailable):
            await store.get("test")

    asyncio.run(run())


def test_storage_write_failure_replaces_success_before_headers() -> None:
    class Unavailable(MemoryStore):
        async def create(self, key: str, value: bytes, ttl: int) -> bool:
            """Rejects attempts to create a stored value.

            Raises:
                StoreUnavailable: Always, with a message indicating unavailable credentials.
            """
            raise StoreUnavailable("private credentials")

    app = Flasgo(session_backend=ServerSideSessions(Unavailable()))

    @app.get("/")
    def endpoint() -> str:
        """
        Store the user identity in the session and report successful processing.

        Returns:
                str: The literal value `"success"`.
        """
        session["user"] = "alice"
        return "success"

    response = app.test_client().get("/")
    assert response.status_code == 503
    assert response.text == "Service Unavailable"
    assert "set-cookie" not in response.headers


def test_redis_separate_methods_have_separate_default_quotas(redis_url: str) -> None:
    async def run() -> None:
        store = RedisStore.from_url(redis_url, namespace="test-" + uuid4().hex)
        app = Flasgo(settings={"CSRF_ENABLED": False}, rate_limiter=RedisRateLimiter(store))
        try:

            @app.get("/")
            @app.ratelimit(1, per=60)
            def get() -> str:
                """
                Identify the HTTP method as GET.

                Returns:
                        str: The string "get".
                """
                return "get"

            @app.post("/")
            @app.ratelimit(1, per=60)
            def post() -> str:
                """Return the string identifying a POST request.

                Returns:
                        str: The string ``"post"``.
                """
                return "post"

            client = app.test_client()
            assert (await client.arequest("GET", "/")).status_code == 200
            assert (await client.arequest("HEAD", "/")).status_code == 429
            assert (await client.arequest("POST", "/")).status_code == 200
        finally:
            await store.aclose()

    asyncio.run(run())


def test_redis_concurrent_session_writes_and_revocation_are_atomic(redis_url: str) -> None:
    async def run() -> None:
        store = RedisStore.from_url(redis_url, namespace="test-" + uuid4().hex)
        backend = ServerSideSessions(store)
        try:
            token = await backend.save(Session({"value": 0}, modified=True), max_age=60)
            first, second = await asyncio.gather(backend.load(token), backend.load(token))
            first["value"] = 1
            second["value"] = 2
            results = await asyncio.gather(backend.save(first, max_age=60), backend.save(second, max_age=60), return_exceptions=True)
            assert sum(isinstance(result, HTTPException) for result in results) == 1
            loaded = await backend.load(token)
            assert loaded.session_id is not None
            await backend.revoke(loaded.session_id)
            loaded["value"] = 3
            with pytest.raises(HTTPException):
                await backend.save(loaded, max_age=60)
        finally:
            await store.aclose()

    asyncio.run(run())
