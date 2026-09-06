import asyncio
from typing import Annotated

import pytest
from flasgo import Depends, Flasgo


def test_dependencies_close_in_reverse_order_at_declared_lifetimes() -> None:
    events = []

    def parent():
        events.append("parent-open")
        try:
            yield "parent"
        finally:
            events.append("parent-close")

    async def child(value: Annotated[str, Depends(parent)]):
        events.append("child-open")
        try:
            yield value
        finally:
            events.append("child-close")

    def transaction():
        events.append("transaction-open")
        try:
            yield "tx"
        finally:
            events.append("transaction-close")

    app = Flasgo()

    @app.get("/")
    def endpoint(
        value: Annotated[str, Depends(child)],
        again: Annotated[str, Depends(child)],
        tx: Annotated[str, Depends(transaction, scope="function")],
    ) -> str:
        events.append("endpoint")
        return value + again + tx

    assert app.test_client().get("/").text == "parentparenttx"
    assert events == [
        "parent-open",
        "child-open",
        "transaction-open",
        "endpoint",
        "transaction-close",
        "child-close",
        "parent-close",
    ]


def test_function_cleanup_failure_prevents_success_response() -> None:
    def transaction():
        yield "tx"
        raise RuntimeError("commit failed")

    app = Flasgo()

    @app.get("/")
    def endpoint(tx: Annotated[str, Depends(transaction, scope="function")]) -> str:
        return "success"

    response = app.test_client().get("/")
    assert response.status_code == 500
    assert "commit failed" not in response.text


def test_exception_reaches_yield_and_closes_already_open_resources() -> None:
    events = []

    def resource():
        try:
            yield "resource"
        except ValueError:
            events.append("rollback")
            raise
        finally:
            events.append("close")

    app = Flasgo()

    @app.get("/")
    def endpoint(value: Annotated[str, Depends(resource)]) -> str:
        raise ValueError("handler failed")

    assert app.test_client().get("/").status_code == 500
    assert events == ["rollback", "close"]


def test_long_lived_dependency_cannot_hold_short_lived_dependency() -> None:
    def short():
        yield "short"

    def long(value: Annotated[str, Depends(short, scope="function")]):
        yield value

    app = Flasgo()
    with pytest.raises(TypeError, match="request-scoped"):

        @app.get("/")
        def endpoint(value: Annotated[str, Depends(long)]) -> str:
            return value


def test_overrides_are_isolated_between_concurrent_requests_and_restore() -> None:
    def original() -> str:
        return "original"

    app = Flasgo()

    @app.get("/")
    async def endpoint(value: Annotated[str, Depends(original)]) -> str:
        await asyncio.sleep(0)
        return value

    async def run() -> None:
        async def one(value: str) -> str:
            with app.override_dependencies({original: lambda: value}):
                response = await app.test_client().arequest("GET", "/")
                return response.text

        assert await asyncio.gather(one("first"), one("second")) == ["first", "second"]
        assert (await app.test_client().arequest("GET", "/")).text == "original"

    asyncio.run(run())


def test_cancellation_reaches_request_dependency_and_closes_it() -> None:
    events = []
    started = asyncio.Event()

    async def resource():
        try:
            yield "resource"
        except asyncio.CancelledError:
            events.append("cancelled")
            raise
        finally:
            events.append("closed")

    app = Flasgo()

    @app.get("/")
    async def endpoint(value: Annotated[str, Depends(resource)]) -> str:
        started.set()
        await asyncio.Event().wait()
        return value

    async def run() -> None:
        task = asyncio.create_task(app.test_client().arequest("GET", "/"))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert events == ["cancelled", "closed"]

    asyncio.run(run())


def test_override_cycle_and_invalid_lifetime_fail_closed() -> None:
    def original() -> str:
        return "original"

    def recursive(value: Annotated[str, Depends(original)]) -> str:
        return value

    app = Flasgo()

    @app.get("/")
    def endpoint(value: Annotated[str, Depends(original)]) -> str:
        return value

    with app.override_dependencies({original: recursive}):
        assert app.test_client().get("/").status_code == 500
    assert app.test_client().get("/").text == "original"


def test_provider_suppression_cannot_turn_failed_request_into_success() -> None:
    def resource():
        try:
            yield "resource"
        except ValueError:
            return

    app = Flasgo()

    @app.get("/")
    def endpoint(value: Annotated[str, Depends(resource, scope="function")]) -> str:
        raise ValueError("failure")

    assert app.test_client().get("/").status_code == 500


def test_registered_uncached_providers_do_not_repeat_scope_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    from flasgo import di

    calls = []

    def provider() -> str:
        calls.append("called")
        return "value"

    app = Flasgo()

    @app.get("/")
    def endpoint(
        first: Annotated[str, Depends(provider, use_cache=False)],
        second: Annotated[str, Depends(provider, use_cache=False)],
    ) -> str:
        return first + second

    def unexpected_validation(*args: object, **kwargs: object) -> None:
        pytest.fail("Registered plans must already be scope-validated")

    monkeypatch.setattr(di, "_validate_dependency_scopes", unexpected_validation)
    for _ in range(2):
        assert app.test_client().get("/").text == "valuevalue"
    assert len(calls) == 4


def test_override_preserves_outer_request_lifetime_constraint() -> None:
    calls = []

    def original() -> str:
        return "original"

    def short() -> str:
        calls.append("short")
        return "short"

    def replacement(value: Annotated[str, Depends(short, scope="function")]) -> str:
        calls.append("replacement")
        return value

    app = Flasgo()

    @app.get("/")
    def endpoint(value: Annotated[str, Depends(original)]) -> str:
        return value

    with app.override_dependencies({original: replacement}):
        assert app.test_client().get("/").status_code == 500
    assert calls == []
    assert app.test_client().get("/").text == "original"


def test_shared_provider_is_validated_separately_for_each_parent_scope() -> None:
    def short() -> str:
        return "short"

    def shared(value: Annotated[str, Depends(short, scope="function")]) -> str:
        return value

    app = Flasgo()
    with pytest.raises(TypeError, match="request-scoped"):

        @app.get("/")
        def endpoint(
            first: Annotated[str, Depends(shared, scope="function")],
            second: Annotated[str, Depends(shared, scope="request")],
        ) -> str:
            return first + second

    assert app._routes == []
