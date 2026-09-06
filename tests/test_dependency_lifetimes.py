import asyncio
from typing import Annotated

import pytest
from flasgo import Depends, Flasgo


def test_dependencies_close_in_reverse_order_at_declared_lifetimes() -> None:
    events = []

    def parent():
        """Provide the parent dependency value and record its lifecycle events."""
        events.append("parent-open")
        try:
            yield "parent"
        finally:
            events.append("parent-close")

    async def child(value: Annotated[str, Depends(parent)]):
        """
        Provide the parent dependency value while managing the child dependency lifetime.
        """
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
        """
        Combine the injected child values and transaction value.

        Parameters:
                value (str): The first value provided by the child dependency.
                again (str): The second value provided by the child dependency.
                tx (str): The value provided by the function-scoped transaction dependency.

        Returns:
                str: The concatenated child and transaction values.
        """
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
        """Provide a transaction resource and raise an error during cleanup to simulate a failed commit."""
        yield "tx"
        raise RuntimeError("commit failed")

    app = Flasgo()

    @app.get("/")
    def endpoint(tx: Annotated[str, Depends(transaction, scope="function")]) -> str:
        """
        Handle a request using a function-scoped transaction dependency.

        Parameters:
                tx (str): Function-scoped transaction value.

        Returns:
                str: The success response.
        """
        return "success"

    response = app.test_client().get("/")
    assert response.status_code == 500
    assert "commit failed" not in response.text


def test_exception_reaches_yield_and_closes_already_open_resources() -> None:
    events = []

    def resource():
        """
        Provide a resource and record rollback and closure events during cleanup.

        Yields:
            str: The resource value.
        """
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
        """Provide the value identifying the short-lived dependency."""
        yield "short"

    def long(value: Annotated[str, Depends(short, scope="function")]):
        """
        Provide a dependency value scoped to a function invocation.

        Yields:
            str: The value supplied by the shorter-lived dependency.
        """
        yield value

    app = Flasgo()
    with pytest.raises(TypeError, match="request-scoped"):

        @app.get("/")
        def endpoint(value: Annotated[str, Depends(long)]) -> str:
            """
            Return the value provided by the long-lived dependency.

            Parameters:
                value (str): The value resolved from the dependency.

            Returns:
                str: The resolved dependency value.
            """
            return value


def test_overrides_are_isolated_between_concurrent_requests_and_restore() -> None:
    def original() -> str:
        """Return the original string value.

        Returns:
            str: The string "original".
        """
        return "original"

    app = Flasgo()

    @app.get("/")
    async def endpoint(value: Annotated[str, Depends(original)]) -> str:
        """
        Return the resolved dependency value.
        """
        await asyncio.sleep(0)
        return value

    async def run() -> None:
        async def one(value: str) -> str:
            """
            Fetch the root endpoint with the original dependency overridden by the given value.

            Parameters:
                value (str): Value supplied by the dependency override.

            Returns:
                str: Text returned by the root endpoint.
            """
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
        """Provide a resource that records cancellation and closure events."""
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
        """Wait for cancellation before returning the injected resource value.

        Parameters:
            value (str): The resource value supplied by the dependency.

        Returns:
            str: The injected resource value.
        """
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
        """Return the original string value.

        Returns:
            str: The string "original".
        """
        return "original"

    def recursive(value: Annotated[str, Depends(original)]) -> str:
        """Pass through the provided string value.

        Returns:
                str: The provided value.
        """
        return value

    app = Flasgo()

    @app.get("/")
    def endpoint(value: Annotated[str, Depends(original)]) -> str:
        """Pass through the value provided by the dependency.

        Parameters:
                value (str): The value supplied by the dependency.

        Returns:
                str: The supplied value.
        """
        return value

    with app.override_dependencies({original: recursive}):
        assert app.test_client().get("/").status_code == 500
    assert app.test_client().get("/").text == "original"


def test_provider_suppression_cannot_turn_failed_request_into_success() -> None:
    def resource():
        """
        Provide a resource value and suppress ValueError exceptions raised during cleanup.

        Yields:
            str: The string "resource".
        """
        try:
            yield "resource"
        except ValueError:
            return

    app = Flasgo()

    @app.get("/")
    def endpoint(value: Annotated[str, Depends(resource, scope="function")]) -> str:
        """
        Raise a `ValueError` to simulate an endpoint failure.

        Raises:
            ValueError: Always raised to represent a failed request.
        """
        raise ValueError("failure")

    assert app.test_client().get("/").status_code == 500


def test_registered_uncached_providers_do_not_repeat_scope_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    from flasgo import di

    calls = []

    def provider() -> str:
        """Provide a dependency value and record that the provider was called.

        Returns:
            str: The dependency value.
        """
        calls.append("called")
        return "value"

    app = Flasgo()

    @app.get("/")
    def endpoint(
        first: Annotated[str, Depends(provider, use_cache=False)],
        second: Annotated[str, Depends(provider, use_cache=False)],
    ) -> str:
        """
        Concatenate the two provided strings.

        Returns:
                str: The concatenation of `first` and `second`
        """
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
        """Return the original string value.

        Returns:
            str: The string "original".
        """
        return "original"

    def short() -> str:
        """Provide the marker value for a short-lived dependency.

        Returns:
            str: The value ``"short"``.
        """
        calls.append("short")
        return "short"

    def replacement(value: Annotated[str, Depends(short, scope="function")]) -> str:
        """
        Provide the value resolved from the function-scoped dependency.

        Returns:
                str: The resolved dependency value.
        """
        calls.append("replacement")
        return value

    app = Flasgo()

    @app.get("/")
    def endpoint(value: Annotated[str, Depends(original)]) -> str:
        """Pass through the value provided by the dependency.

        Parameters:
                value (str): The value supplied by the dependency.

        Returns:
                str: The supplied value.
        """
        return value

    with app.override_dependencies({original: replacement}):
        assert app.test_client().get("/").status_code == 500
    assert calls == []
    assert app.test_client().get("/").text == "original"


def test_shared_provider_is_validated_separately_for_each_parent_scope() -> None:
    def short() -> str:
        """Provide the short dependency value.

        Returns:
            str: The string ``"short"``.
        """
        return "short"

    def shared(value: Annotated[str, Depends(short, scope="function")]) -> str:
        """
        Provide the injected string value.

        Returns:
                str: The injected value.
        """
        return value

    app = Flasgo()
    with pytest.raises(TypeError, match="request-scoped"):

        @app.get("/")
        def endpoint(
            first: Annotated[str, Depends(shared, scope="function")],
            second: Annotated[str, Depends(shared, scope="request")],
        ) -> str:
            """Concatenate the two dependency-provided strings.

            Returns:
                str: The concatenation of ``first`` and ``second``.
            """
            return first + second

    assert app._routes == []
