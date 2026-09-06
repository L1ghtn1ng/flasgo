import asyncio
import subprocess
import sys
from typing import Annotated

import pytest
from flasgo import Depends
from flasgo.di import resolve_endpoint_arguments
from flasgo.params import compile_endpoint_plan
from flasgo.request import Request


@pytest.mark.parametrize("scope", [{}, {"flasgo.dependencies": None}, {"flasgo.dependencies": {}}])
def test_missing_or_invalid_dependency_context_has_clear_runtime_error(scope: dict) -> None:
    def provider() -> str:
        """Provide the value used to resolve the test dependency.

        Returns:
            str: The dependency value.
        """
        return "value"

    def endpoint(value: Annotated[str, Depends(provider)]) -> str:
        """
        Return the dependency-provided string.

        Returns:
                str: The injected dependency value
        """
        return value

    async def receive() -> dict:
        """
        Create an empty HTTP request message for an ASGI-compatible receiver.

        Returns:
                dict: An HTTP request message with an empty body.
        """
        return {"type": "http.request", "body": b""}

    request = Request(scope={"type": "http", "path": "/", **scope}, receive=receive)
    with pytest.raises(RuntimeError, match="requires a DependencyContext"):
        asyncio.run(resolve_endpoint_arguments(compile_endpoint_plan(endpoint, "/"), request, {}))


def test_dependency_context_validation_survives_optimized_python() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-O",
            "-c",
            """
import asyncio
from flasgo import Depends
from flasgo.di import resolve_endpoint_arguments
from flasgo.params import compile_endpoint_plan
from flasgo.request import Request

async def receive():
    return {"type": "http.request", "body": b""}

plan = compile_endpoint_plan(lambda: None, "/", dependencies=[Depends(lambda: None)])
for scope in ({}, {"flasgo.dependencies": None}, {"flasgo.dependencies": {}}):
    request = Request(scope={"type": "http", "path": "/", **scope}, receive=receive)
    try:
        asyncio.run(resolve_endpoint_arguments(plan, request, {}))
    except RuntimeError as error:
        if "requires a DependencyContext" not in str(error):
            raise
    else:
        raise RuntimeError("Invalid dependency context was accepted")
""",
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr
