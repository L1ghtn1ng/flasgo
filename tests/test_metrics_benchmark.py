import asyncio
from collections.abc import AsyncGenerator

import pytest
from benchmarks import metrics
from flasgo import Flasgo


@pytest.mark.parametrize("stalled", [False, True])
def test_benchmark_startup_failure_is_bounded_and_cleans_up(monkeypatch: pytest.MonkeyPatch, stalled: bool) -> None:
    """Verify failed or stalled benchmark startup reports an error and leaves no lifespan task."""

    async def run() -> None:
        """Inject the startup failure mode and check bounded waiting and generator cleanup."""
        app = Flasgo()
        closed = asyncio.Event()

        @app.lifespan
        async def startup(current: Flasgo) -> AsyncGenerator[None]:
            """Fail or stall before startup completion and record lifespan generator cleanup."""
            try:
                if stalled:
                    await asyncio.Event().wait()
                raise RuntimeError("Startup failed")
                yield
            finally:
                closed.set()

        monkeypatch.setattr(metrics, "Flasgo", lambda **kwargs: app)
        monkeypatch.setattr(metrics, "_LIFESPAN_TIMEOUT_SECONDS", 0.01)
        error = TimeoutError if stalled else RuntimeError
        match = None if stalled else "Application startup failed; see logs."
        with pytest.raises(error, match=match):
            await asyncio.wait_for(metrics.measure(False, False, 1, 1, 1), timeout=1)
        assert closed.is_set()
        assert not [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]

    asyncio.run(run())
