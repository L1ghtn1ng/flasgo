from __future__ import annotations

import asyncio
import inspect
import logging
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .logging import log_event

if TYPE_CHECKING:
    from .metrics import Metrics


@dataclass(slots=True)
class _BackgroundTask:
    func: Callable[..., Any]
    args: tuple[Any, ...]
    kwargs: dict[str, Any]
    request_id: str | None


_observation: ContextVar[_BackgroundObservation | None] = ContextVar("flasgo_background_observation", default=None)


class _BackgroundObservation:
    """Per-response accounting, including when a task container is reused concurrently."""

    def __init__(self, owner: BackgroundTasks, metrics: Metrics) -> None:
        """Account for the current task list while the owner lock is held."""
        self.owner = owner
        self.metrics = metrics
        self.pending = len(owner._tasks)
        self.closed = False
        metrics.background_pending.inc(self.pending)

    def added(self) -> None:
        """Include newly attached work in this observation while the owner lock is held."""
        self.pending += 1
        self.metrics.background_pending.inc()

    def close(self) -> None:
        """Release remaining pending tasks as skipped exactly once."""
        with self.owner._lock:
            if not self.closed:
                self.closed = True
                self.owner._observations.discard(self)
                self.metrics.background_pending.dec(self.pending)
                self.metrics.background_tasks.labels(outcome="skipped").inc(self.pending)
                self.pending = 0

    @contextmanager
    def activate(self) -> Iterator[None]:
        """Bind this response observation to task execution without sharing it across requests."""
        token = _observation.set(self)
        try:
            yield
        finally:
            _observation.reset(token)


class BackgroundTasks:
    """Best-effort tasks run after a successful buffered HTTP response."""

    def __init__(self) -> None:
        """Create a reusable task container with synchronized observation registration."""
        self._tasks: list[_BackgroundTask] = []
        self._observer: Callable[[str], None] | None = None
        self._observations: set[_BackgroundObservation] = set()
        self._lock = threading.Lock()

    def add_task(
        self,
        func: Callable[..., Any],
        /,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """Append work and update every active response observation under the owner lock."""
        with self._lock:
            self._tasks.append(_BackgroundTask(func, args, kwargs, None))
            for observation in self._observations:
                observation.added()

    def _observe(self, metrics: Metrics) -> _BackgroundObservation:
        """Create a separate metrics observation for one response execution."""
        with self._lock:
            observation = _BackgroundObservation(self, metrics)
            self._observations.add(observation)
            return observation

    def bind_request_id(self, request_id: str) -> None:
        """Fill missing task request IDs without replacing IDs already bound to the tasks."""
        for task in self._tasks:
            if task.request_id is None:
                task.request_id = request_id

    def bind_observer(self, observer: Callable[[str], None]) -> None:
        """Set the legacy callback for successful and failed task calls."""
        self._observer = observer

    async def __call__(self) -> None:
        """Run tasks using the active observation belonging to this container and release it on exit."""
        logger = logging.getLogger("flasgo.background")
        observation = _observation.get()
        if observation is not None and (observation.owner is not self or observation.closed):
            observation = None
        try:
            await self._run(logger, observation)
        finally:
            if observation is not None:
                observation.close()

    async def _run(self, logger: logging.Logger, observation: _BackgroundObservation | None) -> None:
        """Run tasks sequentially, measuring awaited calls and preserving best-effort failure handling."""
        for task in self._tasks:
            metrics = observation.metrics if observation is not None else None
            if observation is not None:
                with self._lock:
                    observation.pending -= 1
            if metrics is not None:
                metrics.background_pending.dec()
                metrics.background_active.inc()
            started = time.perf_counter() if metrics is not None else 0
            outcome = "success"
            try:
                if inspect.iscoroutinefunction(task.func):
                    await task.func(*task.args, **task.kwargs)
                else:
                    result = await asyncio.to_thread(task.func, *task.args, **task.kwargs)
                    if inspect.isawaitable(result):
                        await result
                log_event(logger, logging.INFO, "background-task-complete", request_id=task.request_id)
                if self._observer is not None:
                    self._observer("success")
            except asyncio.CancelledError:
                outcome = "cancelled"
                raise
            except Exception:
                outcome = "failure"
                log_event(logger, logging.ERROR, "background-task-failed", request_id=task.request_id)
                logger.debug("background task exception", exc_info=True)
                if self._observer is not None:
                    self._observer("failure")
            finally:
                if metrics is not None:
                    metrics.background_active.dec()
                    metrics.background_duration.observe(time.perf_counter() - started)
                    metrics.observe_background(outcome)
