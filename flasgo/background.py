from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .logging import log_event


@dataclass(slots=True)
class _BackgroundTask:
    func: Callable[..., Any]
    args: tuple[Any, ...]
    kwargs: dict[str, Any]
    request_id: str | None


class BackgroundTasks:
    """Best-effort tasks run after a successful buffered HTTP response."""

    def __init__(self) -> None:
        self._tasks: list[_BackgroundTask] = []
        self._observer: Callable[[str], None] | None = None

    def add_task(
        self,
        func: Callable[..., Any],
        /,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        self._tasks.append(_BackgroundTask(func, args, kwargs, None))

    def bind_request_id(self, request_id: str) -> None:
        for task in self._tasks:
            if task.request_id is None:
                task.request_id = request_id

    def bind_observer(self, observer: Callable[[str], None]) -> None:
        self._observer = observer

    async def __call__(self) -> None:
        logger = logging.getLogger("flasgo.background")
        for task in self._tasks:
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
            except Exception:
                log_event(logger, logging.ERROR, "background-task-failed", request_id=task.request_id)
                logger.debug("background task exception", exc_info=True)
                if self._observer is not None:
                    self._observer("failure")
