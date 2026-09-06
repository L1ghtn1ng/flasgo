from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any


class AsyncTestStream:
    """Incremental test response. Leaving the context disconnects the client."""

    def __init__(self) -> None:
        self.status_code = 0
        self.headers: dict[str, str] = {}
        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=1)
        self.started = asyncio.Event()
        self.disconnected = asyncio.Event()
        self.task: asyncio.Task[Any] | None = None

    async def send(self, message: dict[str, Any]) -> None:
        """
        Process an ASGI response message for the test stream.

        Parameters:
                message (dict[str, Any]): Response-start or response-body message to process.

        Raises:
                ConnectionError: If the client has disconnected.
        """
        if self.disconnected.is_set():
            raise ConnectionError("Test client disconnected.")
        if message["type"] == "http.response.start":
            self.status_code = message["status"]
            for key, value in message.get("headers", []):
                name, text = key.decode("latin-1"), value.decode("latin-1")
                self.headers[name] = self.headers[name] + "\n" + text if name in self.headers else text
            self.started.set()
        elif message["type"] == "http.response.body":
            await self.queue.put(message)

    async def wait_started(self) -> None:
        """
        Wait until the application starts sending a response.

        Raises:
            RuntimeError: If the application finishes without starting a response.
        """
        assert self.task is not None
        waiter = asyncio.create_task(self.started.wait())
        try:
            await asyncio.wait({waiter, self.task}, return_when=asyncio.FIRST_COMPLETED)
            if not self.started.is_set():
                await self.task
                raise RuntimeError("Application did not start a response.")
        finally:
            waiter.cancel()
            await asyncio.gather(waiter, return_exceptions=True)

    async def iter_bytes(self) -> AsyncIterator[bytes]:
        """
        Iterate over response body chunks as they become available.

        Yields:
            bytes: A chunk of response body data.

        Raises:
            RuntimeError: If the application ends before the response is complete.
        """
        assert self.task is not None
        while True:
            if not self.queue.empty():
                message = self.queue.get_nowait()
            else:
                waiter = asyncio.create_task(self.queue.get())
                try:
                    done, _ = await asyncio.wait({waiter, self.task}, return_when=asyncio.FIRST_COMPLETED)
                    if waiter not in done:
                        await self.task
                        raise RuntimeError("Application ended an incomplete response.")
                    message = waiter.result()
                finally:
                    waiter.cancel()
                    await asyncio.gather(waiter, return_exceptions=True)
            if message.get("body"):
                yield bytes(message["body"])
            if not message.get("more_body", False):
                return

    async def aclose(self) -> None:
        """
        Close the stream and allow the associated application task to finish.

        The application task is cancelled if it does not finish within one second.
        """
        self.disconnected.set()
        if self.task is not None:
            try:
                async with asyncio.timeout(1):
                    await asyncio.shield(self.task)
            except TimeoutError:
                self.task.cancel()
                await asyncio.gather(self.task, return_exceptions=True)
