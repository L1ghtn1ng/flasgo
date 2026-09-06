"""Local ASGI metrics benchmark: python -m benchmarks.metrics --requests 500.

No sockets or external backends are used. Results measure framework overhead,
not production capacity. Run the same script against a baseline checkout to
compare enabled/disabled dispatch, streaming, and scrape costs.
"""

import argparse
import asyncio
import json
import logging
import platform
import statistics
import time
from collections.abc import AsyncIterator
from typing import Any

from flasgo import Flasgo, StreamingResponse

_TOKEN = "benchmark-only-" + "m" * 32
_LIFESPAN_TIMEOUT_SECONDS = 10


def scope(path: str) -> dict[str, Any]:
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [(b"host", b"localhost"), (b"authorization", f"Bearer {_TOKEN}".encode())],
        "client": ("127.0.0.1", 50000),
        "server": ("localhost", 80),
    }


async def measure(enabled: bool, streaming: bool, routes: int, requests: int, rounds: int) -> dict[str, Any]:
    app = Flasgo(settings={"METRICS_ENABLED": enabled, "METRICS_BEARER_TOKEN": _TOKEN, "CSRF_ENABLED": False})

    async def chunks() -> AsyncIterator[bytes]:
        for _ in range(16):
            yield b"x" * 1024

    async def endpoint():
        return StreamingResponse(chunks()) if streaming else b"x" * 1024

    for index in range(routes):
        app.add_route(f"/route/{index}", endpoint, methods={"GET"}, name=f"route_{index}")

    async def invoke(path: str) -> int:
        received = False
        size = 0

        async def receive():
            nonlocal received
            if not received:
                received = True
                return {"type": "http.request", "body": b"", "more_body": False}
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

        async def send(message):
            nonlocal size
            size += len(message.get("body", b""))

        await app(scope(path), receive, send)
        return size

    events = asyncio.Queue()
    ready: asyncio.Future[None] = asyncio.get_running_loop().create_future()

    async def lifespan_send(message):
        if message["type"] == "lifespan.startup.complete":
            ready.set_result(None)
        elif message["type"] == "lifespan.startup.failed":
            ready.set_exception(RuntimeError(message.get("message", "Application startup failed.")))

    lifespan = asyncio.create_task(app({"type": "lifespan"}, events.get, lifespan_send))
    started_up = False
    try:
        await events.put({"type": "lifespan.startup"})
        await asyncio.wait_for(ready, timeout=_LIFESPAN_TIMEOUT_SECONDS)
        started_up = True
        for index in range(routes):
            await invoke(f"/route/{index}")
        timings = []
        for _ in range(rounds):
            started = time.perf_counter()
            for index in range(requests):
                await invoke(f"/route/{index % routes}")
            timings.append((time.perf_counter() - started) * 1_000_000 / requests)
        result = {"enabled": enabled, "streaming": streaming, "routes": routes, "request_us": round(statistics.median(timings), 2)}
        if enabled:
            scrapes = []
            size = 0
            for _ in range(5):
                started = time.perf_counter()
                size = await invoke("/metrics")
                scrapes.append((time.perf_counter() - started) * 1000)
            result.update(scrape_ms=round(statistics.median(scrapes), 2), scrape_bytes=size)
        return result
    finally:
        if started_up:
            await events.put({"type": "lifespan.shutdown"})
            await asyncio.wait_for(lifespan, timeout=_LIFESPAN_TIMEOUT_SECONDS)
        else:
            lifespan.cancel()
            await asyncio.gather(lifespan, return_exceptions=True)


async def main(requests: int, rounds: int) -> None:
    results = []
    for routes in (1, 100):
        for streaming in (False, True):
            results.extend([await measure(enabled, streaming, routes, requests, rounds) for enabled in (False, True)])
    print(json.dumps({"python": platform.python_version(), "requests": requests, "rounds": rounds, "results": results}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requests", type=int, default=500)
    parser.add_argument("--rounds", type=int, default=3)
    args = parser.parse_args()
    if args.requests <= 0 or args.rounds <= 0:
        parser.error("requests and rounds must be positive")
    logging.disable(logging.CRITICAL)
    asyncio.run(main(args.requests, args.rounds))
