import asyncio
from dataclasses import dataclass
from typing import Annotated

import pytest
from flasgo import Depends, EventSourceResponse, Flasgo, NDJSONResponse, ServerSentEvent, StreamingResponse, request


def test_finite_stream_has_no_content_length_and_keeps_request_context() -> None:
    app = Flasgo()

    @app.get("/")
    def endpoint() -> StreamingResponse:
        """
        Create a streaming response containing the request path followed by a completion marker.

        Returns:
            StreamingResponse: The streaming response.
        """

        async def content():
            yield request.path
            yield b"done"

        return StreamingResponse(content())

    response = app.test_client().get("/")
    assert response.body == b"/done"
    assert "content-length" not in response.headers
    assert "no-store" in response.headers["cache-control"]
    assert app.test_client().head("/").body == b""


def test_disconnect_closes_stream_and_dependencies_without_background_work() -> None:
    events = []

    async def resource():
        try:
            yield "first"
        finally:
            events.append("dependency-closed")

    app = Flasgo()

    @app.get("/")
    def endpoint(value: Annotated[str, Depends(resource)]) -> StreamingResponse:
        """
        Create a streaming response that emits the supplied value and registers background work.

        Parameters:
                value (str): The value yielded by the response stream.

        Returns:
                StreamingResponse: A response that streams the value.
        """

        async def content():
            try:
                yield value
                await asyncio.Event().wait()
            finally:
                events.append("stream-closed")

        response = StreamingResponse(content())
        response.add_task(events.append, "background")
        return response

    async def run() -> None:
        async with app.test_client().astream("GET", "/") as response:
            assert response.status_code == 200
            assert await anext(response.iter_bytes()) == b"first"
        assert events == ["stream-closed", "dependency-closed"]

    asyncio.run(run())


def test_sse_heartbeat_and_safe_json_framing() -> None:
    app = Flasgo()

    @app.get("/")
    def endpoint() -> EventSourceResponse:
        """
        Create a server-sent events response with a heartbeat and a multiline update event.

        Returns:
            EventSourceResponse: The configured streaming response.
        """

        async def events():
            await asyncio.sleep(0.03)
            yield ServerSentEvent({"text": "a\nb"}, event="update", id="1", retry=1000)

        return EventSourceResponse(events(), heartbeat=0.01)

    response = app.test_client().get("/")
    assert ": ping\n\n" in response.text
    assert 'data: {"text":"a\\nb"}\n\n' in response.text
    assert "event: update\nid: 1\nretry: 1000\n" in response.text
    assert response.headers["x-accel-buffering"] == "no"


def test_annotated_sse_and_text_responses_use_the_correct_openapi_media_types() -> None:
    app = Flasgo()

    @app.get("/events")
    def events() -> Annotated[EventSourceResponse, "server-sent events"]:
        raise AssertionError("The endpoint is only used to generate OpenAPI.")

    @app.get("/text")
    def text() -> Annotated[str, "plain text"]:
        return "response"

    paths = app.openapi_spec()["paths"]
    assert paths["/events"]["get"]["responses"]["200"]["content"] == {"text/event-stream": {"schema": {"type": "string"}}}
    assert paths["/text"]["get"]["responses"]["200"]["content"] == {"text/plain": {"schema": {"type": "string"}}}


@pytest.mark.parametrize("field", ["event", "id"])
def test_sse_rejects_control_character_injection(field: str) -> None:
    with pytest.raises(ValueError):
        if field == "event":
            ServerSentEvent("test", event="x\ndata: injected")
        else:
            ServerSentEvent("test", id="x\ndata: injected")


def test_ndjson_contract_filters_each_item() -> None:
    @dataclass
    class Item:
        id: int

    app = Flasgo()

    @app.get("/")
    def endpoint() -> NDJSONResponse:
        async def items():
            yield {"id": 1, "secret": True}
            yield {"id": 2}

        return NDJSONResponse(items(), item_model=Item)

    assert app.test_client().get("/").body == b'{"id":1}\n{"id":2}\n'
    content = app.openapi_spec()["paths"]["/"]["get"]["responses"]["200"]["content"]
    assert "application/x-ndjson" in content


def test_stream_limit_failure_is_incomplete_and_closes_source() -> None:
    closed = []
    app = Flasgo()

    @app.get("/")
    def endpoint() -> StreamingResponse:
        """
        Create a streaming response that rejects chunks larger than two bytes.

        Returns:
            StreamingResponse: A response streaming an oversized chunk for testing
                chunk-size enforcement.
        """

        async def content():
            try:
                yield b"oversized"
            finally:
                closed.append(True)

        return StreamingResponse(content(), max_chunk_bytes=2)

    async def run() -> None:
        async with app.test_client().astream("GET", "/") as response:
            with pytest.raises(RuntimeError, match="incomplete"):
                await anext(response.iter_bytes())
        assert closed == [True]

    asyncio.run(run())


def test_stream_idle_timeout_closes_source() -> None:
    closed = []
    app = Flasgo()

    @app.get("/")
    def endpoint() -> StreamingResponse:
        """
        Create a streaming response whose source remains idle until the configured timeout and records when the source closes.
        """

        async def content():
            try:
                await asyncio.Event().wait()
                yield b"unreachable"
            finally:
                closed.append(True)

        return StreamingResponse(content(), idle_timeout=0.01)

    async def run() -> None:
        async with app.test_client().astream("GET", "/") as response:
            with pytest.raises(RuntimeError, match="incomplete"):
                await anext(response.iter_bytes())
        assert closed == [True]

    asyncio.run(run())


def test_stream_backpressure_and_send_timeout_bound_production() -> None:
    produced = []
    closed = []
    app = Flasgo()

    @app.get("/")
    def endpoint() -> StreamingResponse:
        async def content():
            """
            Yield up to 1,000 byte chunks while recording production and closure events.
            """
            try:
                for index in range(1000):
                    produced.append(index)
                    yield b"chunk"
            finally:
                closed.append(True)

        return StreamingResponse(content(), send_timeout=0.03)

    async def run() -> None:
        async with app.test_client().astream("GET", "/") as response:
            await asyncio.sleep(0.06)
            assert len(produced) <= 2
            assert closed == [True]
            with pytest.raises(RuntimeError, match="incomplete"):
                async for _ in response.iter_bytes():
                    pass

    asyncio.run(run())


def test_head_closes_unstarted_source_once() -> None:
    class Source:
        closed = 0
        iterated = False

        def __aiter__(self):
            """Provide the asynchronous iterator interface for this stream.

            Returns:
                The stream itself.
            """
            return self

        async def __anext__(self):
            self.iterated = True
            return {"id": 1}

        async def aclose(self):
            """Record that the resource has been closed."""
            self.closed += 1

    source = Source()
    app = Flasgo()
    app.get("/")(lambda: NDJSONResponse(source))
    assert app.test_client().head("/").body == b""
    assert source.closed == 1
    assert not source.iterated


def test_middleware_replacing_stream_closes_original_source() -> None:
    from flasgo import Response

    class Source:
        closed = 0

        def __aiter__(self):
            """Provide the asynchronous iterator interface for this stream.

            Returns:
                The stream itself.
            """
            return self

        async def __anext__(self):
            return b"data"

        async def aclose(self):
            """Record that the resource has been closed."""
            self.closed += 1

    source = Source()
    app = Flasgo()
    app.get("/")(lambda: StreamingResponse(source))
    app.after_request(lambda req, response: Response.text("replaced"))
    assert app.test_client().get("/").text == "replaced"
    assert source.closed == 1


def test_background_tasks_do_not_retain_request_context() -> None:
    events = []
    app = Flasgo()

    @app.get("/")
    def endpoint() -> StreamingResponse:
        async def content():
            yield b"done"

        response = StreamingResponse(content())

        def background():
            with pytest.raises(RuntimeError, match="No active request"):
                _ = request.path
            events.append("complete")

        response.add_task(background)
        return response

    assert app.test_client().get("/").body == b"done"
    assert events == ["complete"]
