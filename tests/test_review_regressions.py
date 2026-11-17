"""Regression tests for defects found in the November 2026 bug and security review."""

import asyncio
import functools
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Annotated, Any, cast

import pytest

import flasgo.server as server_module
from flasgo import (
    Blueprint,
    Body,
    Depends,
    Flasgo,
    Form,
    IsAuthenticated,
    Request,
    StreamingResponse,
    User,
    WebSocket,
    WebSocketHandshakeError,
    abort,
    bearer_token_backend,
    jsonify,
)
from flasgo._request import MAX_MULTIPART_PART_HEADER_BYTES, UploadedFile, _parse_content_type, _parse_multipart_form
from flasgo.testing import TestClient


def _multipart(*parts: bytes, boundary: bytes = b"b") -> bytes:
    """Join raw part sections (headers, blank line, payload) into a multipart body."""
    return b"".join(b"--" + boundary + b"\r\n" + part + b"\r\n" for part in parts) + b"--" + boundary + b"--\r\n"


def _multipart_headers(boundary: str = "b") -> dict[str, str]:
    return {"content-type": f"multipart/form-data; boundary={boundary}"}


def _form_app() -> Flasgo:
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.post("/form", public=True)
    async def form(request: Request) -> dict[str, object]:
        data = await request.form()
        return {
            "fields": {key: data.getlist(key) for key in data},
            "files": {key: [(item.filename, item.body.decode("latin-1")) for item in items] for key, items in data.files.items()},
        }

    return app


# Streaming completion -------------------------------------------------------------------------------------------


async def _call_like_uvicorn(app: Flasgo, path: str) -> list[dict[str, Any]]:
    """Drive one GET the way uvicorn's h11 protocol does: ``receive()`` reports a disconnect once the response is done."""
    sent: list[dict[str, Any]] = []
    complete = asyncio.Event()
    delivered_request = False

    async def receive() -> dict[str, Any]:
        nonlocal delivered_request
        if not delivered_request:
            delivered_request = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await complete.wait()
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)
        if message["type"] == "http.response.body" and not message.get("more_body", False):
            complete.set()

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [(b"host", b"localhost")],
        "client": ("127.0.0.1", 50000),
        "server": ("localhost", 80),
    }
    await app(scope, receive, send)
    return sent


def test_completed_stream_is_not_treated_as_a_client_disconnect() -> None:
    events: list[str] = []
    app = Flasgo()

    async def transaction():
        try:
            yield "tx"
        except BaseException as exc:
            events.append(f"rollback:{type(exc).__name__}")
            raise
        else:
            events.append("commit")

    @app.get("/stream", public=True)
    def stream(tx: Annotated[str, Depends(transaction)]) -> StreamingResponse:
        async def content():
            yield "a"
            yield "b"

        response = StreamingResponse(content(), content_type="text/plain")
        response.add_task(events.append, "background")
        return response

    sent = asyncio.run(_call_like_uvicorn(app, "/stream"))

    assert b"".join(message.get("body", b"") for message in sent if message["type"] == "http.response.body") == b"ab"
    assert events == ["commit", "background"]


# Multipart and Content-Type parsing -----------------------------------------------------------------------------


def test_header_parameter_runs_parse_in_linear_time() -> None:
    semicolons = ";" * (MAX_MULTIPART_PART_HEADER_BYTES - 64)
    part = f'Content-Disposition: form-data; name="a"{semicolons}\r\n\r\nx'.encode()
    body = _multipart(*([part] * 60))  # ~1 MiB of parameter separators; the stdlib parser took hours on this
    started = time.perf_counter()
    form = _parse_multipart_form(body, "b", max_parts=1_000, max_fields=1_000)
    assert form.getlist("a") == ["x"] * 60
    assert _parse_content_type("application/json" + ";" * 15_000) == ("application/json", {})
    assert time.perf_counter() - started < 2


def test_oversized_part_headers_are_rejected() -> None:
    padding = "x" * MAX_MULTIPART_PART_HEADER_BYTES
    body = _multipart(f'Content-Disposition: form-data; name="a"; pad="{padding}"\r\n\r\nx'.encode())
    response = TestClient(_form_app()).post("/form", body=body, headers=_multipart_headers())
    assert response.status_code == 413


def test_nested_multipart_is_rejected_before_its_parts_are_parsed() -> None:
    inner = b"--x\r\n\r\n" * 50_000 + b"--x--"
    body = _multipart(b'Content-Disposition: form-data; name="a"\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n' + inner)
    app = Flasgo(settings={"CSRF_ENABLED": False, "MAX_MULTIPART_PARTS": 10})

    @app.post("/form", public=True)
    async def form(request: Request) -> str:
        await request.form()
        return "unreachable"

    started = time.perf_counter()
    response = TestClient(app).post("/form", body=body, headers=_multipart_headers())
    assert response.status_code == 400
    assert "Nested multipart" in response.text
    assert time.perf_counter() - started < 1


@pytest.mark.parametrize("content_type", ["application/json; a*", "application/json; a=(" + "(" * 8_000])
def test_malformed_content_type_parameters_do_not_cause_server_errors(content_type: str) -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.post("/body", public=True)
    def body(data: Annotated[dict[str, int], Body()]) -> dict[str, int]:
        return data

    response = TestClient(app).post("/body", body=b'{"a": 1}', headers={"content-type": content_type})
    assert response.status_code == 200
    assert response.json() == {"a": 1}


def test_malformed_part_header_parameter_does_not_cause_server_error() -> None:
    body = _multipart(b'Content-Disposition: form-data; name="a";bogus*\r\n\r\nvalue')
    response = TestClient(_form_app()).post("/form", body=body, headers=_multipart_headers())
    assert response.status_code == 200
    assert response.json() == {"fields": {"a": ["value"]}, "files": {}}


def test_multipart_parser_keeps_supported_encodings() -> None:
    body = _multipart(
        b'Content-Disposition: form-data; name="doc"; filename="C:\\Users\\me\\report.pdf"\r\nContent-Type: application/pdf\r\n\r\nPDF',
        b'Content-Disposition: form-data; name="intl"; filename="x.txt"; filename*=UTF-8\'\'%C3%A9t%C3%A9.txt\r\n\r\n1',
        b'Content-Disposition: form-data; name="b64"\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=',
        b'Content-Disposition: form-data; name="latin"\r\nContent-Type: text/plain; charset="iso-8859-1"\r\n\r\n\xe9',
        b'Content-Disposition: form-data; name="quoted"; filename="say \\"hi\\".txt"\r\n\r\nq',
        b'Content-Disposition: form-data; name="empty"\r\n\r\n',
        b'Content-Disposition: attachment; name="ignored"\r\n\r\nskip',
    )
    response = TestClient(_form_app()).post("/form", body=body, headers=_multipart_headers())
    assert response.status_code == 200
    assert response.json() == {
        "fields": {"b64": ["hello"], "latin": ["\u00e9"], "empty": [""]},
        "files": {"doc": [["report.pdf", "PDF"]], "intl": [["\u00e9t\u00e9.txt", "1"]], "quoted": [['say "hi".txt', "q"]]},
    }


def test_untouched_optional_file_input_binds_as_no_file() -> None:
    @dataclass
    class Upload:
        title: str
        doc: UploadedFile | None = None

    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.post("/upload", public=True)
    def upload(payload: Annotated[Upload, Form()]) -> dict[str, object]:
        return {"title": payload.title, "doc": payload.doc.filename if payload.doc else None}

    body = _multipart(
        b'Content-Disposition: form-data; name="title"\r\n\r\nhello',
        b'Content-Disposition: form-data; name="doc"; filename=""\r\nContent-Type: application/octet-stream\r\n\r\n',
    )
    response = TestClient(app).post("/upload", body=body, headers=_multipart_headers())
    assert response.status_code == 200
    assert response.json() == {"title": "hello", "doc": None}


def test_empty_urlencoded_body_is_validated_as_an_empty_form() -> None:
    @dataclass
    class Preferences:
        newsletter: bool = False
        tags: list[str] | None = None

    @dataclass
    class Required:
        name: str

    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.post("/prefs", public=True)
    def prefs(payload: Annotated[Preferences, Form()]) -> dict[str, object]:
        return {"newsletter": payload.newsletter, "tags": payload.tags}

    @app.post("/required", public=True)
    def required(payload: Annotated[Required, Form()]) -> str:
        return payload.name

    client = TestClient(app)
    headers = {"content-type": "application/x-www-form-urlencoded"}
    assert client.post("/prefs", body=b"", headers=headers).json() == {"newsletter": False, "tags": None}
    missing = client.post("/required", body=b"", headers=headers)
    assert missing.status_code == 422
    assert cast(dict[str, Any], missing.json())["errors"][0]["location"] == ["form", "name"]
    assert client.post("/required", body=b"").status_code == 422


# Authorization through wrapping decorators ----------------------------------------------------------------------


def _audit[T: Callable[..., Any]](endpoint: T) -> T:
    @functools.wraps(endpoint)
    def wrapper(**kwargs: Any) -> Any:
        return endpoint(**kwargs)

    return cast(T, wrapper)


def _auth_app() -> Flasgo:
    app = Flasgo(settings={"CSRF_ENABLED": False})
    app.register_auth_backend(
        "default", bearer_token_backend(lambda token: User(id="alice", is_authenticated=True) if token == "good" else None)
    )
    return app


def test_authorize_survives_wrapping_decorators_in_either_order() -> None:
    app = _auth_app()

    @app.get("/route-wrapper-authorize")
    @_audit
    @app.authorize()
    def first() -> str:
        return "first"

    @app.authorize()
    @_audit
    @app.get("/authorize-wrapper-route")
    def second() -> str:
        return "second"

    client = TestClient(app)
    for path in ("/route-wrapper-authorize", "/authorize-wrapper-route"):
        assert client.get(path).status_code == 401
        assert client.get(path, headers={"authorization": "Bearer good"}).status_code == 200
    assert app.openapi_spec()["paths"]["/route-wrapper-authorize"]["get"].get("security")


def test_authorizing_a_routed_wrapper_leaves_the_public_original_public() -> None:
    app = _auth_app()

    def view() -> str:
        return "view"

    app.add_route("/public", view, public=True)
    app.add_route("/admin", app.authorize()(_audit(view)))

    client = TestClient(app)
    assert client.get("/public").status_code == 200
    assert client.get("/admin").status_code == 401


def test_protected_blueprint_does_not_protect_the_same_function_elsewhere() -> None:
    app = _auth_app()

    def view() -> str:
        return "view"

    app.add_route("/view", view, public=True)
    protected = Blueprint("protected", url_prefix="/protected", permissions=[IsAuthenticated()])
    protected.add_route("/view", view)
    app.register_blueprint(protected)

    client = TestClient(app)
    assert client.get("/view").status_code == 200
    assert client.get("/protected/view").status_code == 401


# Cross-site lockout ---------------------------------------------------------------------------------------------


def test_csrf_failures_do_not_lock_out_valid_credentials() -> None:
    app = Flasgo(settings={"SECURITY_FAILURE_RATE_LIMIT": 2})
    app.register_auth_backend(
        "default", bearer_token_backend(lambda token: User(id="alice", is_authenticated=True) if token == "good" else None)
    )

    @app.get("/account")
    @app.authorize()
    def account() -> str:
        return "account"

    client = TestClient(app)
    cross_site = {"origin": "https://evil.example"}
    assert [client.post("/anything", headers=cross_site).status_code for _ in range(3)] == [403, 403, 429]
    assert client.get("/account", headers={"authorization": "Bearer good"}).status_code == 200


# Error responses and serialization ------------------------------------------------------------------------------


@pytest.mark.parametrize(("status", "expected"), [(204, 204), (304, 304), (700, 500), (99, 500)])
def test_abort_with_bodiless_or_invalid_status_still_responds(status: int, expected: int) -> None:
    app = Flasgo()

    @app.get("/", public=True)
    def endpoint() -> str:
        abort(status)

    response = TestClient(app).get("/")
    assert response.status_code == expected
    if expected != 500:
        assert response.body == b""
    assert "x-content-type-options" in response.headers


def test_dependency_results_are_injected_as_returned() -> None:
    shared: dict[str, int] = {"hits": 0}

    class Shout:
        def __call__(self, text: str) -> str:
            return text.upper()

    def get_state() -> dict[str, int]:
        return shared

    def get_hasher() -> Callable[[str], str]:
        return Shout()

    app = Flasgo()

    @app.get("/", public=True)
    def endpoint(
        state: Annotated[dict[str, int], Depends(get_state)],
        hasher: Annotated[Callable[[str], str], Depends(get_hasher)],
    ) -> dict[str, object]:
        state["hits"] += 1
        return {"same": state is shared, "shout": hasher("hi")}

    client = TestClient(app)
    assert client.get("/").json() == {"same": True, "shout": "HI"}
    assert shared == {"hits": 1}


@dataclass
class _Cat:
    name: str


@dataclass
class _Dog:
    name: str
    breed: str


def test_union_response_model_projects_through_the_values_own_class() -> None:
    app = Flasgo()

    @app.get("/dog", public=True, response_model=_Cat | _Dog)
    def dog() -> _Cat | _Dog:
        return _Dog("rex", "lab")

    @app.get("/cat", public=True, response_model=_Cat | _Dog)
    def cat() -> _Cat | _Dog:
        return _Cat("tom")

    client = TestClient(app)
    assert client.get("/dog").json() == {"name": "rex", "breed": "lab"}
    assert client.get("/cat").json() == {"name": "tom"}


@dataclass
class _Row:
    id: int
    label: str
    tags: list[str] = field(default_factory=list)


def test_large_response_model_is_not_limited_by_request_validation_work() -> None:
    app = Flasgo(settings={"MAX_VALIDATION_DEPTH": 8})

    @app.get("/rows", public=True, response_model=list[_Row])
    def rows() -> list[_Row]:
        return [_Row(index, f"row-{index}") for index in range(5_000)]

    response = TestClient(app).get("/rows")
    assert response.status_code == 200
    assert len(cast(list[Any], response.json())) == 5_000


def test_containers_of_dataclasses_serialize_like_a_bare_dataclass() -> None:
    app = Flasgo()

    @app.get("/list", public=True)
    def many() -> list[_Cat]:
        return [_Cat("tom")]

    @app.get("/mapping", public=True)
    def mapping() -> dict[str, _Cat]:
        return {"cat": _Cat("tom")}

    @app.get("/jsonify", public=True)
    def jsonified() -> Any:
        return jsonify([_Cat("tom")])

    client = TestClient(app)
    assert client.get("/list").json() == [{"name": "tom"}]
    assert client.get("/mapping").json() == {"cat": {"name": "tom"}}
    assert client.get("/jsonify").json() == [{"name": "tom"}]


# Development server and test client -----------------------------------------------------------------------------


class _FakeWindowsChild:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def poll(self) -> None:
        return None

    def send_signal(self, sig: int) -> None:
        raise ValueError(f"Unsupported signal: {sig}")

    def terminate(self) -> None:
        self.calls.append("terminate")

    def kill(self) -> None:
        self.calls.append("kill")

    def wait(self, timeout: float | None = None) -> int:
        self.calls.append("wait")
        return 0


def test_reload_child_stops_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server_module.os, "name", "nt")
    child = _FakeWindowsChild()
    server_module._stop_reload_child(cast(Any, child))
    assert child.calls == ["terminate", "wait"]


def test_websocket_origin_header_is_not_overridden_by_the_default() -> None:
    app = Flasgo()

    @app.websocket("/ws", public=True)
    async def ws(websocket: WebSocket) -> None:
        await websocket.accept()
        await websocket.close()

    with app.test_client() as client:
        with pytest.raises(WebSocketHandshakeError) as denied, client.websocket_connect("/ws", headers={"Origin": "https://evil.example"}):
            pass
        assert denied.value.status_code == 403
        with client.websocket_connect("/ws"):
            pass


def test_test_client_keeps_double_slash_targets_as_paths() -> None:
    app = Flasgo()

    @app.get("/p", public=True)
    def endpoint(request: Request) -> str:
        return request.path

    client = TestClient(app)
    assert client.get("//evil.example/p").status_code == 404
    assert client.get("/p?x=1#frag").text == "/p"


# Follow-up review -----------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("content_type", "part_type"),
    [
        ("application/x-www-form-urlencoded; charset=punycode", None),
        ("application/x-www-form-urlencoded; charset=undefined", None),
        ("application/x-www-form-urlencoded; charset*=utf-8''%00", None),
        ("multipart/form-data; boundary=b", "text/plain; charset=punycode"),
        ("multipart/form-data; boundary=b", "text/plain; charset=undefined"),
    ],
)
def test_form_charsets_outside_the_allowlist_are_rejected_quickly(content_type: str, part_type: str | None) -> None:
    payload = b"-zzzz9a" + b"a" * 400_000  # quadratic for Python's punycode decoder
    if part_type is None:
        body = b"a=" + payload
    else:
        body = _multipart(f'Content-Disposition: form-data; name="a"\r\nContent-Type: {part_type}\r\n\r\n'.encode() + payload)
    started = time.perf_counter()
    response = TestClient(_form_app()).post("/form", body=body, headers={"content-type": content_type})
    assert response.status_code == 400
    assert time.perf_counter() - started < 1


def test_rfc5987_parameters_in_disallowed_charsets_are_ignored() -> None:
    body = _multipart(
        b'Content-Disposition: form-data; name="doc"; filename="plain.txt"; filename*=punycode\'\'-zzzz9a\r\n\r\nx',
        b'Content-Disposition: form-data; name="nul"; filename="nul.txt"; filename*=a\x00b\'\'x\r\n\r\ny',
    )
    response = TestClient(_form_app()).post("/form", body=body, headers=_multipart_headers())
    assert response.status_code == 200
    assert response.json() == {"fields": {}, "files": {"doc": [["plain.txt", "x"]], "nul": [["nul.txt", "y"]]}}
    assert _parse_content_type("application/json; a*=undefined''x") == ("application/json", {})


@dataclass
class _NodeA:
    child: _NodeA | _NodeB | None
    flag: int


@dataclass
class _NodeB:
    child: _NodeA | _NodeB | None
    flag: str


def test_recursive_union_response_model_projects_in_linear_time() -> None:
    app = Flasgo(settings={"CSRF_ENABLED": False})

    @app.post("/echo", public=True, response_model=_NodeA | _NodeB)
    def echo(data: Annotated[dict[str, Any], Body()]) -> dict[str, Any]:
        return data

    tree: dict[str, Any] = {"child": None, "flag": "leaf"}
    for _ in range(30):
        tree = {"child": tree, "flag": "s"}
    started = time.perf_counter()
    response = TestClient(app).post("/echo", json=tree)
    assert response.status_code == 200
    assert time.perf_counter() - started < 1


def test_authorized_wrapper_protects_every_non_public_route_on_the_inner_function() -> None:
    app = _auth_app()

    @app.get("/v2")
    @app.authorize()
    @_audit
    @app.get("/v1")
    def view() -> str:
        return "view"

    app.add_route("/alias", view)
    app.add_route("/open", cast(Any, view).__wrapped__, public=True)

    client = TestClient(app)
    assert [client.get(path).status_code for path in ("/v1", "/v2", "/alias", "/open")] == [401, 401, 401, 200]


async def _disconnect_after_first_body(app: Flasgo, path: str) -> list[dict[str, Any]]:
    """Disconnect during the first body send, then complete every send() at once, as uvicorn does after a drop."""
    sent: list[dict[str, Any]] = []
    first_chunk = asyncio.Event()
    delivered_request = False

    async def receive() -> dict[str, Any]:
        nonlocal delivered_request
        if not delivered_request:
            delivered_request = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await first_chunk.wait()
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)
        if message["type"] == "http.response.body" and not first_chunk.is_set():
            # The first chunk waits on flow control, during which the server sees the client go away; every later
            # send() is then a no-op that never suspends.
            first_chunk.set()
            await asyncio.sleep(0)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [(b"host", b"localhost")],
        "client": ("127.0.0.1", 50000),
        "server": ("localhost", 80),
    }
    await app(scope, receive, send)
    return sent


def test_real_disconnect_is_not_reported_as_completed_when_the_producer_never_suspends() -> None:
    events: list[str] = []
    app = Flasgo()

    async def transaction():
        try:
            yield "tx"
        except BaseException as exc:
            events.append(f"rollback:{type(exc).__name__}")
            raise
        else:
            events.append("commit")

    @app.get("/big", public=True)
    def big(tx: Annotated[str, Depends(transaction)]) -> StreamingResponse:
        async def content():
            for _ in range(50):
                yield b"x" * 1024

        response = StreamingResponse(content())
        response.add_task(events.append, "background")
        return response

    asyncio.run(_disconnect_after_first_body(app, "/big"))
    assert events == ["rollback:ConnectionError"]


def test_multipart_framing_edge_cases_match_rfc_2046() -> None:
    payload = b"x\r\n--b--tail\r\nmore"
    body = (
        _multipart(b'Content-Disposition: form-data; name="f"; filename="f.bin"\r\n\r\n' + payload)[: -len(b"--b--\r\n")]
        + b'--b\r\nContent-Disposition: form-data; name="headers-only"\r\n--b\r\n--b--\r\n'
    )
    response = TestClient(_form_app()).post("/form", body=body, headers=_multipart_headers())
    assert response.status_code == 200
    assert response.json() == {"fields": {"headers-only": [""]}, "files": {"f": [["f.bin", payload.decode()]]}}


def test_rfc2231_continuations_and_rfc2047_filenames_are_decoded() -> None:
    body = _multipart(
        b'Content-Disposition: form-data; name="plain"; filename*0="long"; filename*1="name.txt"\r\n\r\n1',
        b"Content-Disposition: form-data; name=\"ext\"; filename*0*=utf-8''lo%C3%A9; filename*1=name.txt\r\n\r\n2",
        b'Content-Disposition: form-data; name="word"; filename="=?utf-8?b?aMOpbGxvLnR4dA==?="\r\n\r\n3',
        b'Content-Disposition: form-data; name="q"; filename="=?iso-8859-1?q?h=E9llo_world.txt?="\r\n\r\n4',
    )
    response = TestClient(_form_app()).post("/form", body=body, headers=_multipart_headers())
    assert response.status_code == 200
    assert cast(dict[str, Any], response.json())["files"] == {
        "plain": [["longname.txt", "1"]],
        "ext": [["loéname.txt", "2"]],
        "word": [["héllo.txt", "3"]],
        "q": [["héllo world.txt", "4"]],
    }


def test_empty_urlencoded_charset_defaults_to_utf8() -> None:
    response = TestClient(_form_app()).post(
        "/form", body=b"a=%C3%A9", headers={"content-type": "application/x-www-form-urlencoded; charset="}
    )
    assert response.json() == {"fields": {"a": ["é"]}, "files": {}}
