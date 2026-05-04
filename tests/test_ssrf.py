from __future__ import annotations

import socket
from collections.abc import Callable

import pytest
from flasgo import Flasgo, SSRFConfig, SSRFGuard, SSRFViolation

PUBLIC_IPV4 = "1.1.1.1"
type AddrInfo = tuple[int, int, int, str, tuple[str, int]]


def _public_getaddrinfo(
    *,
    expected_host: str = "example.com",
    expected_port: int | None = None,
) -> Callable[[str, int, int, int, int, int], list[AddrInfo]]:
    def fake_getaddrinfo(
        host: str,
        port: int,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[AddrInfo]:
        assert host == expected_host
        if expected_port is not None:
            assert port == expected_port
        _ = (family, type, proto, flags)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_IPV4, port))]

    return fake_getaddrinfo


def test_ssrf_blocks_private_ip_literal() -> None:
    app = Flasgo()
    with pytest.raises(SSRFViolation):
        app.resolve_outbound_url("http://127.0.0.1/internal")


def test_ssrf_blocks_disallowed_scheme() -> None:
    app = Flasgo()
    with pytest.raises(SSRFViolation):
        app.resolve_outbound_url("file:///etc/passwd")


def test_ssrf_blocks_userinfo_by_default() -> None:
    app = Flasgo()
    with pytest.raises(SSRFViolation):
        app.resolve_outbound_url("https://user:pass@example.com/data")


def test_ssrf_allows_public_domain_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _public_getaddrinfo())
    app = Flasgo()
    resolved = app.resolve_outbound_url("https://example.com/path")
    assert resolved.original_url == "https://example.com/path"
    assert resolved.url == "https://1.1.1.1/path"


def test_ssrf_resolve_url_returns_pinned_connection_target(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _public_getaddrinfo(expected_port=443))
    app = Flasgo()
    resolved = app.resolve_outbound_url("https://example.com:443/path?q=1")

    assert resolved.original_url == "https://example.com:443/path?q=1"
    assert resolved.url == "https://1.1.1.1:443/path?q=1"
    assert resolved.hostname == "example.com"
    assert resolved.port == 443
    assert str(resolved.address) == PUBLIC_IPV4
    assert resolved.host_header == "example.com:443"


def test_ssrf_rejects_invalid_port() -> None:
    app = Flasgo()
    with pytest.raises(SSRFViolation):
        app.resolve_outbound_url("https://example.com:bad/path")


def test_ssrf_disabled_does_not_inspect_malformed_url() -> None:
    guard = SSRFGuard(SSRFConfig(enabled=False))

    resolved = guard.resolve_url("https://example.com:bad/path")
    assert resolved.url == "https://example.com:bad/path"
    assert resolved.address is None


def test_ssrf_resolve_url_preserves_allowed_userinfo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _public_getaddrinfo())
    guard = SSRFGuard(SSRFConfig(allow_userinfo=True))
    resolved = guard.resolve_url("https://user:pass@example.com/path")

    assert resolved.url == "https://user:pass@1.1.1.1/path"
    assert resolved.host_header == "example.com"


def test_ssrf_blocks_domain_resolving_private_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(
        host: str,
        port: int,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        _ = (host, family, type, proto, flags)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.10", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    app = Flasgo()
    with pytest.raises(SSRFViolation):
        app.resolve_outbound_url("https://api.example.com/data")


def test_ssrf_host_allowlist_rejects_unknown_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _public_getaddrinfo())
    app = Flasgo(settings={"SSRF_ALLOWED_HOSTS": {"api.example.com"}})
    with pytest.raises(SSRFViolation):
        app.resolve_outbound_url("https://example.com/path")


def test_ssrf_allowlist_allows_expected_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _public_getaddrinfo(expected_host="api.example.com"))
    app = Flasgo(settings={"SSRF_ALLOWED_HOSTS": {"api.example.com"}})
    resolved = app.resolve_outbound_url("https://api.example.com/path")
    assert resolved.hostname == "api.example.com"
    assert resolved.url == "https://1.1.1.1/path"


def test_ssrf_blocks_unresolvable_hosts_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(
        host: str,
        port: int,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        _ = (host, port, family, type, proto, flags)
        raise socket.gaierror("no resolution")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    app = Flasgo()
    with pytest.raises(SSRFViolation):
        app.resolve_outbound_url("https://unresolvable.invalid")


def test_ssrf_can_allow_unresolvable_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(
        host: str,
        port: int,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        _ = (host, port, family, type, proto, flags)
        raise socket.gaierror("no resolution")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    app = Flasgo(settings={"SSRF_ALLOW_UNRESOLVABLE_HOSTS": True})
    resolved = app.resolve_outbound_url("https://unresolvable.invalid")
    assert resolved.url == "https://unresolvable.invalid"
    assert resolved.address is None
