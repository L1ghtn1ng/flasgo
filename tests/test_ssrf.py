from __future__ import annotations

import socket

import pytest
from fango import Fango, SSRFViolation


def test_ssrf_blocks_private_ip_literal() -> None:
    app = Fango()
    with pytest.raises(SSRFViolation):
        app.validate_outbound_url("http://127.0.0.1/internal")


def test_ssrf_blocks_disallowed_scheme() -> None:
    app = Fango()
    with pytest.raises(SSRFViolation):
        app.validate_outbound_url("file:///etc/passwd")


def test_ssrf_blocks_userinfo_by_default() -> None:
    app = Fango()
    with pytest.raises(SSRFViolation):
        app.validate_outbound_url("https://user:pass@example.com/data")


def test_ssrf_allows_public_domain_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(
        host: str,
        port: int,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        assert host == "example.com"
        _ = (family, type, proto, flags)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    app = Fango()
    assert app.validate_outbound_url("https://example.com/path") == "https://example.com/path"


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
    app = Fango()
    with pytest.raises(SSRFViolation):
        app.validate_outbound_url("https://api.example.com/data")


def test_ssrf_host_allowlist_rejects_unknown_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(
        host: str,
        port: int,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        _ = (family, type, proto, flags)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    app = Fango(settings={"SSRF_ALLOWED_HOSTS": {"api.example.com"}})
    with pytest.raises(SSRFViolation):
        app.validate_outbound_url("https://example.com/path")


def test_ssrf_allowlist_allows_expected_host(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(
        host: str,
        port: int,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        _ = (family, type, proto, flags)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    app = Fango(settings={"SSRF_ALLOWED_HOSTS": {"api.example.com"}})
    assert app.validate_outbound_url("https://api.example.com/path") == "https://api.example.com/path"


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
    app = Fango()
    with pytest.raises(SSRFViolation):
        app.validate_outbound_url("https://unresolvable.invalid")


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
    app = Fango(settings={"SSRF_ALLOW_UNRESOLVABLE_HOSTS": True})
    assert app.validate_outbound_url("https://unresolvable.invalid") == "https://unresolvable.invalid"
