from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit

type IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class SSRFViolation(ValueError):
    """Raised when an outbound URL fails SSRF safety validation."""


@dataclass(slots=True)
class SSRFConfig:
    enabled: bool = True
    allowed_schemes: frozenset[str] = field(default_factory=lambda: frozenset({"http", "https"}))
    allowed_hosts: set[str] = field(default_factory=set)
    allow_private_networks: bool = False
    allow_userinfo: bool = False
    allow_unresolvable_hosts: bool = False


class SSRFGuard:
    def __init__(self, config: SSRFConfig | None = None) -> None:
        self.config = config or SSRFConfig()

    def validate_url(self, url: str) -> str:
        if not self.config.enabled:
            return url

        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme not in self.config.allowed_schemes:
            msg = f"Blocked outbound URL scheme: {scheme!r}"
            raise SSRFViolation(msg)

        if parsed.username or parsed.password:
            if not self.config.allow_userinfo:
                raise SSRFViolation("Blocked outbound URL with userinfo credentials.")

        hostname = parsed.hostname
        if not hostname:
            raise SSRFViolation("Outbound URL must include a hostname.")
        host = hostname.lower()

        if self.config.allowed_hosts and not _host_allowed(host, self.config.allowed_hosts):
            raise SSRFViolation(f"Host {host!r} is not in SSRF allowlist.")

        for address in self._resolve_ips(host, port=parsed.port):
            if _ip_is_disallowed(
                address,
                allow_private_networks=self.config.allow_private_networks,
            ):
                raise SSRFViolation(f"Blocked outbound URL resolved to restricted address: {address}")

        return url

    def _resolve_ips(self, host: str, *, port: int | None) -> set[IPAddress]:
        literal = _parse_ip_literal(host)
        if literal is not None:
            return {literal}

        try:
            infos = socket.getaddrinfo(host, port or 0, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            if self.config.allow_unresolvable_hosts:
                return set()
            msg = f"Could not resolve outbound host {host!r}."
            raise SSRFViolation(msg) from exc

        addresses: set[IPAddress] = set()
        for family, _, _, _, sockaddr in infos:
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue
            ip_raw = sockaddr[0]
            addresses.add(ipaddress.ip_address(ip_raw))
        if not addresses and not self.config.allow_unresolvable_hosts:
            raise SSRFViolation(f"Could not resolve outbound host {host!r}.")
        return addresses


def _host_allowed(host: str, allowed_hosts: set[str]) -> bool:
    for raw in allowed_hosts:
        pattern = raw.strip().lower()
        if pattern == "*":
            return True
        if pattern.startswith("."):
            suffix = pattern[1:]
            if host == suffix or host.endswith(pattern):
                return True
            continue
        if host == pattern:
            return True
    return False


def _parse_ip_literal(host: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _ip_is_disallowed(address: IPAddress, *, allow_private_networks: bool) -> bool:
    inspected: IPAddress = address
    if isinstance(inspected, ipaddress.IPv6Address) and inspected.ipv4_mapped is not None:
        inspected = inspected.ipv4_mapped
    if allow_private_networks:
        return False
    return bool(
        inspected.is_private
        or inspected.is_loopback
        or inspected.is_link_local
        or inspected.is_multicast
        or inspected.is_reserved
        or inspected.is_unspecified
    )
