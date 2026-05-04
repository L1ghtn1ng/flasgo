from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import SplitResult, urlsplit, urlunsplit

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


@dataclass(slots=True, frozen=True)
class SSRFResolvedURL:
    """Validated outbound URL details with a pinned address for safer clients."""

    original_url: str
    url: str
    hostname: str
    port: int
    address: IPAddress | None
    host_header: str


class SSRFGuard:
    def __init__(self, config: SSRFConfig | None = None) -> None:
        self.config = config or SSRFConfig()

    def resolve_url(self, url: str) -> SSRFResolvedURL:
        if not self.config.enabled:
            return SSRFResolvedURL(
                original_url=url,
                url=url,
                hostname="",
                port=0,
                address=None,
                host_header="",
            )

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

        explicit_port = _explicit_port(parsed)
        port = _url_port(parsed, explicit_port)
        addresses = self._resolve_ips(host, port=port)
        for address in addresses:
            if _ip_is_disallowed(
                address,
                allow_private_networks=self.config.allow_private_networks,
            ):
                raise SSRFViolation(f"Blocked outbound URL resolved to restricted address: {address}")

        pinned_address = sorted(addresses, key=lambda item: item.packed)[0] if addresses else None
        return SSRFResolvedURL(
            original_url=url,
            url=_replace_hostname(parsed, pinned_address, port=port, explicit_port=explicit_port)
            if pinned_address is not None
            else url,
            hostname=host,
            port=port,
            address=pinned_address,
            host_header=_host_header(parsed, port=port, explicit_port=explicit_port),
        )

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


def _url_port(parsed: SplitResult, explicit_port: int | None) -> int:
    if explicit_port is not None:
        return explicit_port
    if parsed.scheme.lower() == "https":
        return 443
    if parsed.scheme.lower() == "http":
        return 80
    return 0


def _host_header(parsed: SplitResult, *, port: int, explicit_port: int | None) -> str:
    hostname = parsed.hostname or ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    if port == 0 or explicit_port is None:
        return hostname
    return f"{hostname}:{port}"


def _replace_hostname(
    parsed: SplitResult,
    address: IPAddress,
    *,
    port: int,
    explicit_port: int | None,
) -> str:
    host = str(address)
    if isinstance(address, ipaddress.IPv6Address):
        host = f"[{host}]"
    if parsed.username is not None:
        userinfo = parsed.username
        if parsed.password is not None:
            userinfo = f"{userinfo}:{parsed.password}"
        host = f"{userinfo}@{host}"
    if explicit_port is not None:
        host = f"{host}:{port}"
    return urlunsplit(parsed._replace(netloc=host))


def _explicit_port(parsed: SplitResult) -> int | None:
    try:
        return parsed.port
    except ValueError as exc:
        raise SSRFViolation("Outbound URL includes an invalid port.") from exc


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
