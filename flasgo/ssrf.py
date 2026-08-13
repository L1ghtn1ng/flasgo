from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import SplitResult, urlsplit, urlunsplit

type IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
_PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)


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
    resolution_timeout_seconds: float | None = 5.0


@dataclass(slots=True, frozen=True)
class SSRFResolvedURL:
    """Validated outbound URL details with a pinned address for safer clients.

    Connect to ``url`` (hostname replaced by the validated ``address``) and send
    ``host_header`` as the HTTP Host header. ``original_url`` is retained for logging
    only — fetching it re-resolves DNS and defeats the validation.
    """

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
        """Validate an outbound URL and return a pinned connection target.

        DNS resolution blocks the calling thread. Inside async handlers, use
        :meth:`aresolve_url` (or ``Flasgo.aresolve_outbound_url``) so resolution
        runs on the event loop's resolver with a bounded timeout instead.
        """

        target = self._prepare(url)
        if target is None:
            return _disabled_result(url)
        parsed, host, port, explicit_port = target
        addresses = self._resolve_ips(host, port=port)
        return self._checked_result(url, parsed, host, port, explicit_port, addresses)

    async def aresolve_url(self, url: str) -> SSRFResolvedURL:
        """Async variant of :meth:`resolve_url` that never blocks the event loop.

        Resolution uses the loop's async resolver bounded by
        ``SSRFConfig.resolution_timeout_seconds`` and fails closed on timeout,
        regardless of ``allow_unresolvable_hosts``.
        """

        target = self._prepare(url)
        if target is None:
            return _disabled_result(url)
        parsed, host, port, explicit_port = target
        addresses = await self._aresolve_ips(host, port=port)
        return self._checked_result(url, parsed, host, port, explicit_port, addresses)

    def _prepare(self, url: str) -> tuple[SplitResult, str, int, int | None] | None:
        if not self.config.enabled:
            return None

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
        return parsed, host, _url_port(parsed, explicit_port), explicit_port

    def _checked_result(
        self,
        url: str,
        parsed: SplitResult,
        host: str,
        port: int,
        explicit_port: int | None,
        addresses: set[IPAddress],
    ) -> SSRFResolvedURL:
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
            return self._resolution_failed(host, exc)
        return self._addresses_from_infos(infos, host)

    async def _aresolve_ips(self, host: str, *, port: int | None) -> set[IPAddress]:
        literal = _parse_ip_literal(host)
        if literal is not None:
            return {literal}

        loop = asyncio.get_running_loop()
        try:
            async with asyncio.timeout(self.config.resolution_timeout_seconds):
                infos = await loop.getaddrinfo(host, port or 0, type=socket.SOCK_STREAM)
        except TimeoutError as exc:
            raise SSRFViolation(f"Timed out resolving outbound host {host!r}.") from exc
        except socket.gaierror as exc:
            return self._resolution_failed(host, exc)
        return self._addresses_from_infos(infos, host)

    def _resolution_failed(self, host: str, exc: Exception) -> set[IPAddress]:
        if self.config.allow_unresolvable_hosts:
            return set()
        msg = f"Could not resolve outbound host {host!r}."
        raise SSRFViolation(msg) from exc

    def _addresses_from_infos(self, infos: list[tuple], host: str) -> set[IPAddress]:
        addresses: set[IPAddress] = set()
        for family, _, _, _, sockaddr in infos:
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue
            ip_raw = sockaddr[0]
            addresses.add(ipaddress.ip_address(ip_raw))
        if not addresses and not self.config.allow_unresolvable_hosts:
            raise SSRFViolation(f"Could not resolve outbound host {host!r}.")
        return addresses


def _disabled_result(url: str) -> SSRFResolvedURL:
    return SSRFResolvedURL(
        original_url=url,
        url=url,
        hostname="",
        port=0,
        address=None,
        host_header="",
    )


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
    if (
        inspected.is_loopback
        or inspected.is_link_local
        or inspected.is_multicast
        or inspected.is_reserved
        or inspected.is_unspecified
    ):
        return True
    if any(inspected in network for network in _PRIVATE_NETWORKS if inspected.version == network.version):
        return not allow_private_networks
    return not inspected.is_global
