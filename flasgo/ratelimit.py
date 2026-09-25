import asyncio
import math
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from .request import Request
from .response import Response

type RateLimitKeyFunc = Callable[[Request], str | None]


@dataclass(frozen=True, slots=True)
class RateLimitRule:
    """Per-client sliding-window rate limit for one or more routes."""

    requests: int
    window_seconds: float
    scope: str | None = None
    key_func: RateLimitKeyFunc | None = None

    def __post_init__(self) -> None:
        """
        Validate rate-limit configuration values.

        Raises:
            ValueError: If the request count or window duration is invalid, or if the
                scope is blank.
        """
        if isinstance(self.requests, bool) or not isinstance(self.requests, int) or self.requests <= 0:
            raise ValueError("Rate limit requests must be greater than 0.")
        if isinstance(self.window_seconds, bool) or not math.isfinite(self.window_seconds) or self.window_seconds <= 0:
            raise ValueError("Rate limit window_seconds must be greater than 0.")
        if self.scope is not None and not self.scope.strip():
            raise ValueError("Rate limit scope must not be empty.")


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """Result returned by RateLimiter.check for one rule evaluation."""

    allowed: bool
    limit: int
    remaining: int
    reset_after: int
    retry_after: int


class RateLimitBackend(Protocol):
    async def check_batch(self, rules: list[tuple[RateLimitRule, str]], req: Request) -> list[RateLimitDecision]:
        """
        Evaluate multiple rate-limit rules atomically for a request.

        Parameters:
                rules (list[tuple[RateLimitRule, str]]): Rate-limit rules paired with their client keys.
                req (Request): The incoming request.

        Returns:
                list[RateLimitDecision]: One decision for each supplied rule.
        """


class RateLimiter:
    """In-process sliding-window limiter keyed by route scope and client identity.

    This stores recent request timestamps only. It is intentionally small and
    dependency-free for single-process apps and tests; production deployments
    with multiple workers should use a shared edge or storage-backed limiter.
    """

    def __init__(self, *, max_keys: int = 10_000) -> None:
        if isinstance(max_keys, bool) or not isinstance(max_keys, int) or max_keys <= 0:
            raise ValueError("RateLimiter max_keys must be a positive integer.")
        self.max_keys = max_keys
        self._buckets: dict[tuple[str, str], deque[float]] = {}
        self._bucket_windows: dict[tuple[str, str], float] = {}
        # No bucket can expire before this monotonic time, so a full limiter can skip the O(n) prune until then.
        # It may underestimate (buckets only ever expire later than recorded), which just prunes earlier.
        self._next_expiry = 0.0
        self._lock = asyncio.Lock()

    async def check(self, rule: RateLimitRule, req: Request, *, endpoint_id: str) -> RateLimitDecision:
        """Evaluate one rule with the same bucket semantics as :meth:`check_batch`.

        Buckets can be shared through ``scope`` by rules with different windows, so expiry must honour the longest
        window ever applied to the bucket rather than this rule's window.
        """
        return (await self.check_batch([(rule, endpoint_id)], req))[0]

    async def check_batch(
        self,
        rules: list[tuple[RateLimitRule, str]],
        req: Request,
    ) -> list[RateLimitDecision]:
        """Check multiple rate limit rules atomically.

        Performs read-only evaluation for all rules first, and only appends
        timestamps if every rule would allow the request. This prevents earlier
        passing rules from consuming quota if a later rule denies.

        Args:
            rules: List of (rule, endpoint_id) tuples to check
            req: The incoming request

        Returns:
            List of RateLimitDecision objects, one per rule
        """
        if not rules:
            return []

        now = time.monotonic()

        async with self._lock:
            entries = [((rule.scope or endpoint_id, rate_limit_key(rule, req)), rule) for rule, endpoint_id in rules]
            if self._over_capacity(entries) and now >= self._next_expiry:
                self._prune(now)
            if self._over_capacity(entries):
                req.scope["flasgo.rate_limit_capacity"] = True
                return [self._capacity_decision(rule, now=now) for _bucket_key, rule in entries]

            # Each bucket keeps history for the longest window any rule has applied to it.
            windows: dict[tuple[str, str], float] = {}
            for bucket_key, rule in entries:
                windows[bucket_key] = max(windows.get(bucket_key, self._bucket_windows.get(bucket_key, 0.0)), rule.window_seconds)
            buckets = {bucket_key: self._buckets.get(bucket_key, deque()) for bucket_key in windows}
            for bucket_key, request_times in buckets.items():
                cutoff = now - windows[bucket_key]
                while request_times and request_times[0] <= cutoff:
                    request_times.popleft()

            decisions = [self._decide(rule, buckets[bucket_key], now=now) for bucket_key, rule in entries]
            if all(decision.allowed for decision in decisions):
                for bucket_key, request_times in buckets.items():
                    request_times.append(now)
                    self._buckets[bucket_key] = request_times
                    self._bucket_windows[bucket_key] = windows[bucket_key]
                    self._next_expiry = min(self._next_expiry, now + windows[bucket_key])
            else:
                for bucket_key in buckets.keys() & self._buckets.keys():
                    self._bucket_windows[bucket_key] = windows[bucket_key]
            return decisions

    def _over_capacity(self, entries: list[tuple[tuple[str, str], RateLimitRule]]) -> bool:
        missing = {bucket_key for bucket_key, _rule in entries if bucket_key not in self._buckets}
        return len(self._buckets) + len(missing) > self.max_keys

    @staticmethod
    def _decide(rule: RateLimitRule, request_times: deque[float], *, now: float) -> RateLimitDecision:
        cutoff = now - rule.window_seconds
        recent_times = [timestamp for timestamp in request_times if timestamp > cutoff]
        if len(recent_times) >= rule.requests:
            # A shared scope can hold more entries than this rule allows; the request becomes possible once
            # enough of them expire to bring the count below the limit, not when the oldest one expires.
            blocking = recent_times[len(recent_times) - rule.requests]
            retry_after = _seconds_until(blocking + rule.window_seconds, now=now)
            return RateLimitDecision(allowed=False, limit=rule.requests, remaining=0, reset_after=retry_after, retry_after=retry_after)
        oldest = recent_times[0] if recent_times else now
        return RateLimitDecision(
            allowed=True,
            limit=rule.requests,
            remaining=max(0, rule.requests - len(recent_times) - 1),
            reset_after=_seconds_until(oldest + rule.window_seconds, now=now),
            retry_after=0,
        )

    def _prune(self, now: float) -> None:
        """Remove only buckets whose complete quota state has expired, and record the next expiry."""
        next_expiry = math.inf
        for key, request_times in list(self._buckets.items()):
            expires = request_times[-1] + self._bucket_windows.get(key, 86_400) if request_times else now
            if expires <= now:
                self._buckets.pop(key, None)
                self._bucket_windows.pop(key, None)
            else:
                next_expiry = min(next_expiry, expires)
        self._next_expiry = next_expiry

    def _capacity_decision(self, rule: RateLimitRule, *, now: float) -> RateLimitDecision:
        retry_after = _seconds_until(self._next_expiry, now=now) if math.isfinite(self._next_expiry) else 1
        return RateLimitDecision(
            allowed=False,
            limit=rule.requests,
            remaining=0,
            reset_after=retry_after,
            retry_after=retry_after,
        )


def rate_limit[T: Callable[..., Any]](
    requests: int,
    *,
    per: float,
    scope: str | None = None,
    key_func: RateLimitKeyFunc | None = None,
) -> Callable[[T], T]:
    """Attach a rate limit rule to a route handler.

    By default, requests are keyed by the ASGI client IP. Pass the same
    ``scope`` to multiple endpoints when they should share one quota.
    """

    rule = RateLimitRule(requests=requests, window_seconds=per, scope=scope, key_func=key_func)

    def decorator(endpoint: T) -> T:
        rules: list[RateLimitRule] = list(getattr(endpoint, "__flasgo_rate_limits__", ()))
        rules.append(rule)
        endpoint.__dict__["__flasgo_rate_limits__"] = tuple(rules)
        return endpoint

    return decorator


def build_rate_limit_response(decision: RateLimitDecision) -> Response:
    headers = rate_limit_success_headers(decision)
    headers["retry-after"] = str(decision.retry_after)
    return Response.json(
        {
            "error": "too_many_requests",
            "detail": "Too many requests from this client. Wait before retrying.",
        },
        status_code=429,
        headers=headers,
    )


def rate_limit_success_headers(decision: RateLimitDecision) -> dict[str, str]:
    return {
        "ratelimit-limit": str(decision.limit),
        "ratelimit-remaining": str(decision.remaining),
        "ratelimit-reset": str(decision.reset_after),
        "x-ratelimit-limit": str(decision.limit),
        "x-ratelimit-remaining": str(decision.remaining),
        "x-ratelimit-reset": str(decision.reset_after),
    }


def rate_limit_key(rule: RateLimitRule, req: Request) -> str:
    """Return the client identity a rule counts against: its ``key_func`` result or the client IP."""
    if rule.key_func is not None:
        key = rule.key_func(req)
        if key is not None:
            return str(key)
    return req.client_ip or "unknown"


def _seconds_until(deadline: float, *, now: float) -> int:
    return max(1, math.ceil(deadline - now))


def endpoint_rate_limits(endpoint: Callable[..., Any]) -> tuple[RateLimitRule, ...]:
    raw = getattr(endpoint, "__flasgo_rate_limits__", ())
    if not isinstance(raw, tuple):
        return ()
    return tuple(item for item in raw if isinstance(item, RateLimitRule))
