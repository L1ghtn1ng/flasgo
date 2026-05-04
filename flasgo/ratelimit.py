from __future__ import annotations

import asyncio
import math
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass

from .request import Request
from .response import Response
from .routing import Endpoint

RateLimitKeyFunc = Callable[[Request], str | None]


@dataclass(frozen=True, slots=True)
class RateLimitRule:
    """Per-client sliding-window rate limit for one or more routes."""

    requests: int
    window_seconds: float
    scope: str | None = None
    key_func: RateLimitKeyFunc | None = None

    def __post_init__(self) -> None:
        if self.requests <= 0:
            raise ValueError("Rate limit requests must be greater than 0.")
        if self.window_seconds <= 0:
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


class RateLimiter:
    """In-process sliding-window limiter keyed by route scope and client identity.

    This stores recent request timestamps only. It is intentionally small and
    dependency-free for single-process apps and tests; production deployments
    with multiple workers should use a shared edge or storage-backed limiter.
    """

    def __init__(self, *, max_keys: int = 10_000) -> None:
        if max_keys <= 0:
            raise ValueError("RateLimiter max_keys must be greater than 0.")
        self.max_keys = max_keys
        self._buckets: dict[tuple[str, str], deque[float]] = {}
        self._lock = asyncio.Lock()

    async def check(self, rule: RateLimitRule, req: Request, *, endpoint_id: str) -> RateLimitDecision:
        now = time.monotonic()
        client_key = _rate_limit_key(rule, req)
        scope = rule.scope or endpoint_id
        bucket_key = (scope, client_key)

        async with self._lock:
            if len(self._buckets) > self.max_keys:
                self._prune(now)

            request_times = self._buckets.setdefault(bucket_key, deque())
            self._drop_expired_requests(request_times, rule=rule, now=now)

            # Read-only evaluation: check if request would be allowed
            if len(request_times) >= rule.requests:
                retry_after = _seconds_until_reset(request_times[0], rule=rule, now=now)
                return RateLimitDecision(
                    allowed=False,
                    limit=rule.requests,
                    remaining=0,
                    reset_after=retry_after,
                    retry_after=retry_after,
                )

            # Request is allowed - now mutate state by appending timestamp
            request_times.append(now)
            remaining = max(0, rule.requests - len(request_times))
            reset_after = _seconds_until_reset(request_times[0], rule=rule, now=now)
            return RateLimitDecision(
                allowed=True,
                limit=rule.requests,
                remaining=remaining,
                reset_after=reset_after,
                retry_after=0,
            )

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
            if len(self._buckets) > self.max_keys:
                self._prune(now)

            # Phase 1: Read-only evaluation for all rules
            evaluations = []
            for rule, endpoint_id in rules:
                client_key = _rate_limit_key(rule, req)
                scope = rule.scope or endpoint_id
                bucket_key = (scope, client_key)

                request_times = self._buckets.setdefault(bucket_key, deque())
                self._drop_expired_requests(request_times, rule=rule, now=now)

                if len(request_times) >= rule.requests:
                    retry_after = _seconds_until_reset(request_times[0], rule=rule, now=now)
                    evaluations.append((
                        bucket_key,
                        rule,
                        request_times,
                        RateLimitDecision(
                            allowed=False,
                            limit=rule.requests,
                            remaining=0,
                            reset_after=retry_after,
                            retry_after=retry_after,
                        ),
                    ))
                else:
                    reset_after = _seconds_until_reset(request_times[0], rule=rule, now=now) if request_times else 0
                    remaining = max(0, rule.requests - len(request_times) - 1)  # -1 for the request we're about to add
                    evaluations.append((
                        bucket_key,
                        rule,
                        request_times,
                        RateLimitDecision(
                            allowed=True,
                            limit=rule.requests,
                            remaining=remaining,
                            reset_after=reset_after,
                            retry_after=0,
                        ),
                    ))

            # Phase 2: Check if any rule denied
            all_allowed = all(decision.allowed for _, _, _, decision in evaluations)

            # Phase 3: If all allowed, append timestamps atomically
            if all_allowed:
                for _bucket_key, _rule, request_times, _ in evaluations:
                    request_times.append(now)

            # Return decisions
            return [decision for _, _, _, decision in evaluations]

    def _drop_expired_requests(
        self,
        request_times: deque[float],
        *,
        rule: RateLimitRule,
        now: float,
    ) -> None:
        cutoff = now - rule.window_seconds
        while request_times and request_times[0] <= cutoff:
            request_times.popleft()

    def _prune(self, now: float) -> None:
        """Keep memory bounded when many unique clients hit limited routes."""

        for key, request_times in list(self._buckets.items()):
            if not request_times:
                self._buckets.pop(key, None)
                continue
            if request_times[-1] < now - 86_400:
                self._buckets.pop(key, None)
        if len(self._buckets) <= self.max_keys:
            return
        oldest_keys = sorted(self._buckets, key=lambda key: self._buckets[key][-1])
        for key in oldest_keys[: len(self._buckets) - self.max_keys]:
            self._buckets.pop(key, None)


def rate_limit(
    requests: int,
    *,
    per: float,
    scope: str | None = None,
    key_func: RateLimitKeyFunc | None = None,
) -> Callable[[Endpoint], Endpoint]:
    """Attach a rate limit rule to a route handler.

    By default, requests are keyed by the ASGI client IP. Pass the same
    ``scope`` to multiple endpoints when they should share one quota.
    """

    rule = RateLimitRule(requests=requests, window_seconds=per, scope=scope, key_func=key_func)

    def decorator(endpoint: Endpoint) -> Endpoint:
        rules = list(getattr(endpoint, "__flasgo_rate_limits__", ()))
        rules.append(rule)
        endpoint.__dict__["__flasgo_rate_limits__"] = tuple(rules)
        return endpoint

    return decorator


def build_rate_limit_response(decision: RateLimitDecision) -> Response:
    headers = _rate_limit_headers(decision)
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
    return _rate_limit_headers(decision)


def _rate_limit_headers(decision: RateLimitDecision) -> dict[str, str]:
    return {
        "ratelimit-limit": str(decision.limit),
        "ratelimit-remaining": str(decision.remaining),
        "ratelimit-reset": str(decision.reset_after),
        "x-ratelimit-limit": str(decision.limit),
        "x-ratelimit-remaining": str(decision.remaining),
        "x-ratelimit-reset": str(decision.reset_after),
    }


def _rate_limit_key(rule: RateLimitRule, req: Request) -> str:
    if rule.key_func is not None:
        key = rule.key_func(req)
        if key is not None:
            return str(key)
    return req.client_ip or "unknown"


def _seconds_until_reset(oldest_request_time: float, *, rule: RateLimitRule, now: float) -> int:
    return max(1, math.ceil(oldest_request_time + rule.window_seconds - now))


def endpoint_rate_limits(endpoint: Endpoint) -> tuple[RateLimitRule, ...]:
    raw = getattr(endpoint, "__flasgo_rate_limits__", ())
    if not isinstance(raw, tuple):
        return ()
    return tuple(item for item in raw if isinstance(item, RateLimitRule))
