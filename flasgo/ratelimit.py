from __future__ import annotations

import asyncio
import math
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .request import Request
from .response import Response

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
        self._bucket_windows: dict[tuple[str, str], float] = {}
        self._lock = asyncio.Lock()

    async def check(self, rule: RateLimitRule, req: Request, *, endpoint_id: str) -> RateLimitDecision:
        now = time.monotonic()
        client_key = _rate_limit_key(rule, req)
        scope = rule.scope or endpoint_id
        bucket_key = (scope, client_key)

        async with self._lock:
            if bucket_key not in self._buckets and len(self._buckets) >= self.max_keys:
                self._prune(now)
                if len(self._buckets) >= self.max_keys:
                    return self._capacity_decision(rule, now=now)

            request_times = self._buckets.setdefault(bucket_key, deque())
            # Track the maximum window for this bucket across all rules
            current_window = self._bucket_windows.get(bucket_key, 0.0)
            self._bucket_windows[bucket_key] = max(current_window, rule.window_seconds)
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
            requested_entries = []
            for rule, endpoint_id in rules:
                client_key = _rate_limit_key(rule, req)
                scope = rule.scope or endpoint_id
                requested_entries.append(((scope, client_key), rule))

            missing_keys = {bucket_key for bucket_key, _rule in requested_entries if bucket_key not in self._buckets}
            if len(self._buckets) + len(missing_keys) > self.max_keys:
                self._prune(now)
                missing_keys = {
                    bucket_key for bucket_key, _rule in requested_entries if bucket_key not in self._buckets
                }
                if len(self._buckets) + len(missing_keys) > self.max_keys:
                    return [self._capacity_decision(rule, now=now) for _bucket_key, rule in requested_entries]

            entries = []
            pending_buckets: dict[tuple[str, str], deque[float]] = {}
            entry_windows: dict[tuple[str, str], float] = {}
            for bucket_key, rule in requested_entries:
                request_times = self._buckets.get(bucket_key)
                if request_times is None:
                    request_times = pending_buckets.setdefault(bucket_key, deque())
                current_window = self._bucket_windows.get(bucket_key, 0.0)
                entry_windows[bucket_key] = max(entry_windows.get(bucket_key, current_window), rule.window_seconds)
                entries.append((bucket_key, rule, request_times))

            for bucket_key, window in entry_windows.items():
                if bucket_key in self._buckets:
                    self._bucket_windows[bucket_key] = window

            seen_bucket_keys = set()
            for bucket_key, _rule, request_times in entries:
                if bucket_key in seen_bucket_keys:
                    continue
                seen_bucket_keys.add(bucket_key)
                cutoff = now - entry_windows[bucket_key]
                while request_times and request_times[0] <= cutoff:
                    request_times.popleft()

            evaluations = []
            for bucket_key, rule, request_times in entries:
                cutoff = now - rule.window_seconds
                recent_times = [timestamp for timestamp in request_times if timestamp > cutoff]
                if len(recent_times) >= rule.requests:
                    retry_after = _seconds_until_reset(recent_times[0], rule=rule, now=now)
                    evaluations.append(
                        (
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
                        )
                    )
                else:
                    oldest = recent_times[0] if recent_times else now
                    reset_after = _seconds_until_reset(oldest, rule=rule, now=now)
                    remaining = max(0, rule.requests - len(recent_times) - 1)
                    evaluations.append(
                        (
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
                        )
                    )

            all_allowed = all(decision.allowed for _, _, _, decision in evaluations)

            if all_allowed:
                for bucket_key, request_times in pending_buckets.items():
                    self._buckets[bucket_key] = request_times
                for bucket_key, window in entry_windows.items():
                    self._bucket_windows[bucket_key] = window
                seen_bucket_keys = set()
                for bucket_key, _rule, request_times, _ in evaluations:
                    if bucket_key in seen_bucket_keys:
                        continue
                    seen_bucket_keys.add(bucket_key)
                    request_times.append(now)

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
        """Remove only buckets whose complete quota state has expired."""

        for key, request_times in list(self._buckets.items()):
            if not request_times:
                self._buckets.pop(key, None)
                self._bucket_windows.pop(key, None)
                continue
            bucket_window = self._bucket_windows.get(key, 86_400)
            if request_times[-1] <= now - bucket_window:
                self._buckets.pop(key, None)
                self._bucket_windows.pop(key, None)

    def _capacity_decision(self, rule: RateLimitRule, *, now: float) -> RateLimitDecision:
        retry_after = min(
            (
                _seconds_until_bucket_expires(
                    request_times[-1],
                    window_seconds=self._bucket_windows.get(key, 86_400),
                    now=now,
                )
                for key, request_times in self._buckets.items()
                if request_times
            ),
            default=1,
        )
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


def _seconds_until_bucket_expires(last_request_time: float, *, window_seconds: float, now: float) -> int:
    return max(1, math.ceil(last_request_time + window_seconds - now))


def endpoint_rate_limits(endpoint: Callable[..., Any]) -> tuple[RateLimitRule, ...]:
    raw = getattr(endpoint, "__flasgo_rate_limits__", ())
    if not isinstance(raw, tuple):
        return ()
    return tuple(item for item in raw if isinstance(item, RateLimitRule))
