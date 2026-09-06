from __future__ import annotations

import json
import math
from uuid import uuid4

from .ratelimit import RateLimitDecision, RateLimitRule, _rate_limit_key
from .request import Request
from .stores import RedisStore, StoreUnavailable

_LIMIT_SCRIPT = """
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local max_keys = tonumber(ARGV[1])
local member = ARGV[2]
local n = (#KEYS - 1) / 2
local windows, missing, seen = {}, 0, {}
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
for i = 1, n do
    local key = KEYS[2*i]
    local window = tonumber(ARGV[2*i+2])
    windows[key] = math.max(windows[key] or 0, tonumber(redis.call('GET', KEYS[2*i+1])) or 0, window)
    if not seen[key] then
        seen[key] = true
        if not redis.call('ZSCORE', KEYS[1], key) then missing = missing + 1 end
    end
end
if redis.call('ZCARD', KEYS[1]) + missing > max_keys then return {} end
local results, allowed = {}, true
for i = 1, n do
    local key = KEYS[2*i]
    local limit = tonumber(ARGV[2*i+1])
    local window = tonumber(ARGV[2*i+2])
    redis.call('ZREMRANGEBYSCORE', key, '-inf', now - windows[key])
    local count = redis.call('ZCOUNT', key, '(' .. (now-window), '+inf')
    local first = redis.call('ZRANGEBYSCORE', key, '(' .. (now-window), '+inf', 'WITHSCORES', 'LIMIT', 0, 1)
    local reset = math.max(1, math.ceil(((tonumber(first[2]) or now) + window - now) / 1000))
    if count >= limit then
        allowed = false
        results[i] = {0, limit, 0, reset, reset}
    else
        results[i] = {1, limit, math.max(0, limit-count-1), reset, 0}
    end
end
seen = {}
for i = 1, n do
    local key = KEYS[2*i]
    if not seen[key] then
        seen[key] = true
        if allowed then redis.call('ZADD', key, now, member) end
        local last = redis.call('ZREVRANGE', key, 0, 0, 'WITHSCORES')
        if last[2] then
            local expiry = tonumber(last[2]) + windows[key]
            redis.call('PEXPIREAT', key, expiry)
            redis.call('SET', KEYS[2*i+1], windows[key], 'PXAT', expiry)
            redis.call('ZADD', KEYS[1], expiry, key)
        end
    end
end
return results
"""


class RedisRateLimiter:
    """Atomic shared sliding-window quotas for Redis and Valkey.

    All rules in one phase are evaluated together; a denial never consumes another
    passing quota. Capacity pressure rejects new keys without evicting active ones.
    """

    def __init__(self, store: RedisStore, *, max_keys: int = 10_000) -> None:
        """Initialize a Redis-backed rate limiter with a positive active-key capacity limit.

        Parameters:
                store (RedisStore): Redis or Valkey backend used for rate-limit state.
                max_keys (int): Maximum number of active keys the limiter may track.

        Raises:
                ValueError: If `max_keys` is not a positive integer.
        """
        if isinstance(max_keys, bool) or not isinstance(max_keys, int) or max_keys <= 0:
            raise ValueError("max_keys must be a positive integer.")
        self.store = store
        self.max_keys = max_keys

    async def check(self, rule: RateLimitRule, req: Request, *, endpoint_id: str) -> RateLimitDecision:
        """Evaluate a rate limit rule for a request at the specified endpoint.

        Parameters:
            endpoint_id (str): Identifier of the endpoint associated with the rule.

        Returns:
            RateLimitDecision: The rate-limit decision for the request.
        """
        return (await self.check_batch([(rule, endpoint_id)], req))[0]

    async def check_batch(self, rules: list[tuple[RateLimitRule, str]], req: Request) -> list[RateLimitDecision]:
        """
        Evaluate multiple rate-limit rules for a request as one shared phase.

        Parameters:
                rules (list[tuple[RateLimitRule, str]]): Rate-limit rules paired with their endpoint identifiers.
                req (Request): Request whose identity is evaluated against the rules.

        Returns:
                list[RateLimitDecision]: Decisions for each rule, or an empty list when no rules are provided.

        Raises:
                ValueError: If more than 64 rules are provided.
                StoreUnavailable: If the shared limiter returns invalid accounting data.
        """
        if not rules:
            return []
        if len(rules) > 64:
            raise ValueError("Shared rate limiting supports at most 64 rules in one phase.")
        keys = [self.store.prefix + "ratelimit-registry"]
        args: list[str | int] = [self.max_keys, uuid4().hex]
        for rule, endpoint_id in rules:
            identity = _rate_limit_key(rule, req)
            key = self.store.key("ratelimit:" + json.dumps([rule.scope or endpoint_id, identity]))
            keys.extend((key, key + ":window"))
            args.extend((rule.requests, math.ceil(rule.window_seconds * 1000)))
        rows = await self.store.evaluate(_LIMIT_SCRIPT, keys, args)
        if rows == []:
            req.scope["flasgo.rate_limit_capacity"] = True
            return [RateLimitDecision(False, rule.requests, 0, 1, 1) for rule, _ in rules]
        if not isinstance(rows, list) or len(rows) != len(rules):
            raise StoreUnavailable("Shared limiter returned invalid accounting data.")
        try:
            return [RateLimitDecision(bool(row[0]), *map(int, row[1:])) for row in rows]
        except (TypeError, ValueError, IndexError) as exc:
            raise StoreUnavailable("Shared limiter returned invalid accounting data.") from exc
