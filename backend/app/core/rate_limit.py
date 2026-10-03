from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from time import monotonic

from fastapi import Request
from redis.exceptions import RedisError

from backend.app.core.config import settings
from backend.app.services.scan_queue import ScanQueue


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    remaining: int
    retry_after: int


class RateLimiter:
    """
    Redis-backed fixed-window rate limiter.

    Redis is the shared source of truth so multiple API instances enforce
    the same limit. A local fallback is intentionally kept conservative for
    dependency outages.
    """

    KEY_PREFIX = "cloudsentinel:rate_limit"

    def __init__(
        self,
        queue_factory=ScanQueue,
    ):
        self._queue_factory = queue_factory
        self._fallback: dict[str, tuple[float, int]] = {}

    @staticmethod
    def _trusted_proxy_networks() -> tuple:
        networks = []
        for raw_value in settings.trusted_proxy_ips.split(","):
            value = raw_value.strip()
            if not value:
                continue
            try:
                networks.append(ip_network(value, strict=False))
            except ValueError:
                continue
        return tuple(networks)

    @classmethod
    def _client_ip(cls, request: Request) -> str:
        client = request.client
        peer_ip = client.host if client is not None else "unknown"

        try:
            peer = ip_address(peer_ip)
        except ValueError:
            return peer_ip

        trusted_networks = cls._trusted_proxy_networks()
        if not any(peer in network for network in trusted_networks):
            return peer_ip

        forwarded = request.headers.get("x-forwarded-for", "")
        candidates = [
            value.strip()
            for value in forwarded.split(",")
            if value.strip()
        ]

        if not candidates:
            return peer_ip

        # Walk the proxy chain from right to left. The first address that
        # is not itself trusted is the client address. This avoids trusting
        # spoofed X-Forwarded-For values when the direct peer is untrusted.
        for candidate in reversed(candidates):
            try:
                candidate_ip = ip_address(candidate)
            except ValueError:
                continue

            if not any(candidate_ip in network for network in trusted_networks):
                return candidate

        return candidates[0]

    def _key(self, request: Request, scope: str) -> str:
        return f"{self.KEY_PREFIX}:{scope}:{self._client_ip(request)}"

    def check(
        self,
        request: Request,
        *,
        scope: str,
        limit: int,
        window_seconds: int,
    ) -> RateLimitDecision:
        if limit <= 0 or window_seconds <= 0:
            raise ValueError("Rate limit configuration must be positive")

        key = self._key(request, scope)
        queue = None

        try:
            queue = self._queue_factory()

            now = queue.client.time()
            epoch_seconds = int(now[0])
            window = epoch_seconds // window_seconds
            redis_key = f"{key}:{window}"

            count = int(queue.client.incr(redis_key))

            if count == 1:
                queue.client.expire(
                    redis_key,
                    window_seconds,
                )

            remaining = max(limit - count, 0)

            if count > limit:
                return RateLimitDecision(
                    allowed=False,
                    remaining=0,
                    retry_after=max(
                        1,
                        window_seconds
                        - (epoch_seconds % window_seconds),
                    ),
                )

            return RateLimitDecision(
                allowed=True,
                remaining=remaining,
                retry_after=0,
            )

        except (RedisError, OSError, ConnectionError):
            # Authentication and scanning should remain available during a
            # transient Redis outage. The in-process fallback still places a
            # conservative bound on a single API instance.
            return self._check_fallback(
                key=key,
                limit=limit,
                window_seconds=window_seconds,
            )

        finally:
            if queue is not None:
                queue.close()

    def _check_fallback(
        self,
        *,
        key: str,
        limit: int,
        window_seconds: int,
    ) -> RateLimitDecision:
        now = monotonic()
        window_started, count = self._fallback.get(
            key,
            (now, 0),
        )

        if now - window_started >= window_seconds:
            window_started = now
            count = 0

        count += 1
        self._fallback[key] = (window_started, count)

        if count > limit:
            elapsed = int(now - window_started)

            return RateLimitDecision(
                allowed=False,
                remaining=0,
                retry_after=max(
                    1,
                    window_seconds - elapsed,
                ),
            )

        return RateLimitDecision(
            allowed=True,
            remaining=max(limit - count, 0),
            retry_after=0,
        )


rate_limiter = RateLimiter()
