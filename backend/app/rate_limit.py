"""
Minimal in-memory, per-IP sliding-window rate limiter.

For a multi-instance production deployment, replace this with a shared
store (e.g. Redis) — this in-process version is sufficient for a
single-instance MVP.
"""
import time
from collections import defaultdict, deque

from fastapi import Request, HTTPException

from .config import get_settings

_hits: dict[str, deque] = defaultdict(deque)


def rate_limit_dependency(request: Request) -> None:
    settings = get_settings()
    limit = settings.RATE_LIMIT_PER_MINUTE
    window_seconds = 60

    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    bucket = _hits[client_ip]

    while bucket and now - bucket[0] > window_seconds:
        bucket.popleft()

    if len(bucket) >= limit:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: max {limit} requests per minute.",
        )

    bucket.append(now)
