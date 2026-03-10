"""
SOC-CyBe Security Platform
Module: In-Memory Rate Limiting

Purpose:
This module provides a lightweight per-subject rate limiter for the API.
It is intentionally simple and suitable for local development or single-node
deployments, while still demonstrating the platform's brute-force protection.

Security Considerations:
- Rate limiting slows brute-force login attempts and high-volume API abuse.
- The in-memory implementation is not sufficient for multi-node production on
  its own; distributed deployments should move the same concept to Redis or
  another shared store.

Related Components:
- `app/api/deps.py` for per-request enforcement
- API gateway and Zero Trust design in the broader SOC platform
"""

from collections import defaultdict, deque
from time import time

from fastapi import HTTPException, status


class InMemoryRateLimiter:
    """Track recent request timestamps per subject and reject abusive traffic."""
    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self.requests: dict[str, deque[float]] = defaultdict(deque)

    def check(self, subject: str) -> None:
        """
        Record a request for a subject and raise if the subject exceeds policy.

        The subject is usually a combination of user identity and network
        context so that both stolen credentials and aggressive clients are
        constrained.
        """
        now = time()
        window = self.requests[subject]
        while window and now - window[0] > self.window_seconds:
            window.popleft()
        if len(window) >= self.limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
            )
        window.append(now)
