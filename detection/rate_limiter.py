"""
Sliding-Window Rate Limiter for Beacon Listeners
CyberGuard SOC — Honeytoken-Based Insider Threat Detector
"""

import time
from collections import defaultdict
from typing import Dict, List


class SlidingWindowRateLimiter:
    """
    In-memory sliding-window rate limiter.
    Limits requests per IP over a rolling time window.
    """

    def __init__(self, max_requests: int = 30, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._history: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(self, ip_address: str) -> bool:
        """
        Check if a request from ip_address is allowed.
        Prunes timestamps outside the rolling window.
        Returns True if allowed, False if exceeded limit.
        """
        now = time.time()
        window_start = now - self.window_seconds

        timestamps = self._history[ip_address]
        # Retain only timestamps within the active sliding window
        self._history[ip_address] = [ts for ts in timestamps if ts > window_start]

        if len(self._history[ip_address]) >= self.max_requests:
            return False

        self._history[ip_address].append(now)
        return True

    def reset(self):
        """Reset all rate limiter state."""
        self._history.clear()


# Default singleton instance
rate_limiter = SlidingWindowRateLimiter(max_requests=30, window_seconds=60)
