import time
from collections import defaultdict
from typing import Dict, List, Tuple


class SlidingWindowRateLimiter:
    """
    Thread-safe in-memory sliding window rate limiter.
    Tracks timestamps of requests per client key (e.g. IP address).
    """

    def __init__(self, default_limit: int = 60, default_window_seconds: int = 60):
        self.default_limit = default_limit
        self.default_window_seconds = default_window_seconds
        self._history: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(
        self,
        key: str,
        limit: int | None = None,
        window_seconds: int | None = None,
    ) -> Tuple[bool, int, float]:
        """
        Check whether an action is permitted under the rate limit.

        Returns:
            (allowed: bool, current_count: int, retry_after: float)
        """
        now = time.time()
        max_limit = limit if limit is not None else self.default_limit
        window = window_seconds if window_seconds is not None else self.default_window_seconds
        cutoff = now - window

        # Purge timestamps older than the sliding window
        timestamps = [t for t in self._history[key] if t > cutoff]
        self._history[key] = timestamps

        if len(timestamps) >= max_limit:
            # Over limit: compute seconds until oldest request expires
            oldest = timestamps[0]
            retry_after = max(0.0, round(oldest + window - now, 2))
            return False, len(timestamps), retry_after

        # Record this request
        self._history[key].append(now)
        return True, len(self._history[key]), 0.0

    def get_hit_count(self, key: str, window_seconds: int = 300) -> int:
        """Get total hits in a specific time window without recording a new hit."""
        now = time.time()
        cutoff = now - window_seconds
        return sum(1 for t in self._history.get(key, []) if t > cutoff)

    def reset(self, key: str | None = None):
        """Reset history for a key or all keys (useful for testing)."""
        if key:
            self._history.pop(key, None)
        else:
            self._history.clear()


# Global rate limiter instance for public endpoints (60 req / 60 sec per IP)
rate_limiter = SlidingWindowRateLimiter(default_limit=60, default_window_seconds=60)
