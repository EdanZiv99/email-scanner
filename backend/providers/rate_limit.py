"""Sliding-window rate limiter used by external API providers."""
import threading
import time
from collections import deque


class RateLimiter:
    """Sliding-window rate limiter. Thread-safe.

    State is in-process memory — sufficient for single-worker Flask. For multi-worker
    deployments (gunicorn with multiple processes) this would need a shared store like Redis.
    """

    def __init__(self, max_calls: int, window_seconds: float):
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self.calls = deque()
        self.lock = threading.Lock()

    def try_acquire(self) -> bool:
        """Return True if the call is allowed, False if the rate limit is exceeded."""
        with self.lock:
            now = time.time()
            # Evict timestamps that have fallen outside the window.
            while self.calls and self.calls[0] < now - self.window_seconds:
                self.calls.popleft()
            if len(self.calls) >= self.max_calls:
                return False
            self.calls.append(now)
            return True
