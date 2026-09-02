import threading
import time


class RateLimiter:
    """Thread-safe limiter for spacing outbound scanner network operations."""

    def __init__(self, requests_per_second: float) -> None:
        if requests_per_second <= 0:
            raise ValueError("requests_per_second must be greater than zero")
        self._interval = 1.0 / requests_per_second
        self._lock = threading.Lock()
        self._next_permitted = time.monotonic()

    def acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            wait_time = self._next_permitted - now
            if wait_time > 0:
                time.sleep(wait_time)
            self._next_permitted = max(time.monotonic(), self._next_permitted) + self._interval


def create_rate_limiter(requests_per_second: float | None) -> RateLimiter | None:
    if requests_per_second is None:
        return None
    return RateLimiter(requests_per_second)
