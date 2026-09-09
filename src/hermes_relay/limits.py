"""In-memory rate limits and concurrency gates."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from threading import Lock


@dataclass
class RateDecision:
    allowed: bool
    retry_after_seconds: float = 0.0


class SlidingWindowLimiter:
    """Per-key sliding window limiter (in-memory, process-local)."""

    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def check(self, key: str, limit: int, window_seconds: float = 60.0) -> RateDecision:
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            bucket = self._events[key]
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                retry = max(0.0, window_seconds - (now - bucket[0]))
                return RateDecision(False, retry)
            bucket.append(now)
            return RateDecision(True)

    def reset(self) -> None:
        with self._lock:
            self._events.clear()


class ConcurrencyGate:
    """Simple counter gate used as a second line of defense around Hermes jobs."""

    def __init__(self, maximum: int) -> None:
        self.maximum = maximum
        self._lock = Lock()
        self._current = 0

    @property
    def current(self) -> int:
        with self._lock:
            return self._current

    def try_acquire(self) -> bool:
        with self._lock:
            if self._current >= self.maximum:
                return False
            self._current += 1
            return True

    def release(self) -> None:
        with self._lock:
            if self._current > 0:
                self._current -= 1
