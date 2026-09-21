"""Small in-memory limiter for management login attempts."""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Deque, Dict, Optional


class LoginRateLimiter:
    def __init__(
        self,
        max_failures: int = 5,
        window_seconds: int = 10 * 60,
        block_seconds: int = 15 * 60,
    ) -> None:
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.block_seconds = block_seconds
        self._failures: Dict[str, Deque[float]] = {}
        self._blocked_until: Dict[str, float] = {}
        self._lock = threading.Lock()

    def retry_after(self, key: str, now: Optional[float] = None) -> int:
        current = time.monotonic() if now is None else now
        with self._lock:
            blocked_until = self._blocked_until.get(key, 0)
            if blocked_until <= current:
                self._blocked_until.pop(key, None)
                self._prune_failures(key, current)
                return 0
            return max(1, int(blocked_until - current))

    def record_failure(self, key: str, now: Optional[float] = None) -> int:
        current = time.monotonic() if now is None else now
        with self._lock:
            failures = self._failures.setdefault(key, deque())
            cutoff = current - self.window_seconds
            while failures and failures[0] < cutoff:
                failures.popleft()
            failures.append(current)
            if len(failures) >= self.max_failures:
                blocked_until = current + self.block_seconds
                self._blocked_until[key] = blocked_until
                failures.clear()
                return self.block_seconds
            return 0

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)
            self._blocked_until.pop(key, None)

    def _prune_failures(self, key: str, current: float) -> None:
        failures = self._failures.get(key)
        if not failures:
            self._failures.pop(key, None)
            return
        cutoff = current - self.window_seconds
        while failures and failures[0] < cutoff:
            failures.popleft()
        if not failures:
            self._failures.pop(key, None)
