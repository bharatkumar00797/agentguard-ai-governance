"""Sliding-window rate limits and spend budgets, keyed per agent and tool."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable

Clock = Callable[[], float]


class RateLimiter:
    def __init__(self, clock: Clock = time.monotonic) -> None:
        self._clock = clock
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window_s: float, *, consume: bool = True) -> bool:
        """Return True when another call fits in the window (and record it if consume)."""
        now = self._clock()
        with self._lock:
            hits = self._hits[key]
            while hits and hits[0] <= now - window_s:
                hits.popleft()
            if len(hits) >= limit:
                return False
            if consume:
                hits.append(now)
            return True


class BudgetTracker:
    def __init__(self) -> None:
        self._spent: dict[str, float] = defaultdict(float)
        self._lock = threading.Lock()

    def spent(self, key: str) -> float:
        with self._lock:
            return self._spent[key]

    def try_spend(self, key: str, amount: float, budget: float) -> bool:
        with self._lock:
            if self._spent[key] + amount > budget + 1e-9:
                return False
            self._spent[key] += amount
            return True
