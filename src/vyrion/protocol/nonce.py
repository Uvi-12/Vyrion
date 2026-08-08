"""Atomic single-use nonce consumption.

consume_once returns True for exactly one caller per nonce, even under
concurrency. The in-memory implementation uses a lock so 100 concurrent workers
yield one success. Production backends (Redis SET NX EX, a unique DB insert)
implement the same contract.
"""

from __future__ import annotations

import threading
import time
from typing import Protocol


class NonceStore(Protocol):
    def consume_once(self, *, nonce: str, expires_at: float, execution_id: str) -> bool:
        ...


class InMemoryNonceStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._spent: dict[str, str] = {}

    def consume_once(self, *, nonce: str, expires_at: float, execution_id: str) -> bool:
        now = time.time()
        with self._lock:
            # expire old entries lazily
            if nonce in self._spent:
                return False
            if expires_at < now:
                return False
            self._spent[nonce] = execution_id
            return True
