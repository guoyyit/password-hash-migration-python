"""Failure counting, account locking and upgrade pacing decisions."""

from __future__ import annotations

import random
import threading
from collections.abc import Callable

from .models import LockState, MigrationMode


class LockPolicy:
    """Pure logic for failure counting and lock expiry.

    The counters themselves live on :class:`~credvault.models.LockState`
    inside the persistent store; this class only computes new states, so a
    rehash path can verify successfully without touching the counter.
    """

    def __init__(
        self,
        max_failures: int = 5,
        lock_seconds: float = 900.0,
        now: Callable[[], float] | None = None,
    ) -> None:
        import time

        self.max_failures = max_failures
        self.lock_seconds = lock_seconds
        self._now = now or time.time

    def is_locked(self, lock: LockState, now: float | None = None) -> bool:
        if lock.locked_until is None:
            return False
        current = self._now() if now is None else now
        return lock.locked_until > current

    def register_failure(
        self, lock: LockState, now: float | None = None
    ) -> tuple[LockState, bool]:
        """Return ``(new_state, just_locked)``.

        An expired lock behaves like a fresh failure series: the counter
        restarts at 1 rather than accumulating across lock windows.
        """
        current = self._now() if now is None else now
        if lock.locked_until is not None and lock.locked_until <= current:
            fail_count = 1
            locked_until = None
        else:
            fail_count = lock.fail_count + 1
            locked_until = lock.locked_until
        just_locked = False
        if locked_until is None and fail_count >= self.max_failures:
            locked_until = current + self.lock_seconds
            just_locked = True
        return (
            LockState(
                fail_count=fail_count,
                locked_until=locked_until,
                last_fail_at=current,
            ),
            just_locked,
        )

    def register_success(self, lock: LockState) -> LockState:
        return LockState()

    def clear_lock(self, lock: LockState) -> LockState:
        return LockState()


class MigrationPolicy:
    """Decides whether a given successful login performs an on-login rehash.

    * ``ALWAYS``  - every login on a stale credential is eligible;
    * ``SAMPLED`` - eligible with probability ``sample_rate``; additionally a
      process-wide ``batch_size`` cap limits how many upgrades may happen in
      one rolling window (``reset_window()`` starts a new window);
    * ``OFF``     - transparent upgrades are disabled (stale accounts may
      still log in forever; explicit :meth:`run_upgrade_batch` still works).
    """

    def __init__(
        self,
        mode: MigrationMode,
        sample_rate: float = 1.0,
        batch_size: int = 0,
        rng: Callable[[], float] | None = None,
    ) -> None:
        self.mode = mode
        self.sample_rate = min(1.0, max(0.0, float(sample_rate)))
        self.batch_size = max(0, int(batch_size))
        self._rng: Callable[[], float] = rng or random.random
        self._lock = threading.Lock()
        self._window_upgrades = 0

    def reset_window(self) -> None:
        with self._lock:
            self._window_upgrades = 0

    def window_upgrades(self) -> int:
        with self._lock:
            return self._window_upgrades

    def should_rehash(self, rng_value: float | None = None) -> bool:
        if self.mode == MigrationMode.OFF:
            return False
        if self.mode == MigrationMode.SAMPLED:
            roll = self._rng() if rng_value is None else rng_value
            if roll >= self.sample_rate:
                return False
        with self._lock:
            if self.batch_size and self._window_upgrades >= self.batch_size:
                return False
        return True

    def record_upgrade(self) -> None:
        """Account for one completed upgrade toward the batch cap."""
        with self._lock:
            self._window_upgrades += 1
