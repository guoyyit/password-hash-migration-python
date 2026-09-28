"""High-level credential service: verify, transparent upgrade, lockout.

Concurrency model
-----------------
* A per-account in-process lock serialises verify / password-change for the
  same account; cross-process concurrency is resolved by the storage layer's
  row-version CAS.
* A transparent upgrade is one atomic storage transaction (hash swap +
  ledger booking in the same commit). A crash therefore never leaves a
  half-upgraded row.
* The successful verification result is never rolled back when an upgrade
  fails or is throttled; only ``rehash_*`` audit events are recorded.
"""

from __future__ import annotations

import random
import threading
import time
import uuid
from collections import defaultdict, deque
from typing import Callable

from .audit import AuditEvent, AuditEventType, InMemoryAuditSink
from .config import CredentialConfig
from .errors import (
    AccountDisabled,
    AccountLocked,
    AccountNotFound,
    CredentialError,
    InvalidHash,
    UnknownAlgorithm,
)
from .hashers import HasherRegistry, parse_hash
from .storage import CredentialRecord, CredentialStorage


class _RateLimiter:
    """Sliding-window per-process limiter for upgrade commits."""

    def __init__(self, per_minute: int | None, clock: Callable[[], float]) -> None:
        self._per_minute = per_minute
        self._clock = clock
        self._events: deque[float] = deque()
        self._lock = threading.Lock()

    def allow(self) -> bool:
        if self._per_minute is None:
            return True
        cutoff = self._clock() - 60.0
        with self._lock:
            while self._events and self._events[0] <= cutoff:
                self._events.popleft()
            if len(self._events) >= self._per_minute:
                return False
            self._events.append(self._clock())
            return True


class CredentialService:
    """Coordinates storage, hashers, throttling, lockout and auditing.

    Plaintext passwords are only ever received as method arguments and used
    locally; they are never persisted, logged, or stored on the service.
    """

    def __init__(
        self,
        storage: CredentialStorage,
        registry: HasherRegistry,
        config: CredentialConfig | None = None,
        audit_sink=None,
        *,
        clock: Callable[[], float] | None = None,
        rng: random.Random | None = None,
    ) -> None:
        self.storage = storage
        self.registry = registry
        self.config = config or CredentialConfig()
        # Honour the configured default when it differs from the registry's.
        if registry.ids() and self.config.default_algorithm_id not in (None, registry.default().algorithm_id):
            registry.set_default(self.config.default_algorithm_id)
        self._clock = clock or time.time
        self._rng = rng or random.Random()
        self._external_sink = audit_sink
        self._mem_sink = InMemoryAuditSink()
        self._account_locks: defaultdict[str, threading.Lock] = defaultdict(threading.Lock)
        self._locks_guard = threading.Lock()
        self._rate_limiter = _RateLimiter(self.config.upgrade.max_upgrades_per_minute, self._clock)

    # ------------------------------------------------------------------ helpers
    def _lock_for(self, account_id: str) -> threading.Lock:
        with self._locks_guard:
            return self._account_locks[account_id]

    def _emit(self, event_type: AuditEventType, account_id: str, **detail: object) -> None:
        event = AuditEvent(event_type, account_id, self._clock(), detail)
        self._mem_sink.emit(event)
        if self._external_sink is not None:
            self._external_sink.emit(event)
        return event

    def _emit_tx(self, event_type: AuditEventType, account_id: str, **detail: object) -> AuditEvent:
        """Build an event to be persisted inside the storage transaction."""
        return AuditEvent(event_type, account_id, self._clock(), detail)

    def _must_exist(self, account_id: str) -> CredentialRecord:
        record = self.storage.get(account_id)
        if record is None:
            raise AccountNotFound(account_id)
        return record

    def audit_events(self):
        return self._mem_sink.events()

    # ------------------------------------------------------- account lifecycle
    def create_account(self, account_id: str, password: str) -> None:
        with self._lock_for(account_id):
            hasher = self.registry.default()
            encoded = hasher.encode(password, cost=self.config.default_cost)
            event = self._emit_tx(AuditEventType.PASSWORD_SET, account_id,
                                  algorithm=hasher.algorithm_id, version=hasher.version)
            self.storage.create_account(
                account_id, encoded, hasher.algorithm_id, hasher.version, events=(event,)
            )
            self._emit(AuditEventType.PASSWORD_SET, account_id,
                       algorithm=hasher.algorithm_id, version=hasher.version)

    def set_password(self, account_id: str, password: str) -> None:
        """Change the password using the current default algorithm."""
        with self._lock_for(account_id):
            record = self._must_exist(account_id)
            hasher = self.registry.default()
            encoded = hasher.encode(password, cost=self.config.default_cost)
            event = self._emit_tx(AuditEventType.PASSWORD_SET, account_id,
                                  algorithm=hasher.algorithm_id, version=hasher.version)
            updated = self.storage.replace_hash(
                account_id, encoded, hasher.algorithm_id, hasher.version,
                record.row_version, events=(event,),
            )
            if not updated:
                # Concurrent modification; retry once with fresh version.
                record = self._must_exist(account_id)
                updated = self.storage.replace_hash(
                    account_id, encoded, hasher.algorithm_id, hasher.version,
                    record.row_version, events=(event,),
                )
                if not updated:
                    raise CredentialError("concurrent password update conflict")
            self._emit(AuditEventType.PASSWORD_SET, account_id,
                       algorithm=hasher.algorithm_id, version=hasher.version)

    def reset_password(self, account_id: str, new_password: str) -> None:
        """Admin reset: works even when disabled; old credential is invalidated.

        Any prior lockout is cleared; previously presented passwords can no
        longer authenticate because the stored hash is replaced.
        """
        with self._lock_for(account_id):
            record = self._must_exist(account_id)
            hasher = self.registry.default()
            encoded = hasher.encode(new_password, cost=self.config.default_cost)
            event = self._emit_tx(AuditEventType.PASSWORD_RESET, account_id,
                                  algorithm=hasher.algorithm_id, version=hasher.version)
            if not self.storage.replace_hash(
                account_id, encoded, hasher.algorithm_id, hasher.version,
                record.row_version, events=(event,),
            ):
                record = self._must_exist(account_id)
                if not self.storage.replace_hash(
                    account_id, encoded, hasher.algorithm_id, hasher.version,
                    record.row_version, events=(event,),
                ):
                    raise CredentialError("concurrent password update conflict")
            self._emit(AuditEventType.PASSWORD_RESET, account_id,
                       algorithm=hasher.algorithm_id, version=hasher.version)

    def disable_account(self, account_id: str) -> None:
        event = self._emit_tx(AuditEventType.ACCOUNT_DISABLED, account_id)
        if self.storage.disable(account_id, events=(event,)):
            self._emit(AuditEventType.ACCOUNT_DISABLED, account_id)

    def enable_account(self, account_id: str) -> None:
        event = self._emit_tx(AuditEventType.ACCOUNT_ENABLED, account_id)
        if self.storage.enable(account_id, events=(event,)):
            self._emit(AuditEventType.ACCOUNT_ENABLED, account_id)

    def delete_account(self, account_id: str) -> None:
        event = self._emit_tx(AuditEventType.ACCOUNT_DELETED, account_id)
        if self.storage.delete(account_id, events=(event,)):
            self._emit(AuditEventType.ACCOUNT_DELETED, account_id)

    def get_record(self, account_id: str) -> CredentialRecord:
        return self._must_exist(account_id)

    # ------------------------------------------------------------- lockout logic
    def _active_lock(self, record: CredentialRecord) -> float | None:
        if record.locked_until is None:
            return None
        if record.locked_until <= self._clock():
            # Expired: treat as unlocked and clear the stale state durably.
            self.storage.unlock(record.account_id)
            return None
        return record.locked_until

    def is_locked(self, account_id: str) -> bool:
        with self._lock_for(account_id):
            record = self._must_exist(account_id)
            return self._active_lock(record) is not None

    def unlock_account(self, account_id: str) -> None:
        with self._lock_for(account_id):
            self._must_exist(account_id)
            event = self._emit_tx(AuditEventType.ACCOUNT_ENABLED, account_id, reason="admin_unlock")
            self.storage.unlock(account_id, events=(event,))
            self._emit(AuditEventType.ACCOUNT_ENABLED, account_id, reason="admin_unlock")

    def _register_failure(self, record: CredentialRecord) -> None:
        now = self._clock()
        window = self.config.lockout.failure_window_seconds
        # Sliding failure window: a long streak of quiet failures restarts.
        if window is not None and record.last_failure_at is not None and now - record.last_failure_at > window:
            self.storage.clear_failures(record.account_id)
        updated = self.storage.record_failure(record.account_id, now)
        self._emit(
            AuditEventType.VERIFY_FAILURE,
            record.account_id,
            reason="bad_password",
            failures=updated.failed_count,
        )
        if updated.failed_count >= self.config.lockout.max_failures and updated.locked_until is None:
            until = now + self.config.lockout.lockout_seconds
            event = self._emit_tx(AuditEventType.ACCOUNT_LOCKED, record.account_id,
                                  failures=updated.failed_count, until=until)
            self.storage.apply_lock(record.account_id, until, events=(event,))
            self._emit(AuditEventType.ACCOUNT_LOCKED, record.account_id,
                       failures=updated.failed_count, until=until)

    # ---------------------------------------------------------- transparent upgrade
    def _rehash_if_needed(self, record: CredentialRecord, password: str) -> None:
        """Best-effort upgrade. Never raises into the verify() caller."""
        account_id = record.account_id
        policy = self.config.upgrade
        default_hasher = self.registry.default()
        try:
            stored_hasher = self.registry.get(record.algorithm_id)
        except UnknownAlgorithm:
            # Cannot identify the stored algorithm: leave the record alone,
            # but make the situation visible to operators.
            self._emit(AuditEventType.REHASH_SKIPPED, account_id, reason="unknown_algorithm",
                       algorithm=record.algorithm_id)
            return

        if not stored_hasher.needs_upgrade(
            record.encoded_hash,
            current_default_id=default_hasher.algorithm_id,
            current_cost=self.config.default_cost,
        ):
            return

        if not policy.enabled:
            self._emit(AuditEventType.REHASH_SKIPPED, account_id, reason="disabled_by_policy")
            return
        if self._rng.random() >= policy.rollout_fraction:
            self._emit(AuditEventType.REHASH_SKIPPED, account_id, reason="rollout_sampling")
            return
        if not self._rate_limiter.allow():
            self._emit(AuditEventType.REHASH_SKIPPED, account_id, reason="rate_limited")
            return

        attempt_id = uuid.uuid4().hex
        try:
            new_encoded = default_hasher.encode(password, cost=policy.rehash_cost or self.config.default_cost)
            event = self._emit_tx(
                AuditEventType.REHASH_SUCCESS, account_id,
                attempt=attempt_id,
                from_algorithm=record.algorithm_id,
                to_algorithm=default_hasher.algorithm_id,
                to_version=default_hasher.version,
            )
            committed = self.storage.commit_upgrade(
                account_id, new_encoded, default_hasher.algorithm_id, default_hasher.version,
                expected_row_version=record.row_version, attempt_id=attempt_id, events=(event,),
            )
            if committed:
                self._emit(
                    AuditEventType.REHASH_SUCCESS, account_id,
                    attempt=attempt_id,
                    from_algorithm=record.algorithm_id,
                    to_algorithm=default_hasher.algorithm_id,
                )
            else:
                # CAS miss: a concurrent login/password change raced us.
                # Nothing half-committed; safe to leave as-is.
                self._emit(AuditEventType.REHASH_SKIPPED, account_id,
                           reason="concurrent_change", attempt=attempt_id)
        except Exception as exc:  # noqa: BLE001 - rehash must never fail auth
            # The verification already succeeded; only the upgrade failed.
            self._emit(AuditEventType.REHASH_FAILED, account_id,
                       attempt=attempt_id, error=type(exc).__name__)

    # ------------------------------------------------------------- authentication
    def verify(self, account_id: str, password: str) -> bool:
        with self._lock_for(account_id):
            record = self.storage.get(account_id)
            if record is None:
                # Do not reveal account existence; still audit the attempt.
                self._emit(AuditEventType.VERIFY_FAILURE, account_id, reason="unknown_account")
                return False

            if record.disabled:
                self._emit(AuditEventType.VERIFY_FAILURE, account_id, reason="account_disabled")
                raise AccountDisabled(account_id)

            if self._active_lock(record) is not None:
                self._emit(AuditEventType.VERIFY_FAILURE, account_id, reason="account_locked")
                raise AccountLocked(record.locked_until)

            try:
                hasher = self.registry.identify(record.encoded_hash)
                matches = hasher.verify(password, record.encoded_hash)
            except (InvalidHash, UnknownAlgorithm):
                self._emit(AuditEventType.VERIFY_FAILURE, account_id, reason="invalid_stored_hash")
                return False

            if not matches:
                self._register_failure(record)
                return False

            # Successful authentication: clear failure counters (but never as
            # part of a rehash -- the upgrade path intentionally leaves them).
            if record.failed_count or record.locked_until is not None:
                self.storage.clear_failures(account_id)
            self._emit(AuditEventType.VERIFY_SUCCESS, account_id,
                       algorithm=record.algorithm_id)

            # Transparent, best-effort upgrade; counters are not touched here.
            self._rehash_if_needed(record, password)
            return True

    # --------------------------------------------------------- introspection / ops
    def needs_upgrade(self, account_id: str) -> bool:
        record = self._must_exist(account_id)
        default_id = self.registry.default().algorithm_id
        try:
            hasher = self.registry.get(record.algorithm_id)
        except UnknownAlgorithm:
            return False
        return hasher.needs_upgrade(
            record.encoded_hash,
            current_default_id=default_id,
            current_cost=self.config.default_cost,
        )

    def pending_upgrades(self, limit: int = 100) -> list[CredentialRecord]:
        return self.storage.scan_outdated(
            self.registry.default().algorithm_id, self._clock(), limit
        )

    def stats(self) -> dict[str, int]:
        by_algorithm = self.storage.count_by_algorithm()
        default_id = self.registry.default().algorithm_id
        total = sum(by_algorithm.values())
        return {
            "total": total,
            "on_default": by_algorithm.get(default_id, 0),
            "outdated": total - by_algorithm.get(default_id, 0),
            "by_algorithm": by_algorithm,
        }
