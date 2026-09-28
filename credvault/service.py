"""High level credential management service.

Concurrency model
-----------------
All read/verify/mutate sequences take the single re-entrant
:attr:`CredentialStore.lock`, perform in-memory changes and call
``store.commit()`` while still holding it. Concurrent logins, password
changes and retries are therefore serialised; there is no observable
half-upgraded state. Because the commit is one atomic filesystem replace
(see :mod:`credvault.store`), the same guarantee holds across crashes.

"Successful verification never rolled back"
-------------------------------------------
Password verification happens first. Only a *successful* login enters the
rehash path. The rehash result is independently checked against the same
password inside the same locked transaction; if rehashing or the check
fails, the old (verified) credential is kept untouched and a
``rehash_failure`` event is committed. The login itself remains successful.

Failure counters are only mutated by failed/locked attempts -- the rehash
path never touches them.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import IO, Any

from .audit import AuditLog
from .config import ServiceConfig
from .hashes import AlgorithmRegistry, PasswordHasher, default_registry
from .models import (
    LockState,
    StoredCredential,
    VerifyOutcome,
    VerifyResult,
)
from .policy import LockPolicy, MigrationPolicy
from .store import CredentialStore


class AccountExistsError(ValueError):
    pass


class AccountNotFoundError(KeyError):
    pass


class CredentialService:
    """Register, verify, lock, disable/reset and transparently upgrade."""

    def __init__(
        self,
        store: CredentialStore,
        registry: AlgorithmRegistry,
        config: ServiceConfig | None = None,
        *,
        audit_sink: IO[str] | None = None,
        now: Callable[[], float] = time.time,
    ) -> None:
        self._store = store
        self._registry = registry
        self._config = config or ServiceConfig()
        self._now = now
        self._audit = AuditLog(audit_sink, initial_events=store.read_events(), now=now)
        self._locks = LockPolicy(
            max_failures=self._config.max_failures,
            lock_seconds=self._config.lock_seconds,
            now=now,
        )
        self._migration = MigrationPolicy(
            mode=self._config.migration_mode,
            sample_rate=self._config.migration_sample_rate,
            batch_size=self._config.batch_size,
        )

    # ------------------------------------------------------------------
    # construction
    # ------------------------------------------------------------------
    @classmethod
    def open(
        cls,
        path: str | Path,
        config: ServiceConfig | None = None,
        *,
        audit_sink: IO[str] | None = None,
        registry: AlgorithmRegistry | None = None,
    ) -> CredentialService:
        store = CredentialStore(path)
        service = cls(
            store,
            registry or default_registry(),
            config,
            audit_sink=audit_sink,
        )
        with store.lock:
            event = service._audit.emit(
                "startup_recovery",
                None,
                {"loaded_accounts": str(len(store.accounts()))},
            )
            store.append_events([event])
            store.commit()
        return service

    def register_algorithm(
        self, hasher: PasswordHasher, *, set_default: bool = False
    ) -> None:
        """Register a new algorithm without breaking any existing data."""
        self._registry.register(hasher, set_default=set_default)
        if set_default:
            # frozen config -> replace with an updated copy
            self._config = ServiceConfig(
                default_algorithm=hasher.name,
                default_params=self._config.default_params,
                max_failures=self._config.max_failures,
                lock_seconds=self._config.lock_seconds,
                migration_mode=self._config.migration_mode,
                migration_sample_rate=self._config.migration_sample_rate,
                batch_size=self._config.batch_size,
            )

    def reset_migration_window(self) -> None:
        self._migration.reset_window()

    # ------------------------------------------------------------------
    # small internal helpers
    # ------------------------------------------------------------------
    def _default_hasher_name(self) -> str:
        configured = self._config.default_algorithm
        return configured if self._registry.is_registered(configured) else self._registry.default_name

    def _hash_with_default(self, password: str) -> StoredCredential:
        name = self._default_hasher_name()
        hasher = self._registry.get(name)
        params = hasher.hash(password, params=self._config.default_params)
        return StoredCredential(algorithm=name, params=params, version=1)

    def _is_stale(self, credential: StoredCredential) -> bool:
        default_name = self._default_hasher_name()
        if credential.algorithm != default_name:
            return True
        hasher = self._registry.get(credential.algorithm)
        return bool(hasher.needs_upgrade(credential.params, self._config.default_params))

    def _commit_events(self, events: list) -> None:
        self._store.append_events(events)
        self._store.commit()

    # ------------------------------------------------------------------
    # credential lifecycle
    # ------------------------------------------------------------------
    def create_account(self, username: str, password: str) -> None:
        """Create an enabled account, hashing with the default algorithm."""
        with self._store.lock:
            if username in self._store.accounts():
                raise AccountExistsError(username)
            credential = self._hash_with_default(password)
            self._store.create_account_record(username, credential)
            event = self._audit.emit(
                "password_set", username, {"algorithm": credential.algorithm}
            )
            self._commit_events([event])

    def set_password(self, username: str, password: str) -> None:
        """Set or replace a password with the default algorithm."""
        with self._store.lock:
            credential = self._hash_with_default(password)
            existing = self._store.accounts().get(username)
            if existing is None:
                self._store.create_account_record(username, credential)
                kind = "password_set"
            else:
                existing["credential"] = credential
                existing["lock"] = LockState()
                existing["rehash_epoch"] += 1
                kind = "password_changed"
            event = self._audit.emit(kind, username, {"algorithm": credential.algorithm})
            self._commit_events([event])

    def change_password(
        self, username: str, old_password: str, new_password: str
    ) -> bool:
        """Change password after verifying the current one.

        Disabled or locked accounts cannot change their password this way.
        """
        with self._store.lock:
            record = self._store.accounts().get(username)
            if record is None:
                raise AccountNotFoundError(username)
            credential: StoredCredential = record["credential"]
            if credential.disabled:
                self._commit_events(
                    [self._audit.emit("verify_failure", username, {"reason": "disabled"})]
                )
                return False
            if self._locks.is_locked(record["lock"]):
                return False
            if not self._registry.is_registered(credential.algorithm):
                return False
            hasher = self._registry.get(credential.algorithm)
            if not hasher.verify(old_password, credential.params):
                new_lock, just_locked = self._locks.register_failure(record["lock"])
                record["lock"] = new_lock
                events = [
                    self._audit.emit(
                        "verify_failure", username, {"reason": "bad_credential"}
                    )
                ]
                if just_locked:
                    events.append(
                        self._audit.emit("account_locked", username)
                    )
                self._commit_events(events)
                return False
            credential = self._hash_with_default(new_password)
            record["credential"] = credential
            record["lock"] = LockState()
            record["rehash_epoch"] += 1
            event = self._audit.emit(
                "password_changed", username, {"algorithm": credential.algorithm}
            )
            self._commit_events([event])
            return True

    def reset_password(
        self, username: str, new_password: str, *, unlock: bool = True
    ) -> bool:
        """Administrative reset; old credentials can never validate again."""
        with self._store.lock:
            record = self._store.accounts().get(username)
            if record is None:
                raise AccountNotFoundError(username)
            credential = self._hash_with_default(new_password)
            record["credential"] = credential
            record["rehash_epoch"] += 1
            if unlock:
                record["lock"] = LockState()
            event = self._audit.emit(
                "password_reset", username, {"algorithm": credential.algorithm}
            )
            self._commit_events([event])
            return True

    def disable_account(self, username: str) -> None:
        with self._store.lock:
            record = self._store.accounts().get(username)
            if record is None:
                raise AccountNotFoundError(username)
            credential: StoredCredential = record["credential"]
            if not credential.disabled:
                record["credential"] = StoredCredential(
                    algorithm=credential.algorithm,
                    params=credential.params,
                    version=credential.version,
                    disabled=True,
                )
                event = self._audit.emit("account_disabled", username)
                self._commit_events([event])

    def enable_account(self, username: str) -> None:
        with self._store.lock:
            record = self._store.accounts().get(username)
            if record is None:
                raise AccountNotFoundError(username)
            credential: StoredCredential = record["credential"]
            if credential.disabled:
                record["credential"] = StoredCredential(
                    algorithm=credential.algorithm,
                    params=credential.params,
                    version=credential.version,
                    disabled=False,
                )
                event = self._audit.emit("account_enabled", username)
                self._commit_events([event])

    def delete_account(self, username: str) -> None:
        with self._store.lock:
            if username not in self._store.accounts():
                raise AccountNotFoundError(username)
            del self._store.accounts()[username]
            event = self._audit.emit("account_deleted", username)
            self._commit_events([event])

    # ------------------------------------------------------------------
    # verification + transparent upgrade
    # ------------------------------------------------------------------
    def verify(self, username: str, password: str) -> VerifyResult:
        with self._store.lock:
            record = self._store.accounts().get(username)
            now = self._now()
            if record is None:
                self._commit_events(
                    [self._audit.emit(
                        "verify_failure", username, {"reason": "not_found"}
                    )]
                )
                return VerifyResult(VerifyOutcome.NOT_FOUND)

            credential: StoredCredential = record["credential"]
            lock: LockState = record["lock"]

            if credential.disabled:
                self._commit_events(
                    [self._audit.emit(
                        "verify_failure", username, {"reason": "disabled"}
                    )]
                )
                return VerifyResult(VerifyOutcome.DISABLED)

            if self._locks.is_locked(lock, now):
                self._commit_events(
                    [self._audit.emit("verify_failure", username, {"reason": "locked"})]
                )
                return VerifyResult(VerifyOutcome.LOCKED, locked_until=lock.locked_until)

            if not self._registry.is_registered(credential.algorithm):
                # Cannot verify -> treat as failure but keep the record.
                new_lock, just_locked = self._locks.register_failure(lock, now)
                record["lock"] = new_lock
                events = [
                    self._audit.emit(
                        "verify_failure",
                        username,
                        {"reason": "unknown_algorithm", "algorithm": credential.algorithm},
                    )
                ]
                if just_locked:
                    events.append(self._audit.emit("account_locked", username))
                self._commit_events(events)
                return VerifyResult(
                    VerifyOutcome.BAD_CREDENTIAL, locked_until=new_lock.locked_until
                )

            hasher = self._registry.get(credential.algorithm)
            if not hasher.verify(password, credential.params):
                new_lock, just_locked = self._locks.register_failure(lock, now)
                record["lock"] = new_lock
                events = [
                    self._audit.emit(
                        "verify_failure",
                        username,
                        {
                            "reason": "bad_credential",
                            "fail_count": str(new_lock.fail_count),
                        },
                    )
                ]
                if just_locked:
                    events.append(self._audit.emit("account_locked", username))
                self._commit_events(events)
                return VerifyResult(
                    VerifyOutcome.BAD_CREDENTIAL, locked_until=new_lock.locked_until
                )

            # ---- verification succeeded; failure counters are cleared on
            # a clean success path only (never as a side effect of rehash).
            migrated = False
            events: list = [self._audit.emit("verify_success", username)]
            stale = self._is_stale(credential)
            if stale and self._migration.should_rehash():
                migrated = self._rehash_locked(record, username, password, events)
                if migrated:
                    self._migration.record_upgrade()

            # Counter reset is a property of successful verification, not of
            # the rehash; the rehash path itself never touches fail_count.
            record["lock"] = self._locks.register_success(lock)
            self._commit_events(events)
            return VerifyResult(
                VerifyOutcome.SUCCESS,
                migrated=migrated,
                locked_until=record["lock"].locked_until,
            )

    def _rehash_locked(
        self,
        record: dict[str, Any],
        username: str,
        password: str,
        events: list,
    ) -> bool:
        """Rehash inside the store transaction. Never raises to caller.

        Returns True only when a new default-algorithm credential has been
        installed and independently verified.
        """
        old_credential: StoredCredential = record["credential"]
        try:
            new_credential = self._hash_with_default(password)
            new_hasher = self._registry.get(new_credential.algorithm)
            if not new_hasher.verify(password, new_credential.params):
                raise RuntimeError("freshly computed credential failed self-check")
            record["credential"] = new_credential
            record["rehash_epoch"] += 1
            events.append(
                self._audit.emit(
                    "rehash_success",
                    username,
                    {
                        "from_algorithm": old_credential.algorithm,
                        "to_algorithm": new_credential.algorithm,
                    },
                )
            )
            return True
        except Exception as exc:  # noqa: BLE001 - intentional boundary: any
            # rehash failure (hashing outage, storage hiccup, bad params)
            # must be contained so the already successful verification is
            # never rolled back; we keep the old credential and audit it.
            # Keep the previously verified credential stored on failure.
            record["credential"] = old_credential
            events.append(
                self._audit.emit(
                    "rehash_failure",
                    username,
                    {"from_algorithm": old_credential.algorithm, "error": type(exc).__name__},
                )
            )
            return False

    # ------------------------------------------------------------------
    # batched / paced upgrades
    # ------------------------------------------------------------------
    def run_upgrade_batch(
        self,
        credentials: dict[str, str] | None = None,
        limit: int | None = None,
        *,
        rehash_all: bool = False,
    ) -> int:
        """Upgrade stale accounts using supplied current passwords.

        ``credentials`` maps username -> current password for accounts an
        operator wishes to upgrade proactively. Only stale, enabled,
        currently unlocked accounts are considered; passwords are used
        transiently and never stored. Returns the number upgraded. Capped by
        ``limit`` (and, unless ``rehash_all``, by the migration policy).
        """
        credentials = credentials or {}
        upgraded = 0
        with self._store.lock:
            considered = 0
            for username in sorted(credentials):
                if limit is not None and upgraded >= limit:
                    break
                record = self._store.accounts().get(username)
                if record is None:
                    continue
                credential: StoredCredential = record["credential"]
                if credential.disabled or self._locks.is_locked(record["lock"]):
                    continue
                if not self._is_stale(credential):
                    continue
                if not rehash_all and not self._migration.should_rehash():
                    break
                considered += 1
                password = credentials[username]
                if not self._registry.get(credential.algorithm).verify(
                    password, credential.params
                ):
                    continue
                events = [self._audit.emit("verify_success", username)]
                if self._rehash_locked(record, username, password, events):
                    upgraded += 1
                    self._migration.record_upgrade()
                self._commit_events(events)
            summary = self._audit.emit(
                "batch_upgrade_considered",
                None,
                {"considered": str(considered), "upgraded": str(upgraded)},
            )
            self._commit_events([summary])
        return upgraded

    # ------------------------------------------------------------------
    # introspection
    # ------------------------------------------------------------------
    def get_algorithm_name(self, username: str) -> str | None:
        record = self._store.get_record(username)
        return None if record is None else record["credential"].algorithm

    def get_credential_version(self, username: str) -> int | None:
        record = self._store.get_record(username)
        return None if record is None else record["credential"].version

    def get_rehash_epoch(self, username: str) -> int | None:
        record = self._store.get_record(username)
        return None if record is None else record["rehash_epoch"]

    def is_disabled(self, username: str) -> bool:
        record = self._store.get_record(username)
        return bool(record and record["credential"].disabled)

    def is_locked(self, username: str, *, now: float | None = None) -> bool:
        record = self._store.get_record(username)
        return bool(record and self._locks.is_locked(record["lock"], now))

    def lock_state(self, username: str) -> LockState | None:
        record = self._store.get_record(username)
        return None if record is None else record["lock"]

    def audit_events(self):
        return self._store.read_events()
