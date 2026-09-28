"""Crash-safe persistence for credential records and lock state.

State is one JSON document written atomically (temp file + fsync +
``os.replace`` + directory fsync), so a crash can only ever expose the
previous fully consistent document or the new one -- never a half-written
upgrade. Audit events produced during an operation are committed in the
same document, making "state changed" and "event recorded" indivisible and
making re-bookkeeping detectable via the monotonic event sequence and the
per-account ``rehash_epoch`` counter.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .models import AuditEvent, LockState, StoredCredential

STATE_VERSION = 1


def _credential_from_dict(raw: dict[str, Any]) -> StoredCredential:
    return StoredCredential(
        algorithm=raw["algorithm"],
        params=dict(raw.get("params", {})),
        version=int(raw.get("version", 1)),
        disabled=bool(raw.get("disabled", False)),
    )


def _lock_from_dict(raw: dict[str, Any]) -> LockState:
    return LockState(
        fail_count=int(raw.get("fail_count", 0)),
        locked_until=raw.get("locked_until"),
        last_fail_at=raw.get("last_fail_at"),
    )


def _event_from_dict(raw: dict[str, Any]) -> AuditEvent:
    return AuditEvent(
        seq=int(raw["seq"]),
        at=float(raw["at"]),
        kind=raw["kind"],
        username=raw.get("username"),
        detail=dict(raw.get("detail", {})),
    )


class StoreCorruptionError(RuntimeError):
    """Raised when the on-disk state cannot be safely parsed."""


class CredentialStore:
    """JSON file backed store guarded by a re-entrant process-wide lock."""

    def __init__(self, path: str | Path | None) -> None:
        self._path = Path(path) if path is not None else None
        self._lock = threading.RLock()
        self._state: dict[str, Any] = self._empty_state()
        if self._path is not None and self._path.exists():
            self._state = self._read_unlocked(self._path)

    @staticmethod
    def _empty_state() -> dict[str, Any]:
        return {
            "version": STATE_VERSION,
            "audit_seq": 0,
            "accounts": {},
            "events": [],
        }

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    @property
    def path(self) -> Path | None:
        return self._path

    # ------------------------------------------------------------------
    # persistence
    # ------------------------------------------------------------------
    def _read_unlocked(self, path: Path) -> dict[str, Any]:
        try:
            with path.open("r", encoding="utf-8") as handle:
                raw = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise StoreCorruptionError(f"cannot read state file {path}: {exc}") from exc
        if not isinstance(raw, dict) or "accounts" not in raw:
            raise StoreCorruptionError(f"state file {path} has unexpected layout")
        state = self._empty_state()
        state["version"] = int(raw.get("version", STATE_VERSION))
        state["audit_seq"] = int(raw.get("audit_seq", 0))
        for name, record in raw.get("accounts", {}).items():
            state["accounts"][name] = {
                "credential": _credential_from_dict(record["credential"]),
                "lock": _lock_from_dict(record.get("lock", {})),
                "rehash_epoch": int(record.get("rehash_epoch", 0)),
            }
        state["events"] = [_event_from_dict(e) for e in raw.get("events", [])]
        # Self-heal any inconsistency between counters and event tails.
        if state["events"]:
            state["audit_seq"] = max(state["audit_seq"], state["events"][-1].seq)
        return state

    def _serialise_unlocked(self, state: dict[str, Any]) -> str:
        accounts: dict[str, Any] = {}
        for name, record in state["accounts"].items():
            accounts[name] = {
                "credential": asdict(record["credential"]),
                "lock": asdict(record["lock"]),
                "rehash_epoch": record["rehash_epoch"],
            }
        payload = {
            "version": state["version"],
            "audit_seq": state["audit_seq"],
            "accounts": accounts,
            "events": [asdict(event) for event in state["events"]],
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def commit(self) -> None:
        """Persist the current in-memory state atomically and durably."""
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        text = self._serialise_unlocked(self._state)
        fd, tmp_name = tempfile.mkstemp(
            prefix=".credvault-", suffix=".tmp", dir=str(self._path.parent)
        )
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, self._path)
            self._fsync_dir(self._path.parent)
        except BaseException:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    @staticmethod
    def _fsync_dir(directory: Path) -> None:
        try:
            dir_fd = os.open(str(directory), os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(dir_fd)
        except OSError:
            pass
        finally:
            os.close(dir_fd)

    def reload(self) -> None:
        """Re-read state after a restart (used for recovery verification)."""
        with self._lock:
            if self._path is not None and self._path.exists():
                self._state = self._read_unlocked(self._path)

    # ------------------------------------------------------------------
    # accessors / mutators (callers hold ``self.lock`` while mutating)
    # ------------------------------------------------------------------
    def state(self) -> dict[str, Any]:
        return self._state

    def accounts(self) -> dict[str, Any]:
        return self._state["accounts"]

    def all_usernames(self) -> list[str]:
        with self._lock:
            return sorted(self._state["accounts"])

    def get_record(self, username: str) -> dict[str, Any] | None:
        with self._lock:
            return self._state["accounts"].get(username)

    def create_account_record(
        self, username: str, credential: StoredCredential
    ) -> dict[str, Any]:
        with self._lock:
            record = {
                "credential": credential,
                "lock": LockState(),
                "rehash_epoch": 0,
            }
            self._state["accounts"][username] = record
            return record

    def append_events(self, events: list[AuditEvent]) -> None:
        """Attach events already sequenced by the audit log and bump the seq."""
        with self._lock:
            for event in events:
                self._state["events"].append(event)
                self._state["audit_seq"] = max(self._state["audit_seq"], event.seq)

    def read_events(self) -> list[AuditEvent]:
        with self._lock:
            return list(self._state["events"])
