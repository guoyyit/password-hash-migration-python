"""Durable storage backend.

SQLite is used because it gives us:

* atomic, durable transactions (``BEGIN IMMEDIATE`` write transactions with
  explicit ``commit``) so an upgrade is either fully visible or not visible
  after a crash;
* a compare-and-swap style version counter on every credential row, which
  prevents interleaved password changes and rehashes from clobbering each
  other;
* an append-only upgrade ledger with a unique attempt id, guaranteeing the
  same upgrade is never booked twice.

Sensitive columns: only the encoded hash is stored. Plaintext passwords are
never written anywhere.
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass

from .audit import AuditEvent

_SCHEMA = """
CREATE TABLE IF NOT EXISTS credentials (
    account_id    TEXT PRIMARY KEY,
    encoded_hash  TEXT NOT NULL,
    algorithm_id  TEXT NOT NULL,
    algo_version  INTEGER NOT NULL,
    disabled      INTEGER NOT NULL DEFAULT 0,
    failed_count  INTEGER NOT NULL DEFAULT 0,
    last_failure_at REAL,
    locked_until  REAL,
    row_version   INTEGER NOT NULL DEFAULT 1,
    created_at    REAL NOT NULL,
    updated_at    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS upgrade_ledger (
    attempt_id     TEXT PRIMARY KEY,
    account_id     TEXT NOT NULL,
    from_algorithm TEXT NOT NULL,
    to_algorithm   TEXT NOT NULL,
    committed_at   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_upgrade_ledger_account ON upgrade_ledger(account_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    account_id TEXT NOT NULL,
    ts         REAL NOT NULL,
    detail     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_log_account ON audit_log(account_id);
"""


@dataclass(frozen=True)
class CredentialRecord:
    account_id: str
    encoded_hash: str
    algorithm_id: str
    version: int
    disabled: bool
    failed_count: int
    last_failure_at: float | None
    locked_until: float | None
    row_version: int


@dataclass(frozen=True)
class LedgerEntry:
    attempt_id: str
    account_id: str
    from_algorithm: str
    to_algorithm: str
    committed_at: float


class _WriteTx:
    """Context manager for an explicit IMMEDIATE write transaction."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def __enter__(self) -> sqlite3.Connection:
        self._conn.execute("BEGIN IMMEDIATE")
        return self._conn

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is None:
            self._conn.commit()
        else:
            self._conn.rollback()


class CredentialStorage:
    """SQLite-backed credential, lockout and upgrade-ledger storage."""

    def __init__(self, path: str = ":memory:") -> None:
        # isolation_level=None -> we manage transactions ourselves.
        self._conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._tx_lock = threading.Lock()
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    # ------------------------------------------------------------------ utils
    def _write(self) -> _WriteTx:
        # Serialize writers within this process; SQLite serializes the rest.
        return _WriteTx(self._conn)

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> CredentialRecord:
        return CredentialRecord(
            account_id=row["account_id"],
            encoded_hash=row["encoded_hash"],
            algorithm_id=row["algorithm_id"],
            version=row["algo_version"],
            disabled=bool(row["disabled"]),
            failed_count=row["failed_count"],
            last_failure_at=row["last_failure_at"],
            locked_until=row["locked_until"],
            row_version=row["row_version"],
        )

    def _insert_audit(self, conn: sqlite3.Connection, events: "tuple[AuditEvent, ...]") -> None:
        import json

        for event in events:
            conn.execute(
                "INSERT INTO audit_log(event_type, account_id, ts, detail) VALUES (?, ?, ?, ?)",
                (event.type.value, event.account_id, event.timestamp, json.dumps(event.detail, sort_keys=True)),
            )

    # ------------------------------------------------------- account lifecycle
    def create_account(
        self,
        account_id: str,
        encoded_hash: str,
        algorithm_id: str,
        version: int,
        events: tuple[AuditEvent, ...] = (),
    ) -> None:
        import time

        with self._tx_lock, self._write() as conn:
            cursor = conn.execute(
                "SELECT 1 FROM credentials WHERE account_id = ?", (account_id,)
            )
            if cursor.fetchone() is not None:
                from .errors import AccountAlreadyExists

                raise AccountAlreadyExists(account_id)
            now = time.time()
            conn.execute(
                "INSERT INTO credentials(account_id, encoded_hash, algorithm_id, algo_version,"
                " disabled, failed_count, locked_until, row_version, created_at, updated_at)"
                " VALUES (?, ?, ?, ?, 0, 0, NULL, 1, ?, ?)",
                (account_id, encoded_hash, algorithm_id, version, now, now),
            )
            self._insert_audit(conn, events)

    def get(self, account_id: str) -> CredentialRecord | None:
        cursor = self._conn.execute(
            "SELECT * FROM credentials WHERE account_id = ?", (account_id,)
        )
        row = cursor.fetchone()
        return self._row_to_record(row) if row is not None else None

    def _set_disabled(self, account_id: str, disabled: bool, events: "tuple[AuditEvent, ...]") -> bool:
        import time

        with self._tx_lock, self._write() as conn:
            cursor = conn.execute(
                "UPDATE credentials SET disabled = ?, updated_at = ?"
                " WHERE account_id = ? AND disabled <> ?",
                (1 if disabled else 0, time.time(), account_id, 1 if disabled else 0),
            )
            changed = cursor.rowcount > 0
            self._insert_audit(conn, events if changed else ())
            return changed

    def disable(self, account_id: str, events: tuple[AuditEvent, ...] = ()) -> bool:
        return self._set_disabled(account_id, True, events)

    def enable(self, account_id: str, events: tuple[AuditEvent, ...] = ()) -> bool:
        # Re-enabling also clears lockout; the old credential must not be
        # treated as "still locked".
        import time

        with self._tx_lock, self._write() as conn:
            cursor = conn.execute(
                "UPDATE credentials SET disabled = 0, failed_count = 0, locked_until = NULL,"
                " last_failure_at = NULL, updated_at = ? WHERE account_id = ? AND disabled <> 0",
                (time.time(), account_id),
            )
            changed = cursor.rowcount > 0
            self._insert_audit(conn, events if changed else ())
            return changed

    def delete(self, account_id: str, events: tuple[AuditEvent, ...] = ()) -> bool:
        with self._tx_lock, self._write() as conn:
            cursor = conn.execute("DELETE FROM credentials WHERE account_id = ?", (account_id,))
            removed = cursor.rowcount > 0
            self._insert_audit(conn, events if removed else ())
            return removed

    # --------------------------------------------------------- password changes
    def replace_hash(
        self,
        account_id: str,
        encoded_hash: str,
        algorithm_id: str,
        version: int,
        expected_row_version: int,
        events: tuple[AuditEvent, ...] = (),
    ) -> bool:
        """Set/reset password under a row-version CAS; clears lockout state."""
        import time

        with self._tx_lock, self._write() as conn:
            cursor = conn.execute(
                "UPDATE credentials SET encoded_hash = ?, algorithm_id = ?, algo_version = ?,"
                " failed_count = 0, last_failure_at = NULL, locked_until = NULL,"
                " row_version = row_version + 1, updated_at = ?"
                " WHERE account_id = ? AND row_version = ?",
                (encoded_hash, algorithm_id, version, time.time(), account_id, expected_row_version),
            )
            if cursor.rowcount == 0:
                return False
            self._insert_audit(conn, events)
            return True

    # ------------------------------------------------------------- lockout state
    def record_failure(self, account_id: str, at: float) -> CredentialRecord:
        with self._tx_lock, self._write() as conn:
            conn.execute(
                "UPDATE credentials SET failed_count = failed_count + 1, last_failure_at = ?"
                " WHERE account_id = ?",
                (at, account_id),
            )
            row = conn.execute(
                "SELECT * FROM credentials WHERE account_id = ?", (account_id,)
            ).fetchone()
            if row is None:
                from .errors import AccountNotFound

                raise AccountNotFound(account_id)
            record = self._row_to_record(row)
            return record

    def clear_failures(self, account_id: str) -> None:
        with self._tx_lock, self._write() as conn:
            conn.execute(
                "UPDATE credentials SET failed_count = 0, last_failure_at = NULL,"
                " locked_until = NULL WHERE account_id = ?",
                (account_id,),
            )

    def apply_lock(self, account_id: str, until: float, events: tuple[AuditEvent, ...] = ()) -> None:
        with self._tx_lock, self._write() as conn:
            conn.execute(
                "UPDATE credentials SET locked_until = ? WHERE account_id = ?",
                (until, account_id),
            )
            self._insert_audit(conn, events)

    def unlock(self, account_id: str, events: tuple[AuditEvent, ...] = ()) -> None:
        with self._tx_lock, self._write() as conn:
            conn.execute(
                "UPDATE credentials SET locked_until = NULL, failed_count = 0,"
                " last_failure_at = NULL WHERE account_id = ?",
                (account_id,),
            )
            self._insert_audit(conn, events)

    # -------------------------------------------------------- transparent upgrade
    def commit_upgrade(
        self,
        account_id: str,
        new_encoded_hash: str,
        new_algorithm_id: str,
        new_version: int,
        expected_row_version: int,
        attempt_id: str,
        events: tuple[AuditEvent, ...] = (),
    ) -> bool:
        """Atomically swap the hash and book the attempt in the ledger.

        Returns False (without raising) when the row moved underneath (CAS
        miss / concurrent change) or when the attempt was already booked.
        Failure counters are intentionally NOT touched by an upgrade.
        """
        import time

        with self._tx_lock, self._write() as conn:
            row = conn.execute(
                "SELECT algorithm_id, row_version FROM credentials WHERE account_id = ?",
                (account_id,),
            ).fetchone()
            if row is None or row["row_version"] != expected_row_version:
                return False

            # Idempotency: replaying the same attempt id must never book twice.
            dup = conn.execute(
                "SELECT 1 FROM upgrade_ledger WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if dup is not None:
                return False

            cursor = conn.execute(
                "UPDATE credentials SET encoded_hash = ?, algorithm_id = ?, algo_version = ?,"
                " row_version = row_version + 1, updated_at = ?"
                " WHERE account_id = ? AND row_version = ?",
                (
                    new_encoded_hash,
                    new_algorithm_id,
                    new_version,
                    time.time(),
                    account_id,
                    expected_row_version,
                ),
            )
            if cursor.rowcount == 0:
                return False
            conn.execute(
                "INSERT INTO upgrade_ledger(attempt_id, account_id, from_algorithm,"
                " to_algorithm, committed_at) VALUES (?, ?, ?, ?, ?)",
                (attempt_id, account_id, row["algorithm_id"], new_algorithm_id, time.time()),
            )
            self._insert_audit(conn, events)
            return True

    def ledger_entries(self, account_id: str | None = None) -> list[LedgerEntry]:
        if account_id is None:
            rows = self._conn.execute(
                "SELECT * FROM upgrade_ledger ORDER BY committed_at, rowid"
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM upgrade_ledger WHERE account_id = ? ORDER BY committed_at, rowid",
                (account_id,),
            ).fetchall()
        return [
            LedgerEntry(
                attempt_id=r["attempt_id"],
                account_id=r["account_id"],
                from_algorithm=r["from_algorithm"],
                to_algorithm=r["to_algorithm"],
                committed_at=r["committed_at"],
            )
            for r in rows
        ]

    # ------------------------------------------------------------------- audit
    def append_audit(self, event: AuditEvent) -> None:
        import json

        with self._tx_lock, self._write() as conn:
            conn.execute(
                "INSERT INTO audit_log(event_type, account_id, ts, detail) VALUES (?, ?, ?, ?)",
                (event.type.value, event.account_id, event.timestamp, json.dumps(event.detail, sort_keys=True)),
            )

    def audit_events(self) -> list[AuditEvent]:
        import json

        rows = self._conn.execute(
            "SELECT event_type, account_id, ts, detail FROM audit_log ORDER BY id"
        ).fetchall()
        from .audit import AuditEventType

        return [
            AuditEvent(
                type=AuditEventType(row["event_type"]),
                account_id=row["account_id"],
                timestamp=row["ts"],
                detail=json.loads(row["detail"]),
            )
            for row in rows
        ]

    # --------------------------------------------------------------- maintenance
    def scan_outdated(self, current_algorithm_id: str, now: float, limit: int) -> list[CredentialRecord]:
        rows = self._conn.execute(
            "SELECT * FROM credentials"
            " WHERE disabled = 0 AND algorithm_id <> ?"
            " AND (locked_until IS NULL OR locked_until <= ?)"
            " ORDER BY account_id LIMIT ?",
            (current_algorithm_id, now, limit),
        ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def count_by_algorithm(self) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT algorithm_id, COUNT(*) AS n FROM credentials GROUP BY algorithm_id"
        ).fetchall()
        return {r["algorithm_id"]: r["n"] for r in rows}


def open_storage(path: str = ":memory:") -> CredentialStorage:
    return CredentialStorage(path)
