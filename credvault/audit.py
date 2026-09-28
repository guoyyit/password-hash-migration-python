"""Audit event logging that never leaks passwords or password hashes.

Audit events are *produced* here (validated, sanitised and sequence
numbered). Durability is provided by :class:`credvault.store.CredentialStore`
which commits new events together with the state change they describe in a
single atomic write, so an upgrade and its ``rehash_success`` event can
never diverge. An optional text ``sink`` may additionally receive one JSON
line per event for operational log shipping, but the state file remains the
authoritative, de-duplicatable source of truth (monotonic ``seq``).
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Iterable
from typing import IO, Any

from .models import AuditEvent

#: Event kinds that are allowed to appear in the audit trail.
ALLOWED_KINDS = frozenset(
    {
        "verify_success",
        "verify_failure",
        "account_locked",
        "rehash_success",
        "rehash_failure",
        "password_set",
        "password_changed",
        "password_reset",
        "account_disabled",
        "account_enabled",
        "account_deleted",
        "batch_upgrade_considered",
        "startup_recovery",
    }
)

#: Keys that must never appear in an audit event's detail payload.
FORBIDDEN_DETAIL_KEYS = frozenset(
    {"password", "passwd", "pwd", "secret", "digest", "hash", "salt", "token"}
)

_MAX_VALUE_LEN = 512


class AuditError(ValueError):
    """Raised when an attempt is made to log unsafe or unknown content."""


def sanitize_detail(detail: dict[str, Any] | None) -> dict[str, str]:
    """Validate and normalise an event detail payload.

    Raises :class:`AuditError` if a key name hints at secret material.
    """
    safe: dict[str, str] = {}
    for key, value in (detail or {}).items():
        normalised = str(key).lower()
        for forbidden in FORBIDDEN_DETAIL_KEYS:
            if forbidden in normalised:
                raise AuditError(f"forbidden audit detail key: {key!r}")
        text = "" if value is None else str(value)
        if len(text) > _MAX_VALUE_LEN:
            text = text[:_MAX_VALUE_LEN]
        safe[normalised] = text
    return safe


class AuditLog:
    """Validates, sequences and (optionally) mirrors audit events."""

    def __init__(
        self,
        sink: IO[str] | None = None,
        *,
        initial_events: Iterable[AuditEvent] = (),
        now: Callable[[], float] = time.time,
    ) -> None:
        self._sink = sink
        self._now = now
        self._lock = threading.Lock()
        self._events: list[AuditEvent] = list(initial_events)
        self._seq = self._events[-1].seq if self._events else 0

    def emit(
        self,
        kind: str,
        username: str | None,
        detail: dict[str, Any] | None = None,
    ) -> AuditEvent:
        if kind not in ALLOWED_KINDS:
            raise AuditError(f"unknown audit event kind: {kind!r}")
        safe = sanitize_detail(detail)
        with self._lock:
            self._seq += 1
            event = AuditEvent(
                seq=self._seq,
                at=self._now(),
                kind=kind,
                username=username,
                detail=safe,
            )
            self._events.append(event)
            if self._sink is not None:
                # Mirroring is best effort and never the durability path.
                self._sink.write(
                    json.dumps(
                        {
                            "seq": event.seq,
                            "at": event.at,
                            "kind": event.kind,
                            "username": event.username,
                            "detail": event.detail,
                        },
                        sort_keys=True,
                    )
                    + "\n"
                )
                self._sink.flush()
        return event

    def events(self) -> list[AuditEvent]:
        with self._lock:
            return list(self._events)

    def last_seq(self) -> int:
        with self._lock:
            return self._seq
