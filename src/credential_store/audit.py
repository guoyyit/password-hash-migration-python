"""Audit events.

Events never carry passwords or stored hashes (those would allow offline
guessing). Only algorithm ids, versions, outcome flags and non-sensitive
identifiers are recorded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol
import threading
import time


class AuditEventType(str, Enum):
    VERIFY_SUCCESS = "verify_success"
    VERIFY_FAILURE = "verify_failure"
    ACCOUNT_LOCKED = "account_locked"
    REHASH_SUCCESS = "rehash_success"
    REHASH_FAILED = "rehash_failed"
    REHASH_SKIPPED = "rehash_skipped"
    PASSWORD_SET = "password_set"
    PASSWORD_RESET = "password_reset"
    ACCOUNT_DISABLED = "account_disabled"
    ACCOUNT_ENABLED = "account_enabled"
    ACCOUNT_DELETED = "account_deleted"


# Keys that must never appear in an audit event detail payload.
_FORBIDDEN_DETAIL_KEYS = frozenset(
    {"password", "passwd", "pwd", "secret", "hash", "encoded", "digest", "salt"}
)


@dataclass(frozen=True)
class AuditEvent:
    type: AuditEventType
    account_id: str
    timestamp: float = field(default_factory=time.time)
    detail: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        leaked = {
            key
            for key in self.detail
            if any(bad in key.lower() for bad in _FORBIDDEN_DETAIL_KEYS)
        }
        if leaked:
            raise ValueError(f"audit event for {self.account_id!r} leaks secrets: {sorted(leaked)}")


class AuditSink(Protocol):
    def emit(self, event: AuditEvent) -> None: ...


class InMemoryAuditSink:
    """Collects events in-process (useful for tests / embedding apps)."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._lock = threading.Lock()

    def emit(self, event: AuditEvent) -> None:
        with self._lock:
            self._events.append(event)

    def events(self) -> list[AuditEvent]:
        with self._lock:
            return list(self._events)


class FanoutAuditSink:
    """Forward every event to all wrapped sinks."""

    def __init__(self, *sinks: AuditSink) -> None:
        self._sinks = sinks

    def emit(self, event: AuditEvent) -> None:
        for sink in self._sinks:
            sink.emit(event)


def fanout(*sinks: AuditSink) -> AuditSink:
    """Return a sink that forwards every event to all given sinks."""
    return FanoutAuditSink(*sinks)
