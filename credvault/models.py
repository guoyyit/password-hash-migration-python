"""Domain types used across the credential vault."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class VerifyOutcome(Enum):
    """Result of a single verification attempt."""

    SUCCESS = "success"
    BAD_CREDENTIAL = "bad_credential"
    LOCKED = "locked"
    DISABLED = "disabled"
    NOT_FOUND = "not_found"


class MigrationMode(Enum):
    """How transparent rehash upgrades are scheduled."""

    ALWAYS = "always"
    SAMPLED = "sampled"
    OFF = "off"


@dataclass(frozen=True)
class StoredCredential:
    """On-disk representation of one account credential.

    ``params`` holds algorithm specific parameters (salt, cost, ...).
    Nothing in this structure is ever a plaintext password.
    """

    algorithm: str
    params: dict[str, Any] = field(default_factory=dict)
    version: int = 1
    disabled: bool = False


@dataclass(frozen=True)
class LockState:
    """Persistent lock bookkeeping for an account."""

    fail_count: int = 0
    locked_until: float | None = None
    last_fail_at: float | None = None


@dataclass(frozen=True)
class AuditEvent:
    """A single audit record.

    ``seq`` is a monotonically increasing, crash persistent sequence number
    so consumers can de-duplicate events across restarts.
    """

    seq: int
    at: float
    kind: str
    username: str | None
    detail: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of :meth:`CredentialService.verify`."""

    outcome: VerifyOutcome
    migrated: bool = False
    locked_until: float | None = None
