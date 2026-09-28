"""Local password credential vault with transparent hash upgrade.

Public API:

* :class:`CredentialService` -- credential lifecycle and verification.
* :class:`ServiceConfig` -- locking, default algorithm and migration pace.
* :class:`AlgorithmRegistry` / :class:`PasswordHasher` -- pluggable hash
  algorithms; registering a new one never breaks older credentials.
* :class:`CredentialStore` -- crash-safe JSON persistence.
* :class:`VerifyOutcome` / :class:`VerifyResult` -- verification results.
"""

from __future__ import annotations

from .config import ServiceConfig
from .hashes import (
    AlgorithmRegistry,
    PasswordHasher,
    PBKDF2SHA256Hasher,
    ScryptHasher,
    default_registry,
)
from .models import (
    AuditEvent,
    MigrationMode,
    StoredCredential,
    VerifyOutcome,
    VerifyResult,
)
from .service import (
    AccountExistsError,
    AccountNotFoundError,
    CredentialService,
)
from .store import CredentialStore, StoreCorruptionError

__all__ = [
    "AccountExistsError",
    "AccountNotFoundError",
    "AlgorithmRegistry",
    "AuditEvent",
    "CredentialService",
    "CredentialStore",
    "MigrationMode",
    "PBKDF2SHA256Hasher",
    "PasswordHasher",
    "ScryptHasher",
    "ServiceConfig",
    "StoreCorruptionError",
    "StoredCredential",
    "VerifyOutcome",
    "VerifyResult",
    "default_registry",
]
