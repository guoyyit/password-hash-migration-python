"""Configuration knobs for the credential service."""

from __future__ import annotations

from dataclasses import dataclass

from .models import MigrationMode


@dataclass(frozen=True)
class ServiceConfig:
    """Tunables for locking, migration pacing and default hashing cost.

    Attributes:
        default_algorithm: Name of the algorithm used for every new or
            changed password and for transparent rehashes.
        default_params: Cost parameters handed to the default hasher
            (e.g. ``{"iterations": 200000}``). A credential whose cost is
            below these values is considered stale and eligible for upgrade.
        max_failures: Consecutive failures that trigger a lock.
        lock_seconds: Lock duration once ``max_failures`` is reached.
        migration_mode: ALWAYS / SAMPLED / OFF for on-login upgrades.
        migration_sample_rate: Eligibility probability in SAMPLED mode
            (0.0..1.0) -- controls upgrade pace and hence CPU load.
        batch_size: At most this many transparent upgrades per rolling
            window (0 disables the cap). Call ``reset_migration_window``
            (or restart the process) to begin the next batch.
    """

    default_algorithm: str = "pbkdf2_sha256"
    default_params: dict[str, int] | None = None

    max_failures: int = 5
    lock_seconds: float = 900.0

    migration_mode: MigrationMode = MigrationMode.ALWAYS
    migration_sample_rate: float = 1.0
    batch_size: int = 0
