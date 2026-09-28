"""Configuration for hashing, upgrade throttling and lockout policy."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class UpgradePolicy:
    """Controls the *pace* and *cost* of transparent upgrades.

    - ``enabled``: master switch; when False, verified legacy hashes are left
      untouched (but still verify).
    - ``rollout_fraction``: 0.0..1.0, fraction of post-login upgrade
      opportunities that are taken (sampled deterministically per attempt).
    - ``max_upgrades_per_minute``: hard per-process rate cap (batch burst
      protection); ``None`` disables the cap.
    - ``rehash_cost``: cost parameter to hash with when upgrading; ``None``
      uses the hasher's built-in default cost.
    """

    enabled: bool = True
    rollout_fraction: float = 1.0
    max_upgrades_per_minute: int | None = None
    rehash_cost: int | None = None


@dataclass(frozen=True)
class LockoutPolicy:
    """Failed-attempt lockout parameters.

    Locks are stored durably and survive process restarts.
    """

    max_failures: int = 5
    lockout_seconds: float = 900.0
    failure_window_seconds: float | None = None


@dataclass(frozen=True)
class CredentialConfig:
    default_algorithm_id: str = "pbkdf2_sha256"
    default_cost: int | None = None
    upgrade: UpgradePolicy = field(default_factory=UpgradePolicy)
    lockout: LockoutPolicy = field(default_factory=LockoutPolicy)
