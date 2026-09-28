"""Crash recovery and upgrade throttling scenarios."""

from __future__ import annotations

from credential_store.config import CredentialConfig, UpgradePolicy
from credential_store.hashers import build_default_registry
from credential_store.service import CredentialService
from credential_store.storage import CredentialStorage


def _reopen(path, cfg=None):
    storage = CredentialStorage(path)
    return CredentialService(storage, build_default_registry(), cfg or CredentialConfig()), storage


def test_completed_upgrade_survives_restart_and_verifies(tmp_path):
    path = str(tmp_path / "c.db")
    storage = CredentialStorage(path)
    reg = build_default_registry()
    svc = CredentialService(storage, reg, CredentialConfig())
    legacy = reg.get("legacy_sha1").encode("legacypw")
    storage.create_account("u1", legacy, "legacy_sha1", 1)
    assert svc.verify("u1", "legacypw") is True
    assert storage.get("u1").algorithm_id == "pbkdf2_sha256"
    storage.close()

    svc2, storage2 = _reopen(path)
    rec = storage2.get("u1")
    assert rec.algorithm_id == "pbkdf2_sha256"
    assert svc2.verify("u1", "legacypw") is True
    # ledger must not grow again on subsequent logins
    assert len(storage2.ledger_entries("u1")) == 1
    assert svc2.verify("u1", "legacypw") is True
    assert len(storage2.ledger_entries("u1")) == 1


def test_interrupted_upgrade_leaves_account_loginable(tmp_path):
    """Simulate a crash *before* the upgrade commit: nothing was booked."""
    path = str(tmp_path / "c.db")
    storage = CredentialStorage(path)
    reg = build_default_registry()
    legacy = reg.get("legacy_sha1").encode("legacypw")
    storage.create_account("u1", legacy, "legacy_sha1", 1)
    storage.close()

    # A fresh process must still verify the legacy hash and migrate it.
    svc2, storage2 = _reopen(path)
    assert svc2.verify("u1", "legacypw") is True
    assert storage2.get("u1").algorithm_id == "pbkdf2_sha256"
    assert len(storage2.ledger_entries("u1")) == 1


def test_rollout_fraction_controls_pace(tmp_path):
    import random

    storage = CredentialStorage(str(tmp_path / "c.db"))
    reg = build_default_registry()
    cfg = CredentialConfig(upgrade=UpgradePolicy(enabled=True, rollout_fraction=0.25))
    svc = CredentialService(storage, reg, cfg, rng=random.Random(7))
    for i in range(40):
        legacy = reg.get("legacy_sha1").encode("pw")
        storage.create_account(f"u{i}", legacy, "legacy_sha1", 1)
    for i in range(40):
        assert svc.verify(f"u{i}", "pw") is True  # login always succeeds
    migrated = sum(1 for i in range(40) if not svc.needs_upgrade(f"u{i}"))
    assert 3 <= migrated <= 20  # roughly a quarter with slack
    # skipped accounts remain verifiable on legacy data
    still_old = [i for i in range(40) if svc.needs_upgrade(f"u{i}")]
    assert still_old
    for i in still_old[:5]:
        assert svc.verify(f"u{i}", "pw") is True


def test_rate_cap_bursts_are_queued_behind_the_limit(tmp_path):
    storage = CredentialStorage(str(tmp_path / "c.db"))
    reg = build_default_registry()
    cfg = CredentialConfig(upgrade=UpgradePolicy(
        rollout_fraction=1.0, max_upgrades_per_minute=5))
    svc = CredentialService(storage, reg, cfg)
    for i in range(20):
        legacy = reg.get("legacy_sha1").encode("pw")
        storage.create_account(f"u{i}", legacy, "legacy_sha1", 1)
    for i in range(20):
        assert svc.verify(f"u{i}", "pw") is True
    migrated = len(storage.ledger_entries())
    assert migrated == 5
    # unmigrated accounts are still perfectly usable
    assert svc.verify("u19", "pw") is True


def test_upgrade_can_ramp_cost(tmp_path):
    storage = CredentialStorage(str(tmp_path / "c.db"))
    reg = build_default_registry()
    # current accounts sit on the default at a low cost
    low = reg.default().encode("pw", cost=1000)
    storage.create_account("u1", low, "pbkdf2_sha256", 1)
    cfg = CredentialConfig(default_cost=5000,
                           upgrade=UpgradePolicy(rollout_fraction=1.0, rehash_cost=5000))
    svc = CredentialService(storage, reg, cfg)
    assert svc.needs_upgrade("u1")
    assert svc.verify("u1", "pw") is True
    rec = storage.get("u1")
    assert reg.default().cost_of(rec.encoded_hash) == 5000
    assert not svc.needs_upgrade("u1")


def test_upgrade_disabled_leaves_legacy_intact_but_loginable(tmp_path):
    storage = CredentialStorage(str(tmp_path / "c.db"))
    reg = build_default_registry()
    cfg = CredentialConfig(upgrade=UpgradePolicy(enabled=False))
    svc = CredentialService(storage, reg, cfg)
    legacy = reg.get("legacy_sha1").encode("pw")
    storage.create_account("u1", legacy, "legacy_sha1", 1)
    assert svc.verify("u1", "pw") is True
    assert storage.get("u1").algorithm_id == "legacy_sha1"
    assert len(storage.ledger_entries()) == 0
