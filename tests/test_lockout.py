"""Failure limits, lock expiry, durable locks and reset/disable semantics."""

from __future__ import annotations

from credential_store.audit import AuditEventType
from credential_store.config import CredentialConfig, LockoutPolicy, UpgradePolicy
from credential_store.errors import AccountDisabled, AccountLocked
from credential_store.hashers import build_default_registry
from credential_store.service import CredentialService
from credential_store.storage import CredentialStorage


class FakeClock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


def _svc(path, clock, *, max_failures=3, lockout_seconds=60.0, window=None):
    storage = CredentialStorage(path)
    cfg = CredentialConfig(
        lockout=LockoutPolicy(max_failures=max_failures, lockout_seconds=lockout_seconds,
                              failure_window_seconds=window),
        upgrade=UpgradePolicy(rollout_fraction=0.0),  # upgrades off; focus on lockout
    )
    return CredentialService(storage, build_default_registry(), cfg, clock=clock), storage


def test_lockout_after_threshold_then_expires(tmp_path):
    clock = FakeClock()
    svc, storage = _svc(str(tmp_path / "c.db"), clock)
    svc.create_account("u1", "pw")

    for _ in range(3):
        assert svc.verify("u1", "bad") is False
    assert svc.is_locked("u1")
    # even a correct password is rejected while locked
    try:
        svc.verify("u1", "pw")
        raise AssertionError("expected AccountLocked")
    except AccountLocked:
        pass

    # lock survives restart
    storage.close()
    clock2 = FakeClock(clock.t)
    svc2, _ = _svc(str(tmp_path / "c.db"), clock2)
    assert svc2.is_locked("u1")

    # after expiry the account unlocks and the right password works
    clock2.advance(61)
    assert svc2.verify("u1", "pw") is True
    assert not svc2.is_locked("u1")


def test_successful_login_clears_failures(tmp_path):
    clock = FakeClock()
    svc, _ = _svc(str(tmp_path / "c.db"), clock)
    svc.create_account("u1", "pw")
    svc.verify("u1", "bad")
    svc.verify("u1", "bad")
    assert svc.verify("u1", "pw") is True
    assert svc.get_record("u1").failed_count == 0
    # two more failures must not trigger a lock (counter restarted)
    assert svc.verify("u1", "bad") is False
    assert svc.verify("u1", "bad") is False
    assert not svc.is_locked("u1")


def test_rehash_commit_does_not_touch_failure_counter(tmp_path):
    """The upgrade transaction itself must never reset/change counters.

    (A full successful verify clears counters because the *authentication*
    succeeded -- not because a rehash happened.)
    """
    clock = FakeClock()
    storage = CredentialStorage(str(tmp_path / "c.db"))
    cfg = CredentialConfig(lockout=LockoutPolicy(max_failures=5, lockout_seconds=60),
                           upgrade=UpgradePolicy(rollout_fraction=1.0))
    svc = CredentialService(storage, build_default_registry(), cfg, clock=clock)
    legacy = build_default_registry().get("legacy_sha1").encode("legacypw")
    storage.create_account("u1", legacy, "legacy_sha1", 1)

    storage.record_failure("u1", clock())
    storage.record_failure("u1", clock())
    rec = storage.get("u1")
    assert rec.failed_count == 2

    # Exactly what the service does during a transparent upgrade.
    new_hash = build_default_registry().default().encode("legacypw")
    assert storage.commit_upgrade(
        "u1", new_hash, "pbkdf2_sha256", 1, rec.row_version, "att"
    )
    rec = storage.get("u1")
    assert rec.failed_count == 2 and rec.locked_until is None
    assert rec.algorithm_id == "pbkdf2_sha256"


def test_reset_invalidates_old_password_and_lock(tmp_path):
    clock = FakeClock()
    svc, _ = _svc(str(tmp_path / "c.db"), clock)
    svc.create_account("u1", "pw")
    for _ in range(3):
        svc.verify("u1", "bad")
    assert svc.is_locked("u1")
    svc.reset_password("u1", "newpw")
    assert not svc.is_locked("u1")
    assert svc.verify("u1", "pw") is False
    assert svc.verify("u1", "newpw") is True


def test_disabled_account_rejects_and_recovers_on_enable(tmp_path):
    clock = FakeClock()
    svc, _ = _svc(str(tmp_path / "c.db"), clock)
    svc.create_account("u1", "pw")
    svc.disable_account("u1")
    try:
        svc.verify("u1", "pw")
        raise AssertionError("expected AccountDisabled")
    except AccountDisabled:
        pass
    # disabling survives restart
    svc2, storage2 = _svc(str(tmp_path / "c.db"), FakeClock())
    try:
        svc2.verify("u1", "pw")
        raise AssertionError("expected AccountDisabled after restart")
    except AccountDisabled:
        pass
    svc2.enable_account("u1")
    assert svc2.verify("u1", "pw") is True
    storage2.close()


def test_deleted_account_can_not_authenticate(tmp_path):
    svc, _ = _svc(str(tmp_path / "c.db"), FakeClock())
    svc.create_account("u1", "pw")
    svc.delete_account("u1")
    assert svc.verify("u1", "pw") is False
    kinds = [e.type for e in svc.audit_events()]
    assert AuditEventType.ACCOUNT_DELETED in kinds


def test_failure_window_resets_stale_streak(tmp_path):
    clock = FakeClock()
    svc, _ = _svc(str(tmp_path / "c.db"), clock, max_failures=3,
                  lockout_seconds=60, window=30)
    svc.create_account("u1", "pw")
    svc.verify("u1", "bad")
    svc.verify("u1", "bad")
    clock.advance(31)
    # streak aged out: two failures again must not lock
    svc.verify("u1", "bad")
    svc.verify("u1", "bad")
    assert not svc.is_locked("u1")
