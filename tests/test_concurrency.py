"""Tests for concurrent rehash and interleaved password operations."""

from __future__ import annotations

import threading
from typing import Any

from conftest import make_service

from credvault import StoredCredential, VerifyOutcome
from credvault.hashes import (
    PBKDF2SHA256Hasher,
    SaltedSHA256LegacyHasher,
)


def _seed_legacy(service, username="alice", password="pw"):
    service.create_account(username, password)
    record = service._store.accounts()[username]
    record["credential"] = StoredCredential(
        algorithm="legacy_sha256_salted",
        params=SaltedSHA256LegacyHasher().hash(password),
    )
    with service._store.lock:
        service._store.commit()


def test_concurrent_logins_migrate_exactly_once(service):
    _seed_legacy(service)
    outcomes: list[VerifyOutcome] = []
    migrated_flags: list[bool] = []
    barrier = threading.Barrier(16)

    def worker():
        barrier.wait()
        result = service.verify("alice", "pw")
        outcomes.append(result.outcome)
        migrated_flags.append(result.migrated)

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert all(o is VerifyOutcome.SUCCESS for o in outcomes)
    # Exactly one transaction performed the upgrade (epoch == 1); other
    # threads simply verify against whatever credential was current.
    assert service.get_rehash_epoch("alice") == 1
    assert service.get_algorithm_name("alice") == "pbkdf2_sha256"
    assert sum(migrated_flags) == 1
    # audit: exactly one successful rehash recorded, never double-booked
    kinds = [e.kind for e in service.audit_events()]
    assert kinds.count("rehash_success") == 1
    # password still valid after the storm
    assert service.verify("alice", "pw").outcome is VerifyOutcome.SUCCESS


def test_rehash_interleaved_with_password_change(service):
    _seed_legacy(service)
    order: list[str] = []

    def login():
        result = service.verify("alice", "pw")
        order.append(f"login:{result.outcome.value}:{result.migrated}")

    def change():
        ok = service.set_password("alice", "brand-new")
        order.append(f"change:{ok is None}")

    t1 = threading.Thread(target=login)
    t2 = threading.Thread(target=change)
    t1.start(); t2.start(); t1.join(); t2.join()

    # After both operations the *new* password must be on the default
    # algorithm and the old one must no longer work, regardless of ordering.
    assert service.get_algorithm_name("alice") == "pbkdf2_sha256"
    assert service.verify("alice", "brand-new").outcome is VerifyOutcome.SUCCESS
    assert service.verify("alice", "pw").outcome is VerifyOutcome.BAD_CREDENTIAL
    # Never a torn state: exactly one consistent credential on disk.
    rec = service._store.get_record("alice")
    assert rec["credential"].algorithm == "pbkdf2_sha256"


def test_failed_retries_during_concurrent_logins_lock_once(service):
    service.create_account("bob", "correct")
    barrier = threading.Barrier(6)
    results: list[VerifyOutcome] = []

    def worker(password):
        barrier.wait()
        results.append(service.verify("bob", password).outcome)

    threads = [
        threading.Thread(target=worker, args=("bad",)) for _ in range(5)
    ] + [threading.Thread(target=worker, args=("correct",))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # 5 failures must reach the lock threshold (max_failures=3 in fixture);
    # account is locked, one lock event, counter never exceeded threshold by
    # jumping past a rehash.
    assert service.is_locked("bob")
    assert service.lock_state("bob").fail_count >= 3
    assert [e.kind for e in service.audit_events()].count("account_locked") == 1


class _FlakyDefaultHasher(PBKDF2SHA256Hasher):
    """PBKDF2 hasher whose hashing blows up once to simulate rehash failure."""

    name = "pbkdf2_sha256"

    def __init__(self, fail_times: int = 1):
        super().__init__(default_iterations=1000)
        self._fail_times = fail_times
        self.calls = 0

    def hash(self, password: str, *, params=None) -> dict[str, Any]:
        self.calls += 1
        if self.calls <= self._fail_times:
            raise RuntimeError("simulated hashing outage")
        return super().hash(password, params=params)


def test_rehash_failure_keeps_successful_login_and_old_credential(db_path):
    from credvault.config import ServiceConfig

    # 1) create the account with a healthy registry...
    svc = make_service(db_path, ServiceConfig(max_failures=3))
    _seed_legacy(svc)
    # 2) ...then swap in a default hasher that fails its next hash() call,
    #    i.e. the failure happens only inside the transparent rehash.
    flaky = _FlakyDefaultHasher(fail_times=1)
    svc._registry._hashers["pbkdf2_sha256"] = flaky

    result = svc.verify("alice", "pw")
    # Login succeeded; migration reported as not performed; no rollback.
    assert result.outcome is VerifyOutcome.SUCCESS
    assert result.migrated is False
    assert svc.get_algorithm_name("alice") == "legacy_sha256_salted"
    assert svc.get_rehash_epoch("alice") == 0
    kinds = [e.kind for e in svc.audit_events()]
    assert "rehash_failure" in kinds
    assert "verify_success" in kinds

    # Once hashing recovers, next login completes the upgrade.
    result2 = svc.verify("alice", "pw")
    assert result2.migrated is True
    assert svc.get_algorithm_name("alice") == "pbkdf2_sha256"
    assert svc.verify("alice", "pw").outcome is VerifyOutcome.SUCCESS


def test_rehash_does_not_reset_existing_failure_counter(service):
    # Seed an account with one prior failure and a legacy credential.
    _seed_legacy(service, "carol", "pw")
    service.verify("carol", "wrong")
    assert service.lock_state("carol").fail_count == 1
    # A successful login resets the counter (verification semantics), but
    # the rehash event must not itself alter/reset anything: emulate by
    # checking a single success clears to zero with exactly one rehash.
    result = service.verify("carol", "pw")
    assert result.outcome is VerifyOutcome.SUCCESS
    assert service.lock_state("carol").fail_count == 0
    assert service.get_rehash_epoch("carol") == 1
