"""Concurrent transparent rehash and password-change interleaving."""

from __future__ import annotations

import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from credential_store.config import CredentialConfig
from credential_store.hashers import build_default_registry
from credential_store.service import CredentialService
from credential_store.storage import CredentialStorage


def _service(db_path, *, fraction=1.0, rpm=None):
    from credential_store.config import UpgradePolicy

    return CredentialService(
        CredentialStorage(db_path),
        build_default_registry(),
        CredentialConfig(upgrade=UpgradePolicy(
            rollout_fraction=fraction, max_upgrades_per_minute=rpm)),
        rng=random.Random(12345),
    )


def _seed_legacy(storage, account_id, password):
    reg = build_default_registry()
    encoded = reg.get("legacy_sha1").encode(password)
    storage.create_account(account_id, encoded, "legacy_sha1", 1)


def test_concurrent_logins_book_upgrade_exactly_once(tmp_path):
    storage = CredentialStorage(str(tmp_path / "c.db"))
    _seed_legacy(storage, "u1", "legacypw")
    svc = CredentialService(storage, build_default_registry(), CredentialConfig())

    outcomes: list[bool] = []
    barrier = threading.Barrier(20)

    def login():
        barrier.wait()
        return svc.verify("u1", "legacypw")

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = [pool.submit(login) for _ in range(20)]
        outcomes = [f.result() for f in futures]

    assert all(outcomes)
    ledger = storage.ledger_entries("u1")
    assert len(ledger) == 1, ledger
    assert ledger[0].from_algorithm == "legacy_sha1"
    assert ledger[0].to_algorithm == "pbkdf2_sha256"
    rec = storage.get("u1")
    assert rec.algorithm_id == "pbkdf2_sha256"
    # new hash actually verifies
    assert build_default_registry().identify(rec.encoded_hash).verify("legacypw", rec.encoded_hash)


def test_upgrade_never_clobbers_concurrent_password_change(tmp_path):
    storage = CredentialStorage(str(tmp_path / "c.db"))
    _seed_legacy(storage, "u1", "legacypw")
    svc = CredentialService(storage, build_default_registry(), CredentialConfig())

    start = threading.Event()

    def login_old():
        start.wait()
        return svc.verify("u1", "legacypw")

    def change_pw():
        start.wait()
        svc.set_password("u1", "newpw")
        return True

    # Repeat many times to explore interleavings.
    for _ in range(25):
        storage.unlock("u1")
        # Reset to a legacy row each iteration.
        legacy = build_default_registry().get("legacy_sha1").encode("legacypw")
        rec = storage.get("u1")
        storage.replace_hash(rec.account_id, legacy, "legacy_sha1", 1, rec.row_version)

        with ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(login_old)
            f2 = pool.submit(change_pw)
            start.set()
            f1.result()
            f2.result()
        start.clear()

        # Final state must always be self-consistent: only the new password works.
        assert svc.verify("u1", "newpw") is True
        assert svc.verify("u1", "legacypw") is False
        rec = storage.get("u1")
        assert rec.algorithm_id == "pbkdf2_sha256"


def test_rehash_failure_does_not_invalidate_successful_auth(tmp_path, monkeypatch):
    storage = CredentialStorage(str(tmp_path / "c.db"))
    _seed_legacy(storage, "u1", "legacypw")
    svc = CredentialService(storage, build_default_registry(), CredentialConfig())

    def boom(*_args, **_kwargs):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(storage, "commit_upgrade", boom)
    assert svc.verify("u1", "legacypw") is True
    # old hash untouched, login still works, failure recorded as audit event
    rec = storage.get("u1")
    assert rec.algorithm_id == "legacy_sha1"
    kinds = [e.type.value for e in svc.audit_events()]
    assert "rehash_failed" in kinds
    assert "verify_success" in kinds
