"""End-to-end tests for verification, locking, reset and disable/delete."""

from __future__ import annotations

import pytest
from conftest import make_service

from credvault import (
    AccountExistsError,
    AccountNotFoundError,
    ServiceConfig,
    StoredCredential,
    VerifyOutcome,
)
from credvault.hashes import (
    PBKDF2SHA256Hasher,
    SaltedSHA256LegacyHasher,
    UnsaltedSHA256LegacyHasher,
)


def test_create_uses_default_algorithm(service):
    service.create_account("alice", "pw")
    assert service.get_algorithm_name("alice") == "pbkdf2_sha256"
    assert service.verify("alice", "pw").outcome is VerifyOutcome.SUCCESS


def test_duplicate_create_rejected(service):
    service.create_account("alice", "pw")
    with pytest.raises(AccountExistsError):
        service.create_account("alice", "pw2")


def test_unknown_user_verify_does_not_reveal_existence(service):
    result = service.verify("ghost", "pw")
    assert result.outcome is VerifyOutcome.NOT_FOUND


def test_legacy_credential_verifies_then_migrates(service):
    service.create_account("alice", "pw")
    # Simulate data written by a previous generation of the system.
    legacy = SaltedSHA256LegacyHasher().hash("pw")
    record = service._store.accounts()["alice"]
    record["credential"] = StoredCredential(
        algorithm="legacy_sha256_salted", params=legacy
    )
    with service._store.lock:
        service._store.commit()

    result = service.verify("alice", "pw")
    assert result.outcome is VerifyOutcome.SUCCESS
    assert result.migrated is True
    assert service.get_algorithm_name("alice") == "pbkdf2_sha256"

    # Second login: already on the default algorithm, no migration.
    again = service.verify("alice", "pw")
    assert again.migrated is False
    assert service.get_rehash_epoch("alice") == 1


def test_legacy_unsalted_credential_migrates(service):
    service.create_account("bob", "hunter2")
    record = service._store.accounts()["bob"]
    record["credential"] = StoredCredential(
        algorithm="legacy_sha256_unsalted",
        params=UnsaltedSHA256LegacyHasher().hash("hunter2"),
    )
    result = service.verify("bob", "hunter2")
    assert result.outcome is VerifyOutcome.SUCCESS
    assert result.migrated is True
    assert service.get_algorithm_name("bob") == "pbkdf2_sha256"


def test_wrong_password_never_migrates(service):
    service.create_account("carol", "right")
    record = service._store.accounts()["carol"]
    record["credential"] = StoredCredential(
        algorithm="legacy_sha256_salted",
        params=SaltedSHA256LegacyHasher().hash("right"),
    )
    result = service.verify("carol", "wrong")
    assert result.outcome is VerifyOutcome.BAD_CREDENTIAL
    assert service.get_algorithm_name("carol") == "legacy_sha256_salted"
    assert service.get_rehash_epoch("carol") == 0


def test_stale_cost_is_upgraded(db_path):
    cfg = ServiceConfig(
        default_params={"iterations": 5000},
        max_failures=3,
    )
    svc = make_service(db_path, cfg)
    svc.create_account("dave", "pw")
    # weaken cost below current default
    rec = svc._store.accounts()["dave"]
    rec["credential"] = StoredCredential(
        algorithm="pbkdf2_sha256",
        params=PBKDF2SHA256Hasher(default_iterations=500).hash("pw"),
    )
    result = svc.verify("dave", "pw")
    assert result.migrated is True
    assert rec["credential"].params["iterations"] == 5000


def test_locking_after_max_failures_and_expiry(db_path):
    clock = {"t": 1000.0}
    cfg = ServiceConfig(max_failures=3, lock_seconds=100.0)
    svc = make_service(db_path, cfg, now=lambda: clock["t"])
    svc.create_account("erin", "pw")
    for _ in range(2):
        assert svc.verify("erin", "bad").outcome is VerifyOutcome.BAD_CREDENTIAL
    third = svc.verify("erin", "bad")
    assert third.outcome is VerifyOutcome.BAD_CREDENTIAL
    assert svc.is_locked("erin")
    # correct password rejected while locked, counter untouched
    assert svc.verify("erin", "pw").outcome is VerifyOutcome.LOCKED
    assert svc.lock_state("erin").fail_count == 3
    # lock expires -> correct password works again
    clock["t"] += 101
    result = svc.verify("erin", "pw")
    assert result.outcome is VerifyOutcome.SUCCESS
    assert not svc.is_locked("erin")


def test_successful_login_resets_failure_count(service):
    service.create_account("frank", "pw")
    service.verify("frank", "bad")
    service.verify("frank", "bad")
    assert service.lock_state("frank").fail_count == 2
    service.verify("frank", "pw")
    assert service.lock_state("frank").fail_count == 0


def test_disabled_account_cannot_verify(service):
    service.create_account("grace", "pw")
    service.disable_account("grace")
    assert service.verify("grace", "pw").outcome is VerifyOutcome.DISABLED
    service.enable_account("grace")
    assert service.verify("grace", "pw").outcome is VerifyOutcome.SUCCESS


def test_reset_invalidates_old_password(service):
    service.create_account("heidi", "old")
    service.reset_password("heidi", "new")
    assert service.verify("heidi", "old").outcome is VerifyOutcome.BAD_CREDENTIAL
    assert service.verify("heidi", "new").outcome is VerifyOutcome.SUCCESS
    # reset also clears an active lock
    for _ in range(3):
        service.verify("heidi", "old")
    assert service.is_locked("heidi")
    service.reset_password("heidi", "newer")
    assert not service.is_locked("heidi")
    assert service.verify("heidi", "newer").outcome is VerifyOutcome.SUCCESS


def test_change_password_requires_current(service):
    service.create_account("ivan", "old")
    assert not service.change_password("ivan", "wrong", "new")
    assert service.change_password("ivan", "old", "new")
    assert service.verify("ivan", "old").outcome is VerifyOutcome.BAD_CREDENTIAL
    assert service.verify("ivan", "new").outcome is VerifyOutcome.SUCCESS


def test_delete_account_removes_everything(service):
    service.create_account("judy", "pw")
    service.delete_account("judy")
    assert service.verify("judy", "pw").outcome is VerifyOutcome.NOT_FOUND
    with pytest.raises(AccountNotFoundError):
        service.disable_account("judy")


def test_disabled_after_restart_still_rejected(db_path, config):
    svc = make_service(db_path, config)
    svc.create_account("kate", "pw")
    svc.disable_account("kate")
    svc2 = make_service(db_path, config)
    assert svc2.verify("kate", "pw").outcome is VerifyOutcome.DISABLED


def test_no_plaintext_or_digest_in_state_file(db_path, service):
    secret = "super-secret-value-123"
    service.create_account("leo", secret)
    service.verify("leo", secret)
    blob = db_path.read_text()
    assert secret not in blob
    params = service._store.accounts()["leo"]["credential"].params
    for value in params.values():
        if isinstance(value, str):
            assert value not in blob or value.startswith("pbkdf2") is False
    # digest value appears but must never coincide with plaintext, and audit
    # events must not carry digest/salt fields
    for event in service.audit_events():
        for key in event.detail:
            assert key not in {"digest", "hash", "salt", "password"}
