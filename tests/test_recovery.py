"""Tests for crash recovery, durability and upgrade idempotency."""

from __future__ import annotations

import json

from conftest import make_service

from credvault import StoredCredential, VerifyOutcome
from credvault.hashes import SaltedSHA256LegacyHasher


def _seed_legacy(svc, username="alice", password="pw"):
    svc.create_account(username, password)
    record = svc._store.accounts()[username]
    record["credential"] = StoredCredential(
        algorithm="legacy_sha256_salted",
        params=SaltedSHA256LegacyHasher().hash(password),
    )
    with svc._store.lock:
        svc._store.commit()


def test_completed_upgrade_survives_restart(db_path, config):
    svc = make_service(db_path, config)
    _seed_legacy(svc)
    assert svc.verify("alice", "pw").migrated is True
    assert svc.get_rehash_epoch("alice") == 1

    svc2 = make_service(db_path, config)
    assert svc2.get_algorithm_name("alice") == "pbkdf2_sha256"
    # Restart must not re-perform or re-bookkeep the upgrade.
    result = svc2.verify("alice", "pw")
    assert result.migrated is False
    assert svc2.get_rehash_epoch("alice") == 1
    assert [e.kind for e in svc2.audit_events()].count("rehash_success") == 1


def test_lock_state_survives_restart(db_path, config):
    svc = make_service(db_path, config)
    svc.create_account("bob", "pw")
    for _ in range(3):
        svc.verify("bob", "bad")
    assert svc.is_locked("bob")

    svc2 = make_service(db_path, config)
    assert svc2.is_locked("bob")
    assert svc2.verify("bob", "pw").outcome is VerifyOutcome.LOCKED


def test_password_change_survives_restart(db_path, config):
    svc = make_service(db_path, config)
    svc.create_account("carol", "old")
    svc.change_password("carol", "old", "new")
    svc2 = make_service(db_path, config)
    assert svc2.verify("carol", "old").outcome is VerifyOutcome.BAD_CREDENTIAL
    assert svc2.verify("carol", "new").outcome is VerifyOutcome.SUCCESS


def test_disable_and_reset_survive_restart(db_path, config):
    svc = make_service(db_path, config)
    svc.create_account("dave", "pw")
    svc.disable_account("dave")
    svc2 = make_service(db_path, config)
    assert svc2.verify("dave", "pw").outcome is VerifyOutcome.DISABLED
    svc2.reset_password("dave", "pw2")
    svc3 = make_service(db_path, config)
    assert svc3.verify("dave", "pw").outcome is VerifyOutcome.BAD_CREDENTIAL
    assert svc3.verify("dave", "pw2").outcome is VerifyOutcome.SUCCESS


def test_interrupted_rehash_before_commit_changes_nothing(db_path, config):
    """If durability fails, nothing is observable: no half-upgrade."""
    svc = make_service(db_path, config)
    _seed_legacy(svc)
    assert svc.get_algorithm_name("alice") == "legacy_sha256_salted"

    calls = {"n": 0}
    real_commit = svc._store.commit

    def failing_commit():
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("disk vanished during commit")
        return real_commit()

    svc._store.commit = failing_commit  # type: ignore[method-assign]
    # The failed verify raises to the caller (crash-like); the in-memory
    # change is discarded by reopening from the still-old durable file.
    try:
        svc.verify("alice", "pw")
        raised = False
    except OSError:
        raised = True
    assert raised

    svc2 = make_service(db_path, config)
    assert svc2.get_algorithm_name("alice") == "legacy_sha256_salted"
    assert svc2.get_rehash_epoch("alice") == 0
    kinds = [e.kind for e in svc2.audit_events()]
    assert "rehash_success" not in kinds
    # next clean login performs the upgrade exactly once
    assert svc2.verify("alice", "pw").migrated is True
    assert svc2.get_rehash_epoch("alice") == 1


def test_state_file_is_single_consistent_json_document(db_path, config):
    svc = make_service(db_path, config)
    _seed_legacy(svc, "alice")
    svc.verify("alice", "pw")
    with db_path.open() as handle:
        doc = json.load(handle)
    assert doc["version"] == 1
    assert "alice" in doc["accounts"]
    seqs = [e["seq"] for e in doc["events"]]
    assert seqs == sorted(seqs)
    assert len(seqs) == len(set(seqs))  # no duplicate/rebokable seq
    assert doc["audit_seq"] == seqs[-1]


def test_no_temp_files_left_behind(db_path, config):
    svc = make_service(db_path, config)
    svc.create_account("erin", "pw")
    svc.verify("erin", "pw")
    leftovers = [p.name for p in db_path.parent.iterdir() if p.name.startswith(".credvault-")]
    assert leftovers == []
