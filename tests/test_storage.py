"""Tests for the SQLite storage: CAS, ledger idempotency, durability."""

from __future__ import annotations

import pytest

from credential_store.audit import AuditEvent, AuditEventType
from credential_store.errors import AccountAlreadyExists
from credential_store.storage import CredentialStorage


def _evt(kind=AuditEventType.PASSWORD_SET, account="u1"):
    return AuditEvent(kind, account)


def test_create_and_get(tmp_path):
    s = CredentialStorage(str(tmp_path / "a.db"))
    s.create_account("u1", "$legacy_sha1$..$..$..", "legacy_sha1", 1)
    rec = s.get("u1")
    assert rec is not None and rec.algorithm_id == "legacy_sha1" and rec.row_version == 1
    assert s.get("missing") is None


def test_duplicate_create_rejected(tmp_path):
    s = CredentialStorage(str(tmp_path / "b.db"))
    s.create_account("u1", "h", "legacy_sha1", 1)
    with pytest.raises(AccountAlreadyExists):
        s.create_account("u1", "h2", "pbkdf2_sha256", 1)


def test_cas_stale_version_loses(tmp_path):
    s = CredentialStorage(str(tmp_path / "c.db"))
    s.create_account("u1", "old", "legacy_sha1", 1)
    assert s.commit_upgrade("u1", "new", "pbkdf2_sha256", 1, 1, "att-1")
    # stale expected version: rejected
    assert not s.commit_upgrade("u1", "new2", "pbkdf2_sha512", 1, 1, "att-2")
    assert s.get("u1").algorithm_id == "pbkdf2_sha256"
    assert len(s.ledger_entries()) == 1


def test_ledger_dedupes_same_attempt(tmp_path):
    s = CredentialStorage(str(tmp_path / "d.db"))
    s.create_account("u1", "old", "legacy_sha1", 1)
    assert s.commit_upgrade("u1", "new", "pbkdf2_sha256", 1, 1, "same-att")
    assert not s.commit_upgrade("u1", "new2", "pbkdf2_sha256", 1, 2, "same-att")
    assert len(s.ledger_entries("u1")) == 1


def test_replace_hash_clears_lockout_and_bumps_version(tmp_path):
    s = CredentialStorage(str(tmp_path / "e.db"))
    s.create_account("u1", "old", "legacy_sha1", 1)
    s.record_failure("u1", 1.0)
    s.record_failure("u1", 2.0)
    s.apply_lock("u1", 99.0)
    assert s.replace_hash("u1", "fresh", "pbkdf2_sha256", 1, 1)
    rec = s.get("u1")
    assert rec.encoded_hash == "fresh" and rec.row_version == 2
    assert rec.failed_count == 0 and rec.locked_until is None


def test_disable_enable_delete(tmp_path):
    s = CredentialStorage(str(tmp_path / "f.db"))
    s.create_account("u1", "old", "legacy_sha1", 1)
    assert s.disable("u1")
    assert s.get("u1").disabled
    assert not s.disable("u1")  # idempotent
    assert s.enable("u1")
    assert not s.get("u1").disabled
    assert s.delete("u1")
    assert s.get("u1") is None


def test_state_and_ledger_survive_reopen(tmp_path):
    path = str(tmp_path / "g.db")
    s = CredentialStorage(path)
    s.create_account("u1", "old", "legacy_sha1", 1, events=(_evt(),))
    s.commit_upgrade(
        "u1", "new", "pbkdf2_sha256", 1, 1, "att-x",
        events=(_evt(AuditEventType.REHASH_SUCCESS),),
    )
    s.record_failure("u1", 3.0)
    s.apply_lock("u1", 42.0)
    s.close()

    s2 = CredentialStorage(path)
    rec = s2.get("u1")
    assert rec.algorithm_id == "pbkdf2_sha256" and rec.row_version == 2
    assert rec.failed_count == 1 and rec.locked_until == 42.0
    assert len(s2.ledger_entries()) == 1
    kinds = {e.type for e in s2.audit_events()}
    assert AuditEventType.PASSWORD_SET in kinds
    assert AuditEventType.REHASH_SUCCESS in kinds
    s2.close()


def test_scan_outdated_excludes_disabled_and_locked(tmp_path):
    s = CredentialStorage(str(tmp_path / "h.db"))
    s.create_account("old1", "h", "legacy_sha1", 1)
    s.create_account("old2", "h", "legacy_sha1", 1)
    s.create_account("fresh", "h", "pbkdf2_sha256", 1)
    s.disable("old2")
    s.apply_lock("old1", 1e12)
    # old1 locked, old2 disabled, fresh current -> nothing eligible
    assert s.scan_outdated("pbkdf2_sha256", now=0.0, limit=10) == []
    s.unlock("old1")
    found_after_unlock = {r.account_id for r in s.scan_outdated("pbkdf2_sha256", now=0.0, limit=10)}
    assert found_after_unlock == {"old1"}
