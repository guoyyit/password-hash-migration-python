"""Tests for migration pacing, batch upgrades and new-algorithm rollout."""

from __future__ import annotations

from conftest import make_service

from credvault import (
    MigrationMode,
    ServiceConfig,
    StoredCredential,
    VerifyOutcome,
)
from credvault.hashes import (
    PBKDF2SHA256Hasher,
    SaltedSHA256LegacyHasher,
)


def _seed_legacy_users(svc, names, password="pw"):
    for name in names:
        svc.create_account(name, password)
        record = svc._store.accounts()[name]
        record["credential"] = StoredCredential(
            algorithm="legacy_sha256_salted",
            params=SaltedSHA256LegacyHasher().hash(password),
        )
    with svc._store.lock:
        svc._store.commit()


def test_migration_off_keeps_old_data_working(db_path):
    cfg = ServiceConfig(migration_mode=MigrationMode.OFF, max_failures=3)
    svc = make_service(db_path, cfg)
    _seed_legacy_users(svc, ["a", "b"])
    for name in ("a", "b"):
        result = svc.verify(name, "pw")
        assert result.outcome is VerifyOutcome.SUCCESS
        assert result.migrated is False
        assert svc.get_algorithm_name(name) == "legacy_sha256_salted"


def test_migration_sampled_zero_rate_never_upgrades(db_path):
    cfg = ServiceConfig(
        migration_mode=MigrationMode.SAMPLED,
        migration_sample_rate=0.0,
        max_failures=3,
    )
    svc = make_service(db_path, cfg)
    _seed_legacy_users(svc, ["a"])
    for _ in range(5):
        assert svc.verify("a", "pw").migrated is False
    assert svc.get_algorithm_name("a") == "legacy_sha256_salted"


def test_migration_sampled_full_rate_upgrades(db_path):
    cfg = ServiceConfig(
        migration_mode=MigrationMode.SAMPLED,
        migration_sample_rate=1.0,
        max_failures=3,
    )
    svc = make_service(db_path, cfg)
    _seed_legacy_users(svc, ["a"])
    assert svc.verify("a", "pw").migrated is True


def test_batch_size_caps_upgrades_per_window(db_path):
    cfg = ServiceConfig(
        migration_mode=MigrationMode.ALWAYS,
        batch_size=2,
        max_failures=3,
    )
    svc = make_service(db_path, cfg)
    names = ["u1", "u2", "u3", "u4"]
    _seed_legacy_users(svc, names)
    for name in names:
        svc.verify(name, "pw")
    upgraded = [n for n in names if svc.get_algorithm_name(n) == "pbkdf2_sha256"]
    assert upgraded == ["u1", "u2"]
    # capped accounts can still log in on their old hashes
    for name in ("u3", "u4"):
        assert svc.verify(name, "pw").outcome is VerifyOutcome.SUCCESS
        assert svc.get_algorithm_name(name) == "legacy_sha256_salted"
    # next window allows another batch
    svc.reset_migration_window()
    svc.verify("u3", "pw")
    assert svc.get_algorithm_name("u3") == "pbkdf2_sha256"


def test_run_upgrade_batch_respects_limit(db_path, config):
    svc = make_service(db_path, config)
    names = ["u1", "u2", "u3"]
    _seed_legacy_users(svc, names)
    credentials = {n: "pw" for n in names}
    done = svc.run_upgrade_batch(credentials, limit=2)
    assert done == 2
    remaining = [n for n in names if svc.get_algorithm_name(n) != "pbkdf2_sha256"]
    assert len(remaining) == 1
    done2 = svc.run_upgrade_batch(credentials, limit=2)
    assert done2 == 1
    assert all(svc.get_algorithm_name(n) == "pbkdf2_sha256" for n in names)


def test_run_upgrade_batch_skips_wrong_password(db_path, config):
    svc = make_service(db_path, config)
    _seed_legacy_users(svc, ["good", "bad"])
    done = svc.run_upgrade_batch({"good": "pw", "bad": "wrong"})
    assert done == 1
    assert svc.get_algorithm_name("good") == "pbkdf2_sha256"
    assert svc.get_algorithm_name("bad") == "legacy_sha256_salted"


def test_roll_out_a_new_default_algorithm(db_path):
    """Registering scrypt as new default upgrades legacy users on login."""
    cfg = ServiceConfig(
        default_algorithm="scrypt",
        default_params={"n": 2 ** 12, "r": 8, "p": 1, "dklen": 32},
        max_failures=3,
    )
    svc = make_service(db_path, cfg)
    _seed_legacy_users(svc, ["alice"])
    result = svc.verify("alice", "pw")
    assert result.migrated is True
    assert svc.get_algorithm_name("alice") == "scrypt"
    # subsequent login uses scrypt and is already current -> no re-migration
    assert svc.verify("alice", "pw").migrated is False

    # Meanwhile a PBKDF2 account (older current default) remains verifiable.
    svc.create_account("bob", "bpw")
    pb_params = PBKDF2SHA256Hasher(default_iterations=1000).hash("bpw")
    svc._store.accounts()["bob"]["credential"] = StoredCredential(
        algorithm="pbkdf2_sha256", params=pb_params
    )
    # pbkdf2 != default scrypt -> transparently upgraded to scrypt on login
    r = svc.verify("bob", "bpw")
    assert r.outcome is VerifyOutcome.SUCCESS and r.migrated is True
    assert svc.get_algorithm_name("bob") == "scrypt"


def test_registering_algorithm_at_runtime_keeps_old_credentials(db_path, config):
    svc = make_service(db_path, config)
    svc.create_account("zoe", "pw")
    # inject a credential for an algorithm not yet known
    svc._store.accounts()["zoe"]["credential"] = StoredCredential(
        algorithm="future-kdf-9000", params={"tag": "opaque"}
    )
    # cannot verify while unknown -> failure recorded, but record intact
    assert svc.verify("zoe", "pw").outcome is VerifyOutcome.BAD_CREDENTIAL
    assert svc.get_algorithm_name("zoe") == "future-kdf-9000"

    class FutureKDF(PBKDF2SHA256Hasher):
        name = "future-kdf-9000"

        def hash(self, password, *, params=None):
            return {"tag": "opaque"}

        def verify(self, password, params):
            return params.get("tag") == "opaque" and password == "pw"

    svc.register_algorithm(FutureKDF(default_iterations=1000))
    assert svc.verify("zoe", "pw").outcome is VerifyOutcome.SUCCESS


def test_audit_records_rehash_and_no_secret_values(db_path, config):
    svc = make_service(db_path, config)
    secret = "audited-secret-xyz"
    _seed_legacy_users(svc, ["alice"], password=secret)
    svc.verify("alice", secret)
    events = svc.audit_events()
    kinds = {e.kind for e in events}
    assert {"rehash_success", "verify_success", "password_set"} <= kinds
    serialized = [str(e) for e in events]
    assert all(secret not in line for line in serialized)
    for event in events:
        assert all(
            k not in {"digest", "hash", "salt", "password"} for k in event.detail
        )


def test_batch_upgrade_does_not_touch_failure_counter(db_path, config):
    svc = make_service(db_path, config)
    _seed_legacy_users(svc, ["alice"], password="pw")
    # a prior failure is recorded against the legacy account
    svc.verify("alice", "wrong")
    assert svc.lock_state("alice").fail_count == 1
    # administrative batch upgrade performs no verification-failure path
    # and must not reset (or increase) the failure counter
    done = svc.run_upgrade_batch({"alice": "pw"})
    assert done == 1
    assert svc.lock_state("alice").fail_count == 1
    assert svc.get_algorithm_name("alice") == "pbkdf2_sha256"
