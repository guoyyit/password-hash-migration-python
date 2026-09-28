"""Adding a brand new algorithm must not break existing stored credentials."""

from __future__ import annotations

from dataclasses import dataclass

from credential_store.config import CredentialConfig, UpgradePolicy
from credential_store.hashers import (
    Pbkdf2Hasher,
    build_default_registry,
    encode_hash,
    parse_hash,
)
from credential_store.service import CredentialService
from credential_store.storage import CredentialStorage
import hashlib
import hmac
import secrets


@dataclass(frozen=True)
class FutureArgonLikeHasher:
    """Stand-in for a future algorithm registered in a later deployment."""

    algorithm_id: str = "argon_future"
    version: int = 1

    def encode(self, password: str, *, cost: int | None = None) -> str:
        salt = secrets.token_bytes(16)
        # Pretend KDF: pbkdf2 with sha3_256 and an extra pepper marker.
        digest = hashlib.pbkdf2_hmac("sha3_256", password.encode(), salt, 3, dklen=16)
        return encode_hash(self.algorithm_id, {"v": 1, "i": 3, "tag": "future"}, salt, digest)

    def verify(self, password: str, encoded: str) -> bool:
        algo, params, salt, expected = parse_hash(encoded)
        if algo != self.algorithm_id:
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha3_256", password.encode(), salt, int(params["i"]), dklen=len(expected))
        return hmac.compare_digest(candidate, expected)

    def needs_upgrade(self, encoded, *, current_default_id, current_cost):
        return self.algorithm_id != current_default_id

    def cost_of(self, encoded):
        return int(parse_hash(encoded)[1]["i"])


def test_old_data_verifies_after_new_algorithm_becomes_default(tmp_path):
    # Deployment 1: pbkdf2_sha256 default; mixed old/legacy/current accounts.
    path = str(tmp_path / "c.db")
    storage = CredentialStorage(path)
    reg = build_default_registry()
    svc = CredentialService(storage, reg, CredentialConfig())
    legacy = reg.get("legacy_sha1").encode("legpw")
    storage.create_account("old", legacy, "legacy_sha1", 1)
    svc.create_account("cur", "curpw")
    storage.close()

    # Deployment 2: register the future algorithm and make it default,
    # while *keeping all old hashers registered*.
    reg2 = build_default_registry()
    reg2.register(FutureArgonLikeHasher(), make_default=True)
    cfg2 = CredentialConfig(default_algorithm_id="argon_future",
                            upgrade=UpgradePolicy(rollout_fraction=1.0))
    storage2 = CredentialStorage(path)
    svc2 = CredentialService(storage2, reg2, cfg2)

    # old legacy account still verifies and migrates to the new default
    assert svc2.verify("old", "legpw") is True
    rec = storage2.get("old")
    assert rec.algorithm_id == "argon_future"
    assert len(storage2.ledger_entries("old")) == 1

    # current pbkdf2 account is now "outdated" but verifies, then migrates
    assert svc2.verify("cur", "curpw") is True
    assert storage2.get("cur").algorithm_id == "argon_future"

    # brand-new accounts are hashed with the new default immediately
    svc2.create_account("neo", "neopw")
    assert storage2.get("neo").algorithm_id == "argon_future"
    assert svc2.verify("neo", "neopw") is True

    # wrong passwords still rejected everywhere
    assert svc2.verify("old", "legpwx") is False
    assert svc2.verify("neo", "wrong") is False

    # stats expose the population mix
    stats = svc2.stats()
    assert stats["total"] == 3 and stats["outdated"] == 0


def test_unknown_algorithm_in_storage_does_not_crash_login(tmp_path):
    path = str(tmp_path / "c.db")
    storage = CredentialStorage(path)
    reg = build_default_registry()
    legacy = reg.get("legacy_sha1").encode("pw")
    storage.create_account("u1", legacy, "legacy_sha1", 1)
    storage.close()

    # Registry missing the legacy hasher: login cannot verify, but must not raise.
    reg2 = build_default_registry()
    reg2._hashers.pop("legacy_sha1")  # simulate old hasher somehow unavailable
    storage2 = CredentialStorage(path)
    svc = CredentialService(storage2, reg2, CredentialConfig())
    assert svc.verify("u1", "pw") is False
