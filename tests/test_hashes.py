"""Tests for hash algorithms and the versioned registry."""

from __future__ import annotations

import pytest

from credvault.hashes import (
    AlgorithmRegistry,
    PBKDF2SHA256Hasher,
    SaltedSHA256LegacyHasher,
    ScryptHasher,
    UnknownAlgorithmError,
    UnsaltedSHA256LegacyHasher,
)


@pytest.mark.parametrize(
    "hasher",
    [
        PBKDF2SHA256Hasher(default_iterations=1000),
        ScryptHasher(default_n=2 ** 12),
        SaltedSHA256LegacyHasher(),
        UnsaltedSHA256LegacyHasher(),
    ],
)
def test_hash_roundtrip_and_reject(hasher):
    stored = hasher.hash("correct horse battery staple")
    assert hasher.verify("correct horse battery staple", stored)
    assert not hasher.verify("wrong password", stored)
    # salts make two hashes differ
    assert hasher.hash("same") != hasher.hash("same") or hasher.name.endswith("unsalted")
    # no plaintext in the serialisable params
    assert "correct horse battery staple" not in str(stored)


def test_legacy_unsalted_is_deterministic():
    h = UnsaltedSHA256LegacyHasher()
    p1 = h.hash("pw")
    p2 = h.hash("pw")
    assert p1 == p2  # pre-existing legacy data has no salt


def test_registry_defaults_and_lookup():
    registry = AlgorithmRegistry()
    registry.register(PBKDF2SHA256Hasher(default_iterations=1000), set_default=True)
    registry.register(ScryptHasher(default_n=2 ** 12))
    assert registry.default_name == "pbkdf2_sha256"
    assert isinstance(registry.get("scrypt"), ScryptHasher)
    with pytest.raises(UnknownAlgorithmError):
        registry.get("nope")
    registry.register(ScryptHasher(default_n=2 ** 13), set_default=True)
    assert registry.default_name == "scrypt"
    # re-registering does not invalidate the old PBKDF2 verifier
    assert registry.is_registered("pbkdf2_sha256")


def test_adding_new_algorithm_keeps_old_data_verifiable():
    registry = AlgorithmRegistry()
    registry.register(SaltedSHA256LegacyHasher(), set_default=True)
    old_params = registry.get("legacy_sha256_salted").hash("legacy-pw")

    registry.register(PBKDF2SHA256Hasher(default_iterations=1000), set_default=True)
    # old record still verifies with the old algorithm...
    assert registry.get("legacy_sha256_salted").verify("legacy-pw", old_params)
    # ...while brand-new passwords use the new default
    new_params = registry.get("pbkdf2_sha256").hash("new-pw")
    assert registry.get("pbkdf2_sha256").verify("new-pw", new_params)


def test_pbkdf2_cost_upgrade_signal():
    hasher = PBKDF2SHA256Hasher(default_iterations=200_000)
    cheap = {"iterations": 1000}
    strong = {"iterations": 200_000}
    assert hasher.needs_upgrade(cheap, {"iterations": 200_000})
    assert not hasher.needs_upgrade(strong, {"iterations": 200_000})
    assert hasher.needs_upgrade({}, {"iterations": 200_000})


def test_verify_tolerates_malformed_params():
    hasher = PBKDF2SHA256Hasher(default_iterations=1000)
    assert not hasher.verify("pw", {})
    assert not hasher.verify("pw", {"salt": "!!", "iterations": 1, "digest": "!!"})
