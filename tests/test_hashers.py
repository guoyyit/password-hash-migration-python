"""Tests for self-describing hash encoding and the hasher registry."""

from __future__ import annotations

import pytest

from credential_store.errors import InvalidHash, UnknownAlgorithm
from credential_store.hashers import (
    LegacySaltedSha1Hasher,
    Pbkdf2Hasher,
    build_default_registry,
    parse_hash,
)


def test_pbkdf2_roundtrip_and_timing_safe_mismatch():
    h = Pbkdf2Hasher("pbkdf2_sha256", 1, "sha256", default_iterations=1000)
    encoded = h.encode("s3cret", cost=1000)
    assert encoded.startswith("$pbkdf2_sha256$")
    assert h.verify("s3cret", encoded)
    assert not h.verify("S3CRET", encoded)
    assert not h.verify("", encoded)


def test_same_password_produces_distinct_hashes():
    h = Pbkdf2Hasher("pbkdf2_sha256", 1, "sha256", 1000)
    assert h.encode("pw", cost=1000) != h.encode("pw", cost=1000)


def test_legacy_sha1_still_verifies_and_always_wants_upgrade():
    legacy = LegacySaltedSha1Hasher()
    encoded = legacy.encode("oldpw")
    assert legacy.verify("oldpw", encoded)
    assert not legacy.verify("oldpwx", encoded)
    assert legacy.needs_upgrade(encoded, current_default_id="pbkdf2_sha256", current_cost=None)


def test_needs_upgrade_on_algorithm_and_cost():
    h = Pbkdf2Hasher("pbkdf2_sha256", 1, "sha256", 1000)
    encoded = h.encode("pw", cost=1000)
    # same default + equal cost -> no upgrade
    assert not h.needs_upgrade(encoded, current_default_id="pbkdf2_sha256", current_cost=1000)
    # higher configured cost -> upgrade (cost ramp-up)
    assert h.needs_upgrade(encoded, current_default_id="pbkdf2_sha256", current_cost=5000)
    # default moved to another family -> upgrade
    assert h.needs_upgrade(encoded, current_default_id="pbkdf2_sha512", current_cost=None)


def test_parse_hash_rejects_malformed():
    with pytest.raises(InvalidHash):
        parse_hash("not-an-encoded-hash")
    with pytest.raises(InvalidHash):
        parse_hash("$algo$badparams$salt$digest")


def test_registry_keeps_old_and_new_side_by_side():
    reg = build_default_registry()
    assert reg.default().algorithm_id == "pbkdf2_sha256"
    legacy_encoded = reg.get("legacy_sha1").encode("pw")
    new_encoded = reg.get("pbkdf2_sha512").encode("pw")
    # old data stays verifiable after the default moves forward
    reg.set_default("pbkdf2_sha512")
    assert reg.default().algorithm_id == "pbkdf2_sha512"
    assert reg.identify(legacy_encoded).verify("pw", legacy_encoded)
    assert reg.identify(new_encoded).verify("pw", new_encoded)


def test_registry_unknown_algorithm():
    reg = build_default_registry()
    with pytest.raises(UnknownAlgorithm):
        reg.get("nope")
    with pytest.raises(UnknownAlgorithm):
        reg.set_default("nope")
