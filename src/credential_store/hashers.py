"""Pluggable password hash algorithms.

Every encoded hash is fully self-describing so that credentials produced by
older configurations remain verifiable forever (as long as the matching
hasher stays registered)::

    $<algorithm-id>$<k=v,k=v params>$<salt-base64url>$<digest-base64url>

The algorithm id identifies *both* the algorithm family and its parameter
version. Registering a new algorithm never removes old ones, so stored
hashes keep verifying after the default moves on.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .errors import InvalidHash, UnknownAlgorithm

EncodedHash = str  # type alias for readability


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _parse_params(segment: str) -> dict[str, str]:
    params: dict[str, str] = {}
    if not segment:
        return params
    for item in segment.split(","):
        if "=" not in item:
            raise InvalidHash(f"malformed parameter segment: {segment!r}")
        key, value = item.split("=", 1)
        params[key] = value
    return params


def encode_hash(algorithm_id: str, params: dict[str, str | int], salt: bytes, digest: bytes) -> EncodedHash:
    param_str = ",".join(f"{k}={v}" for k, v in sorted(params.items()))
    return f"${algorithm_id}${param_str}${_b64e(salt)}${_b64e(digest)}"


def parse_hash(encoded: EncodedHash) -> tuple[str, dict[str, str], bytes, bytes]:
    """Return (algorithm_id, params, salt, digest) for an encoded hash."""
    parts = encoded.split("$")
    if len(parts) != 5 or parts[0] != "" or not parts[1] or not parts[3] or not parts[4]:
        raise InvalidHash("encoded hash does not match $algo$params$salt$digest")
    algorithm_id = parts[1]
    params = _parse_params(parts[2])
    try:
        salt = _b64d(parts[3])
        digest = _b64d(parts[4])
    except (ValueError, TypeError) as exc:
        raise InvalidHash("encoded hash contains invalid base64") from exc
    return algorithm_id, params, salt, digest


@runtime_checkable
class PasswordHasher(Protocol):
    """A password hashing algorithm + parameter version."""

    algorithm_id: str
    version: int

    def encode(self, password: str, *, cost: int | None = None) -> EncodedHash: ...

    def verify(self, password: str, encoded: EncodedHash) -> bool: ...

    def needs_upgrade(
        self,
        encoded: EncodedHash,
        *,
        current_default_id: str,
        current_cost: int | None,
    ) -> bool: ...

    def cost_of(self, encoded: EncodedHash) -> int: ...


@dataclass(frozen=True)
class Pbkdf2Hasher:
    """PBKDF2-HMAC over SHA-256/SHA-512 with an iteration count as cost."""

    algorithm_id: str
    version: int
    hash_name: str
    default_iterations: int
    dklen: int = 32
    salt_bytes: int = 16

    def _iterations(self, cost: int | None, params: dict[str, str] | None = None) -> int:
        if cost is not None:
            return cost
        if params is not None and "i" in params:
            return int(params["i"])
        return self.default_iterations

    def encode(self, password: str, *, cost: int | None = None) -> EncodedHash:
        iterations = self._iterations(cost)
        if iterations <= 0:
            raise ValueError("cost (iterations) must be positive")
        salt = secrets.token_bytes(self.salt_bytes)
        digest = hashlib.pbkdf2_hmac(
            self.hash_name, password.encode("utf-8"), salt, iterations, dklen=self.dklen
        )
        return encode_hash(
            self.algorithm_id,
            {"v": self.version, "i": iterations},
            salt,
            digest,
        )

    def verify(self, password: str, encoded: EncodedHash) -> bool:
        try:
            algorithm_id, params, salt, expected = parse_hash(encoded)
            iterations = int(params.get("i", ""))
        except (InvalidHash, ValueError):
            return False
        if algorithm_id != self.algorithm_id or iterations <= 0 or not salt:
            return False
        candidate = hashlib.pbkdf2_hmac(
            self.hash_name, password.encode("utf-8"), salt, iterations, dklen=len(expected)
        )
        return hmac.compare_digest(candidate, expected)

    def needs_upgrade(
        self,
        encoded: EncodedHash,
        *,
        current_default_id: str,
        current_cost: int | None,
    ) -> bool:
        if self.algorithm_id != current_default_id:
            return True
        if current_cost is not None and self.cost_of(encoded) < current_cost:
            return True
        return False

    def cost_of(self, encoded: EncodedHash) -> int:
        _, params, _, _ = parse_hash(encoded)
        try:
            return int(params["i"])
        except (KeyError, ValueError) as exc:
            raise InvalidHash("pbkdf2 hash is missing its iteration count") from exc


@dataclass(frozen=True)
class LegacySaltedSha1Hasher:
    """Legacy unsalted-parameter salted SHA-1 scheme, kept *only* for verify.

    It models an old algorithm that must continue to authenticate existing
    accounts so they can be transparently migrated on next login.
    """

    algorithm_id: str = "legacy_sha1"
    version: int = 1
    salt_bytes: int = 8

    def encode(self, password: str, *, cost: int | None = None) -> EncodedHash:
        salt = secrets.token_bytes(self.salt_bytes)
        digest = hashlib.sha1(salt + password.encode("utf-8")).digest()
        return encode_hash(self.algorithm_id, {"v": self.version}, salt, digest)

    def verify(self, password: str, encoded: EncodedHash) -> bool:
        try:
            algorithm_id, _params, salt, expected = parse_hash(encoded)
        except InvalidHash:
            return False
        if algorithm_id != self.algorithm_id or not salt:
            return False
        candidate = hashlib.sha1(salt + password.encode("utf-8")).digest()
        return hmac.compare_digest(candidate, expected)

    def needs_upgrade(
        self,
        encoded: EncodedHash,
        *,
        current_default_id: str,
        current_cost: int | None,
    ) -> bool:
        # Any non-default (legacy) scheme always wants migrating.
        return self.algorithm_id != current_default_id

    def cost_of(self, encoded: EncodedHash) -> int:
        return 1


class HasherRegistry:
    """Holds every hasher that may appear in stored data, plus the default."""

    def __init__(self) -> None:
        self._hashers: dict[str, PasswordHasher] = {}
        self._default_id: str | None = None

    def register(self, hasher: PasswordHasher, *, make_default: bool = False) -> None:
        self._hashers[hasher.algorithm_id] = hasher
        if make_default or self._default_id is None:
            self._default_id = hasher.algorithm_id

    def get(self, algorithm_id: str) -> PasswordHasher:
        try:
            return self._hashers[algorithm_id]
        except KeyError as exc:
            raise UnknownAlgorithm(f"no registered hasher for {algorithm_id!r}") from exc

    def identify(self, encoded: EncodedHash) -> PasswordHasher:
        algorithm_id, _, _, _ = parse_hash(encoded)
        return self.get(algorithm_id)

    def default(self) -> PasswordHasher:
        if self._default_id is None:
            raise UnknownAlgorithm("registry has no default hasher")
        return self._hashers[self._default_id]

    def set_default(self, algorithm_id: str) -> None:
        if algorithm_id not in self._hashers:
            raise UnknownAlgorithm(f"no registered hasher for {algorithm_id!r}")
        self._default_id = algorithm_id

    def ids(self) -> list[str]:
        return list(self._hashers)


def build_default_registry() -> HasherRegistry:
    """Registry shipped with the service: two PBKDF2 families + legacy SHA-1."""
    registry = HasherRegistry()
    registry.register(
        Pbkdf2Hasher("pbkdf2_sha256", version=1, hash_name="sha256", default_iterations=200_000),
        make_default=True,
    )
    registry.register(
        Pbkdf2Hasher("pbkdf2_sha512", version=1, hash_name="sha512", default_iterations=200_000),
    )
    registry.register(LegacySaltedSha1Hasher())
    return registry
