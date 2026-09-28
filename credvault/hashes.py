"""Pluggable password hash algorithms and a versioned algorithm registry.

Multiple algorithms (and parameter sets) can be registered at the same time.
Old credentials remain verifiable forever as long as their algorithm is
registered; newly set passwords always use the current default algorithm.

All digests and salts are base64 text so parameter dictionaries are JSON
safe. Plaintext passwords are only ever handled inside local variables and
are never stored on a hasher or returned.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from abc import ABC, abstractmethod
from typing import Any

# Default cost parameters. Kept modest so the test suite stays fast.
DEFAULT_PBKDF2_ITERATIONS = 120_000
DEFAULT_SCRYPT_N = 2 ** 14
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1
DEFAULT_KEY_LEN = 32
DEFAULT_SALT_LEN = 16


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _new_salt(length: int = DEFAULT_SALT_LEN) -> bytes:
    return os.urandom(length)


class PasswordHasher(ABC):
    """Abstract password hash algorithm."""

    #: Unique stable identifier persisted with credentials.
    name: str = ""

    @abstractmethod
    def hash(self, password: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return a JSON-serialisable parameter dict (salt, digest, ...)."""
        raise NotImplementedError

    @abstractmethod
    def verify(self, password: str, params: dict[str, Any]) -> bool:
        """Check ``password`` against stored params without leaking timing."""
        raise NotImplementedError

    def needs_upgrade(
        self, params: dict[str, Any], default_params: dict[str, Any] | None
    ) -> bool:
        """Whether a credential using this hasher should be rehashed.

        Default: never (algorithm equality alone is enough). Subclasses with
        tunable cost (PBKDF2, scrypt) override this to compare cost.
        """
        return False


class PBKDF2SHA256Hasher(PasswordHasher):
    """PBKDF2-HMAC-SHA256, the current default algorithm."""

    name = "pbkdf2_sha256"

    def __init__(
        self,
        default_iterations: int = DEFAULT_PBKDF2_ITERATIONS,
        dklen: int = DEFAULT_KEY_LEN,
    ) -> None:
        self.default_iterations = default_iterations
        self.dklen = dklen

    def hash(self, password: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        iterations = int((params or {}).get("iterations", self.default_iterations))
        salt = _new_salt()
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations, dklen=self.dklen
        )
        return {
            "salt": _b64e(salt),
            "iterations": iterations,
            "digest": _b64e(digest),
        }

    def verify(self, password: str, params: dict[str, Any]) -> bool:
        try:
            salt = _b64d(params["salt"])
            iterations = int(params["iterations"])
            expected = _b64d(params["digest"])
            candidate = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), salt, iterations,
                dklen=len(expected),
            )
        except (KeyError, TypeError, ValueError, OverflowError):
            return False
        return hmac.compare_digest(candidate, expected)

    def needs_upgrade(
        self, params: dict[str, Any], default_params: dict[str, Any] | None
    ) -> bool:
        target = (default_params or {}).get("iterations", self.default_iterations)
        try:
            return int(params.get("iterations", 0)) < int(target)
        except (TypeError, ValueError):
            return True


class ScryptHasher(PasswordHasher):
    """scrypt, registered as an alternative/newer algorithm option."""

    name = "scrypt"

    def __init__(
        self,
        default_n: int = DEFAULT_SCRYPT_N,
        r: int = DEFAULT_SCRYPT_R,
        p: int = DEFAULT_SCRYPT_P,
        dklen: int = DEFAULT_KEY_LEN,
    ) -> None:
        self.default_n = default_n
        self.r = r
        self.p = p
        self.dklen = dklen

    def hash(self, password: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        overrides = params or {}
        n = int(overrides.get("n", self.default_n))
        r = int(overrides.get("r", self.r))
        p = int(overrides.get("p", self.p))
        dklen = int(overrides.get("dklen", self.dklen))
        salt = _new_salt()
        digest = hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=dklen
        )
        return {"salt": _b64e(salt), "n": n, "r": r, "p": p, "dklen": dklen,
                "digest": _b64e(digest)}

    def verify(self, password: str, params: dict[str, Any]) -> bool:
        try:
            salt = _b64d(params["salt"])
            n = int(params["n"])
            r = int(params["r"])
            p = int(params["p"])
            dklen = int(params["dklen"])
            expected = _b64d(params["digest"])
            candidate = hashlib.scrypt(
                password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=dklen
            )
        except (KeyError, TypeError, ValueError, OverflowError):
            return False
        return hmac.compare_digest(candidate, expected)

    def needs_upgrade(
        self, params: dict[str, Any], default_params: dict[str, Any] | None
    ) -> bool:
        target_n = (default_params or {}).get("n", self.default_n)
        try:
            return int(params.get("n", 0)) < int(target_n)
        except (TypeError, ValueError):
            return True


class _LegacySHA256Hasher(PasswordHasher):
    """Base for deliberately weak legacy schemes used by pre-upgrade data."""

    def verify(self, password: str, params: dict[str, Any]) -> bool:
        raise NotImplementedError

    def _raw_hash(self, password: str, salt: bytes) -> bytes:
        raise NotImplementedError


class UnsaltedSHA256LegacyHasher(_LegacySHA256Hasher):
    """Single-round unsalted SHA-256 (insecure, legacy data only)."""

    name = "legacy_sha256_unsalted"

    def hash(self, password: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        digest = hashlib.sha256(password.encode("utf-8")).digest()
        return {"digest": _b64e(digest)}

    def verify(self, password: str, params: dict[str, Any]) -> bool:
        try:
            expected = _b64d(params["digest"])
        except (KeyError, TypeError, ValueError):
            return False
        candidate = hashlib.sha256(password.encode("utf-8")).digest()
        return hmac.compare_digest(candidate, expected)

    def needs_upgrade(
        self, params: dict[str, Any], default_params: dict[str, Any] | None
    ) -> bool:
        return True


class SaltedSHA256LegacyHasher(_LegacySHA256Hasher):
    """Single-round salted SHA-256 (insecure, legacy data only)."""

    name = "legacy_sha256_salted"

    def hash(self, password: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        salt = _new_salt()
        digest = hashlib.sha256(salt + password.encode("utf-8")).digest()
        return {"salt": _b64e(salt), "digest": _b64e(digest)}

    def verify(self, password: str, params: dict[str, Any]) -> bool:
        try:
            salt = _b64d(params["salt"])
            expected = _b64d(params["digest"])
        except (KeyError, TypeError, ValueError):
            return False
        candidate = hashlib.sha256(salt + password.encode("utf-8")).digest()
        return hmac.compare_digest(candidate, expected)

    def needs_upgrade(
        self, params: dict[str, Any], default_params: dict[str, Any] | None
    ) -> bool:
        return True


class UnknownAlgorithmError(KeyError):
    """Raised when a credential references an unregistered algorithm."""


class AlgorithmRegistry:
    """Registry of known hash algorithms; supports multiple versions."""

    def __init__(self) -> None:
        self._hashers: dict[str, PasswordHasher] = {}
        self._default: str | None = None

    def register(self, hasher: PasswordHasher, *, set_default: bool = False) -> None:
        if not getattr(hasher, "name", ""):
            raise ValueError("hasher must declare a non-empty name")
        self._hashers[hasher.name] = hasher
        if set_default or self._default is None:
            self._default = hasher.name

    def get(self, name: str) -> PasswordHasher:
        try:
            return self._hashers[name]
        except KeyError as exc:
            raise UnknownAlgorithmError(name) from exc

    def is_registered(self, name: str) -> bool:
        return name in self._hashers

    def names(self) -> list[str]:
        return list(self._hashers)

    @property
    def default_name(self) -> str:
        if self._default is None:
            raise RuntimeError("no default password hasher registered")
        return self._default

    @default_name.setter
    def default_name(self, name: str) -> None:
        if name not in self._hashers:
            raise UnknownAlgorithmError(name)
        self._default = name


def default_registry() -> AlgorithmRegistry:
    """Registry with the current algorithm and both legacy verifiers."""
    registry = AlgorithmRegistry()
    registry.register(PBKDF2SHA256Hasher(), set_default=True)
    registry.register(ScryptHasher())
    registry.register(SaltedSHA256LegacyHasher())
    registry.register(UnsaltedSHA256LegacyHasher())
    return registry
