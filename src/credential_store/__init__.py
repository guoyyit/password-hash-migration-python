"""Local password credential store with transparent hash migration."""

from .config import CredentialConfig, LockoutPolicy, UpgradePolicy
from .errors import (
    AccountAlreadyExists,
    AccountDisabled,
    AccountLocked,
    AccountNotFound,
    CredentialError,
    InvalidHash,
    InvalidPassword,
    UnknownAlgorithm,
)
from .hashers import HasherRegistry
from .service import CredentialService
from .storage import CredentialStorage

__all__ = [
    "CredentialService",
    "CredentialStorage",
    "HasherRegistry",
    "CredentialConfig",
    "UpgradePolicy",
    "LockoutPolicy",
    "CredentialError",
    "AccountNotFound",
    "AccountAlreadyExists",
    "AccountDisabled",
    "AccountLocked",
    "InvalidPassword",
    "InvalidHash",
    "UnknownAlgorithm",
]
