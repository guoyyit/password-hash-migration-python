"""Domain errors for the local credential store."""


class CredentialError(Exception):
    """Base class for all credential-store errors."""


class AccountNotFound(CredentialError):
    """Raised when an account id is unknown."""


class AccountAlreadyExists(CredentialError):
    """Raised when creating an account that already exists."""


class AccountDisabled(CredentialError):
    """Raised when authenticating against a disabled account."""


class AccountLocked(CredentialError):
    """Raised when authenticating against a locked (non-expired) account."""

    def __init__(self, locked_until: float | None = None) -> None:
        super().__init__("account is locked")
        self.locked_until = locked_until


class InvalidPassword(CredentialError):
    """Raised when the presented password does not match the stored hash."""


class InvalidHash(CredentialError):
    """Raised when a stored/encoded hash cannot be parsed or verified."""


class UnknownAlgorithm(CredentialError):
    """Raised when no registered hasher matches a stored algorithm id."""


class RehashSkipped(Exception):
    """Raised internally to signal that an upgrade was deliberately skipped.

    This is control flow, not an authentication failure: the password was
    already verified successfully.
    """


class RehashFailed(Exception):
    """Raised internally when the transparent upgrade could not be committed.

    A successful verification is never rolled back because of this.
    """
