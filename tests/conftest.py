"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from credvault.config import ServiceConfig
from credvault.hashes import default_registry
from credvault.service import CredentialService
from credvault.store import CredentialStore


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "credentials.json"


@pytest.fixture
def config() -> ServiceConfig:
    # Small/cheap defaults keep the suite fast; locking is exercised with
    # an injectable clock where needed.
    return ServiceConfig(max_failures=3, lock_seconds=600.0)


@pytest.fixture
def service(db_path: Path, config: ServiceConfig) -> CredentialService:
    return CredentialService.open(db_path, config)


def make_service(db_path: Path, config: ServiceConfig | None = None,
                 registry=None, *, now=None) -> CredentialService:
    """Factory helper used by tests that need a clock or custom registry."""
    store = CredentialStore(db_path)
    kwargs = {}
    if now is not None:
        kwargs["now"] = now
    return CredentialService(
        store, registry or default_registry(), config or ServiceConfig(), **kwargs
    )
