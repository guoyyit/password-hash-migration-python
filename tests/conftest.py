"""Shared pytest fixtures."""

from __future__ import annotations

import pytest

from credential_store.config import CredentialConfig
from credential_store.hashers import build_default_registry
from credential_store.service import CredentialService
from credential_store.storage import CredentialStorage


@pytest.fixture
def registry():
    return build_default_registry()


@pytest.fixture
def service(tmp_path, registry):
    storage = CredentialStorage(str(tmp_path / "creds.db"))
    svc = CredentialService(storage, registry, CredentialConfig())
    yield svc
    storage.close()
