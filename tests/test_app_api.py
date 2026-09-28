"""End-to-end HTTP API tests."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from credential_store.app import create_app
from credential_store.hashers import build_default_registry
from credential_store.storage import CredentialStorage


@pytest.fixture
def client(tmp_path):
    storage = CredentialStorage(str(tmp_path / "api.db"))
    from credential_store.service import CredentialService
    from credential_store.config import CredentialConfig
    svc = CredentialService(storage, build_default_registry(), CredentialConfig())
    return TestClient(create_app(service=svc, own_storage=False))


def test_full_account_lifecycle_over_http(client):
    r = client.post("/accounts", json={"account_id": "u1", "password": "pw1"})
    assert r.status_code == 201
    # duplicate
    assert client.post("/accounts", json={"account_id": "u1", "password": "x"}).status_code == 409

    assert client.post("/accounts/u1/verify", json={"password": "pw1"}).json()["ok"]
    assert client.post("/accounts/u1/verify", json={"password": "bad"}).json()["ok"] is False

    r = client.get("/accounts/u1")
    assert r.status_code == 200 and r.json()["algorithm"] == "pbkdf2_sha256"

    assert client.put("/accounts/u1/password", json={"password": "pw2"}).status_code == 204
    assert client.post("/accounts/u1/verify", json={"password": "pw1"}).json()["ok"] is False
    assert client.post("/accounts/u1/verify", json={"password": "pw2"}).json()["ok"]

    client.post("/accounts/u1/disable")
    assert client.post("/accounts/u1/verify", json={"password": "pw2"}).status_code == 403
    client.post("/accounts/u1/enable")
    assert client.post("/accounts/u1/verify", json={"password": "pw2"}).json()["ok"]

    assert client.get("/stats").json()["total"] == 1
    assert client.delete("/accounts/u1").status_code == 204
    # Unknown account: generic non-confirming response (no account enumeration).
    r = client.post("/accounts/u1/verify", json={"password": "pw2"})
    assert r.status_code == 200 and r.json()["ok"] is False


def test_lockout_423_over_http(client):
    client.post("/accounts", json={"account_id": "u1", "password": "pw"})
    for _ in range(5):
        client.post("/accounts/u1/verify", json={"password": "nope"})
    r = client.post("/accounts/u1/verify", json={"password": "pw"})
    assert r.status_code == 423 and r.json()["locked"] is True
    client.post("/accounts/u1/unlock")
    assert client.post("/accounts/u1/verify", json={"password": "pw"}).json()["ok"]
