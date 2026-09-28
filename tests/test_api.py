"""HTTP integration tests for the FastAPI application."""

from __future__ import annotations

from fastapi.testclient import TestClient

from credvault.api import create_app


def _client(tmp_path):
    return TestClient(create_app(tmp_path / "creds.json"))


def test_health_and_account_lifecycle(tmp_path):
    client = _client(tmp_path)
    assert client.get("/health").json() == {"status": "ok"}
    assert client.post("/accounts", json={"username": "a", "password": "pw"}).status_code == 200
    assert client.post("/accounts", json={"username": "a", "password": "pw"}).status_code == 409
    assert client.post("/verify", json={"username": "a", "password": "pw"}).status_code == 200
    assert client.post("/verify", json={"username": "a", "password": "x"}).status_code == 401


def test_verify_migration_flag(tmp_path):
    client = _client(tmp_path)
    client.post("/accounts", json={"username": "a", "password": "pw"})
    # first verify uses already-default algorithm -> migrated false
    assert client.post("/verify", json={"username": "a", "password": "pw"}).json() == {
        "username": "a", "migrated": False
    }


def test_change_reset_disable_delete(tmp_path):
    client = _client(tmp_path)
    client.post("/accounts", json={"username": "a", "password": "pw"})
    r = client.post(
        "/password/change",
        json={"username": "a", "old_password": "pw", "new_password": "pw2"},
    )
    assert r.status_code == 200
    assert client.post("/verify", json={"username": "a", "password": "pw"}).status_code == 401
    assert client.post("/verify", json={"username": "a", "password": "pw2"}).status_code == 200

    assert client.post("/admin/disable", json={"username": "a"}).status_code == 200
    assert client.post("/verify", json={"username": "a", "password": "pw2"}).status_code == 403
    assert client.post("/admin/reset", json={"username": "a", "new_password": "pw3"}).status_code == 200
    assert client.post("/verify", json={"username": "a", "password": "pw3"}).status_code == 200
    assert client.request("DELETE", "/admin/accounts/a").status_code == 200
    assert client.post("/verify", json={"username": "a", "password": "pw3"}).status_code == 401


def test_state_persists_across_app_restart(tmp_path):
    client = _client(tmp_path)
    client.post("/accounts", json={"username": "a", "password": "pw"})
    client2 = _client(tmp_path)
    assert client2.post("/verify", json={"username": "a", "password": "pw"}).status_code == 200
