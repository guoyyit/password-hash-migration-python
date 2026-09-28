"""FastAPI wiring exposing the credential service over HTTP.

Passwords appear only inside request bodies; responses and logs never echo
them or any stored hash.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .config import CredentialConfig
from .errors import (
    AccountAlreadyExists,
    AccountDisabled,
    AccountLocked,
    AccountNotFound,
    CredentialError,
)
from .hashers import HasherRegistry, build_default_registry
from .service import CredentialService
from .storage import CredentialStorage


class CreateAccountRequest(BaseModel):
    account_id: str = Field(min_length=1, max_length=256)
    password: str = Field(min_length=1, max_length=1024)


class PasswordRequest(BaseModel):
    password: str = Field(min_length=1, max_length=1024)


def create_app(
    db_path: str | None = None,
    config: CredentialConfig | None = None,
    registry: HasherRegistry | None = None,
    *,
    own_storage: bool = True,
    service: CredentialService | None = None,
) -> FastAPI:
    if service is not None:
        svc = service
        own_storage = False
    else:
        path = db_path or os.environ.get("CREDSTORE_DB", ":memory:")
        storage = CredentialStorage(path)
        svc = CredentialService(storage, registry or build_default_registry(), config)

    app = FastAPI(title="local-credential-store", version="0.1.0")

    @app.exception_handler(CredentialError)
    async def credential_error_handler(_request, exc: CredentialError) -> JSONResponse:
        status = 400
        detail: Any = {"error": type(exc).__name__}
        if isinstance(exc, AccountNotFound):
            status = 404
        elif isinstance(exc, AccountAlreadyExists):
            status = 409
        elif isinstance(exc, AccountDisabled):
            status = 403
        elif isinstance(exc, AccountLocked):
            status = 423
            detail["locked_until"] = exc.locked_until
        return JSONResponse(status_code=status, content=detail)

    @app.post("/accounts", status_code=201)
    def create_account(body: CreateAccountRequest) -> dict[str, str]:
        svc.create_account(body.account_id, body.password)
        return {"account_id": body.account_id}

    @app.post("/accounts/{account_id}/verify")
    def verify(account_id: str, body: PasswordRequest) -> dict[str, object]:
        # Invalid password returns 200 with ok=false (no information leak in
        # status codes beyond disabled/locked), or 401 if you prefer; we use
        # an explicit body so clients branch on ``ok``.
        try:
            ok = svc.verify(account_id, body.password)
        except AccountLocked as exc:
            return JSONResponse(
                status_code=423,
                content={"ok": False, "locked": True, "locked_until": exc.locked_until},
            )
        except AccountDisabled:
            return JSONResponse(status_code=403, content={"ok": False, "disabled": True})
        except AccountNotFound:
            return JSONResponse(status_code=404, content={"ok": False})
        return {"ok": ok}

    @app.get("/accounts/{account_id}")
    def get_account(account_id: str) -> dict[str, object]:
        record = svc.get_record(account_id)
        return {
            "account_id": record.account_id,
            "algorithm": record.algorithm_id,
            "version": record.version,
            "disabled": record.disabled,
            "failed_count": record.failed_count,
            "locked_until": record.locked_until,
            "needs_upgrade": svc.needs_upgrade(account_id),
        }

    @app.put("/accounts/{account_id}/password", status_code=204)
    def set_password(account_id: str, body: PasswordRequest) -> None:
        svc.set_password(account_id, body.password)

    @app.post("/accounts/{account_id}/reset", status_code=204)
    def reset_password(account_id: str, body: PasswordRequest) -> None:
        svc.reset_password(account_id, body.password)

    @app.post("/accounts/{account_id}/disable", status_code=204)
    def disable(account_id: str) -> None:
        svc.disable_account(account_id)

    @app.post("/accounts/{account_id}/enable", status_code=204)
    def enable(account_id: str) -> None:
        svc.enable_account(account_id)

    @app.post("/accounts/{account_id}/unlock", status_code=204)
    def unlock(account_id: str) -> None:
        svc.unlock_account(account_id)

    @app.delete("/accounts/{account_id}", status_code=204)
    def delete_account(account_id: str) -> None:
        svc.delete_account(account_id)

    @app.get("/stats")
    def stats() -> dict[str, object]:
        return svc.stats()

    if own_storage:
        @app.on_event("shutdown")
        def _close() -> None:
            svc.storage.close()

    return app


app = create_app()
