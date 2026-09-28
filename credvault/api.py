"""Thin FastAPI HTTP layer over :class:`CredentialService`."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .config import ServiceConfig
from .models import VerifyOutcome
from .service import (
    AccountExistsError,
    AccountNotFoundError,
    CredentialService,
)

_OUTCOME_STATUS = {
    VerifyOutcome.BAD_CREDENTIAL: 401,
    VerifyOutcome.LOCKED: 423,
    VerifyOutcome.DISABLED: 403,
    VerifyOutcome.NOT_FOUND: 401,  # do not reveal account existence
}


class PasswordBody(BaseModel):
    username: str
    password: str


class ChangeBody(BaseModel):
    username: str
    old_password: str
    new_password: str


class ResetBody(BaseModel):
    username: str
    new_password: str


class UsernameBody(BaseModel):
    username: str


def create_app(
    db_path: str | Path = "credentials.json",
    config: ServiceConfig | None = None,
) -> FastAPI:
    service = CredentialService.open(db_path, config)
    app = FastAPI(title="credvault", version="1.0.0")
    app.state.service = service

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/accounts")
    def create_account(body: PasswordBody) -> dict[str, str]:
        try:
            service.create_account(body.username, body.password)
        except AccountExistsError as exc:
            raise HTTPException(status_code=409, detail="account exists") from exc
        return {"username": body.username, "status": "created"}

    @app.post("/verify")
    def verify(body: PasswordBody) -> dict[str, Any]:
        result = service.verify(body.username, body.password)
        if result.outcome is not VerifyOutcome.SUCCESS:
            raise HTTPException(
                status_code=_OUTCOME_STATUS[result.outcome],
                detail={"reason": result.outcome.value},
            )
        return {"username": body.username, "migrated": result.migrated}

    @app.post("/password/change")
    def change_password(body: ChangeBody) -> dict[str, str]:
        try:
            ok = service.change_password(
                body.username, body.old_password, body.new_password
            )
        except AccountNotFoundError as exc:
            raise HTTPException(status_code=401, detail="invalid credentials") from exc
        if not ok:
            raise HTTPException(status_code=401, detail="invalid credentials")
        return {"status": "changed"}

    @app.post("/admin/reset")
    def reset_password(body: ResetBody) -> dict[str, str]:
        try:
            service.reset_password(body.username, body.new_password)
        except AccountNotFoundError as exc:
            raise HTTPException(status_code=404, detail="not found") from exc
        return {"status": "reset"}

    @app.post("/admin/disable")
    def disable_account(body: UsernameBody) -> dict[str, str]:
        try:
            service.disable_account(body.username)
        except AccountNotFoundError as exc:
            raise HTTPException(status_code=404, detail="not found") from exc
        return {"status": "disabled"}

    @app.post("/admin/enable")
    def enable_account(body: UsernameBody) -> dict[str, str]:
        try:
            service.enable_account(body.username)
        except AccountNotFoundError as exc:
            raise HTTPException(status_code=404, detail="not found") from exc
        return {"status": "enabled"}

    @app.delete("/admin/accounts/{username}")
    def delete_account(username: str) -> dict[str, str]:
        try:
            service.delete_account(username)
        except AccountNotFoundError as exc:
            raise HTTPException(status_code=404, detail="not found") from exc
        return {"status": "deleted"}

    return app
