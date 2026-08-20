"""Own Vault management UI transports."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atlaso.app.database import get_db
from atlaso.app.models import EsxiKickstart, Schedule, Vault, VaultEntry
from atlaso.app.security import Identity, require_session_identity
from atlaso.app.ui_routes import MANAGEMENT_UI_ROOT

Endpoint = Callable[..., Any]


@dataclass(frozen=True)
class VaultsUiDependencies:
    """Provide facade-owned helpers without importing the compatibility facade."""

    require_management_ui_request: Endpoint
    require_admin_identity: Endpoint
    render: Endpoint
    verify_csrf: Endpoint
    vaults_context: Endpoint
    vaults_render_error: Endpoint
    create_vault: Endpoint
    decrypt_secret: Endpoint
    kickstart_template_variables: Endpoint
    parse_vault_uris_json: Endpoint
    record_audit: Endpoint
    update_vault_entry: Endpoint
    upsert_vault_entry: Endpoint
    vault_entry_input: Endpoint
    vault_marker_name: Endpoint


@dataclass(frozen=True)
class VaultsUiRouter:
    """Return the configured router and compatibility endpoint exports."""

    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_router(dependencies: VaultsUiDependencies) -> VaultsUiRouter:
    """Build the Vault management UI router.

    Args:
        dependencies: Stable facade dependencies used by the extracted transports.

    Returns:
        Configured management router and stable endpoint callables.
    """
    router = APIRouter(
        prefix=MANAGEMENT_UI_ROOT,
        dependencies=[Depends(dependencies.require_management_ui_request)],
    )
    require_admin_identity = dependencies.require_admin_identity
    render = dependencies.render
    verify_csrf = dependencies.verify_csrf
    vaults_context = dependencies.vaults_context
    _vaults_render_error = dependencies.vaults_render_error
    create_vault = dependencies.create_vault
    decrypt_secret = dependencies.decrypt_secret
    kickstart_template_variables = dependencies.kickstart_template_variables
    parse_vault_uris_json = dependencies.parse_vault_uris_json
    record_audit = dependencies.record_audit
    update_vault_entry = dependencies.update_vault_entry
    upsert_vault_entry = dependencies.upsert_vault_entry
    VaultEntryInput = dependencies.vault_entry_input
    vault_marker_name = dependencies.vault_marker_name

    @router.get("/vaults", response_class=HTMLResponse, response_model=None)
    def vaults_page(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the vaults page endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        require_admin_identity(identity)
        return render(
            request, "vaults.html", {"identity": identity, **vaults_context(db)}
        )

    @router.post("/vaults", response_model=None)
    def create_vault_from_ui(
        request: Request,
        name: str = Form(...),
        description: str = Form(""),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the create vault from ui endpoint.

        Args:
            request: Incoming HTTP request.
            name: Name of the target object.
            description: Human-readable description of the resource.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        require_admin_identity(identity)
        try:
            vault = create_vault(
                db,
                name=name,
                description=description,
                actor=identity.username,
            )
            db.commit()
        except ValueError as exc:
            db.rollback()
            return _vaults_render_error(request, identity, db, str(exc))
        except IntegrityError:
            db.rollback()
            return _vaults_render_error(
                request,
                identity,
                db,
                "A vault with this name already exists.",
                status_code=409,
            )
        record_audit(
            db,
            actor=identity.username,
            action="create_vault",
            resource_type="vault",
            resource_id=str(vault.id),
        )
        return RedirectResponse(f"/vaults#vault-panel-{vault.id}", status_code=303)

    @router.post("/vaults/{vault_id}/entries", response_model=None)
    def create_vault_entry_from_ui(
        vault_id: int,
        request: Request,
        key: str = Form(...),
        value: str = Form(""),
        description: str = Form(""),
        username: str = Form(""),
        resource_name: str = Form(""),
        uris_json: str = Form("[]"),
        copy_entry_id: str = Form(""),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the create vault entry from ui endpoint.

        Args:
            vault_id: Identifier of the vault.
            request: Incoming HTTP request.
            key: Stable setting, vault, or mapping key.
            value: Value to process.
            description: Human-readable description of the resource.
            username: Account name used for authentication or lookup.
            resource_name: Resource name supplied by the caller.
            uris_json: Uris json supplied by the caller.
            copy_entry_id: Identifier of the copy entry.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
            ValueError: If an input value is invalid.
        """
        verify_csrf(request, csrf)
        require_admin_identity(identity)
        vault = db.get(Vault, vault_id)
        if vault is None:
            raise HTTPException(status_code=404, detail="Vault not found.")
        source_entry: VaultEntry | None = None
        if copy_entry_id.strip():
            try:
                source_entry = db.get(VaultEntry, int(copy_entry_id))
            except ValueError as exc:
                raise HTTPException(
                    status_code=422,
                    detail="Choose a valid vault entry to copy.",
                ) from exc
            if source_entry is None or source_entry.vault_id != vault.id:
                raise HTTPException(status_code=404, detail="Vault entry not found.")
        copied_value = (
            decrypt_secret(source_entry.encrypted_value)
            if source_entry is not None and not value
            else value
        )
        try:
            _entry, created = upsert_vault_entry(
                db,
                vault=vault,
                entry=VaultEntryInput(
                    key=key,
                    secret_type=(
                        source_entry.secret_type
                        if source_entry is not None
                        else (
                            "esx_password"
                            if key.strip().lower().startswith("esx.")
                            else "vcf_password"
                        )
                    ),
                    value=copied_value,
                    description=description,
                    username=username,
                    resource_name=(
                        source_entry.resource_name
                        if source_entry is not None
                        else resource_name
                    ),
                    source_type=(
                        (source_entry.source_type or "manual")
                        if source_entry is not None
                        else "manual"
                    ),
                    source_endpoint=(
                        (source_entry.source_endpoint or "")
                        if source_entry is not None
                        else ""
                    ),
                    uris=parse_vault_uris_json(uris_json),
                    imported_at=(
                        source_entry.imported_at if source_entry is not None else None
                    ),
                ),
                actor=identity.username,
            )
            if not created:
                raise ValueError(
                    "That key already exists. Edit the existing entry to rotate its password."
                )
            db.commit()
        except ValueError as exc:
            db.rollback()
            return _vaults_render_error(
                request,
                identity,
                db,
                str(exc),
                status_code=409,
            )
        except IntegrityError:
            db.rollback()
            return _vaults_render_error(
                request,
                identity,
                db,
                "That key already exists in this vault.",
                status_code=409,
            )
        record_audit(
            db,
            actor=identity.username,
            action="create_vault_entry",
            resource_type="vault_entry",
            resource_id=str(_entry.id),
            detail=f"vault_id={vault.id}; key={_entry.key}; type={_entry.secret_type}"
            + (
                f"; copied_from_entry_id={source_entry.id}"
                if source_entry is not None
                else ""
            ),
        )
        return RedirectResponse(f"/vaults#vault-panel-{vault.id}", status_code=303)

    @router.post(
        "/vaults/{vault_id}/entries/{entry_id}/edit",
        response_model=None,
    )
    def edit_vault_entry_from_ui(
        vault_id: int,
        entry_id: int,
        request: Request,
        key: str = Form(...),
        value: str = Form(""),
        description: str = Form(""),
        username: str = Form(""),
        resource_name: str | None = Form(None),
        uris_json: str = Form("[]"),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the edit vault entry from ui endpoint.

        Args:
            vault_id: Identifier of the vault.
            entry_id: Identifier of the entry.
            request: Incoming HTTP request.
            key: Stable setting, vault, or mapping key.
            value: Value to process.
            description: Human-readable description of the resource.
            username: Account name used for authentication or lookup.
            resource_name: Resource name supplied by the caller.
            uris_json: Uris json supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        require_admin_identity(identity)
        entry = db.get(VaultEntry, entry_id)
        if entry is None or entry.vault_id != vault_id:
            raise HTTPException(status_code=404, detail="Vault entry not found.")
        try:
            update_vault_entry(
                entry,
                key=key,
                secret_type=entry.secret_type,
                value=value,
                description=description,
                username=username,
                resource_name=(
                    entry.resource_name if resource_name is None else resource_name
                ),
                uris=parse_vault_uris_json(uris_json),
            )
            db.add(entry)
            db.commit()
        except ValueError as exc:
            db.rollback()
            return _vaults_render_error(request, identity, db, str(exc))
        except IntegrityError:
            db.rollback()
            return _vaults_render_error(
                request,
                identity,
                db,
                "That key already exists in this vault.",
                status_code=409,
            )
        record_audit(
            db,
            actor=identity.username,
            action="update_vault_entry",
            resource_type="vault_entry",
            resource_id=str(entry.id),
            detail=f"vault_id={vault_id}; key={entry.key}; type={entry.secret_type}",
        )
        return RedirectResponse("/vaults", status_code=303)

    @router.post(
        "/vaults/{vault_id}/entries/{entry_id}/reveal",
        response_class=JSONResponse,
        response_model=None,
    )
    def reveal_vault_entry_from_ui(
        vault_id: int,
        entry_id: int,
        request: Request,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Handle the reveal vault entry from ui endpoint.

        Args:
            vault_id: Identifier of the vault.
            entry_id: Identifier of the entry.
            request: Incoming HTTP request.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        require_admin_identity(identity)
        entry = db.get(VaultEntry, entry_id)
        if entry is None or entry.vault_id != vault_id:
            raise HTTPException(status_code=404, detail="Vault entry not found.")
        value = decrypt_secret(entry.encrypted_value)
        record_audit(
            db,
            actor=identity.username,
            action="reveal_vault_entry",
            resource_type="vault_entry",
            resource_id=str(entry.id),
            detail=f"vault_id={vault_id}; key={entry.key}",
        )
        return JSONResponse(
            {"value": value},
            headers={
                "Cache-Control": "no-store, private",
                "Pragma": "no-cache",
            },
        )

    @router.post(
        "/vaults/{vault_id}/entries/{entry_id}/delete",
        response_model=None,
    )
    def delete_vault_entry_from_ui(
        vault_id: int,
        entry_id: int,
        request: Request,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the delete vault entry from ui endpoint.

        Args:
            vault_id: Identifier of the vault.
            entry_id: Identifier of the entry.
            request: Incoming HTTP request.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        require_admin_identity(identity)
        entry = db.get(VaultEntry, entry_id)
        if entry is None or entry.vault_id != vault_id:
            raise HTTPException(status_code=404, detail="Vault entry not found.")
        key = entry.key
        db.delete(entry)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_vault_entry",
            resource_type="vault_entry",
            resource_id=str(entry_id),
            detail=f"vault_id={vault_id}; key={key}",
        )
        return RedirectResponse("/vaults", status_code=303)

    @router.post("/vaults/{vault_id}/delete", response_model=None)
    def delete_vault_from_ui(
        vault_id: int,
        request: Request,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the delete vault from ui endpoint.

        Args:
            vault_id: Identifier of the vault.
            request: Incoming HTTP request.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        require_admin_identity(identity)
        vault = db.get(Vault, vault_id)
        if vault is None:
            raise HTTPException(status_code=404, detail="Vault not found.")
        dependent_schedules: list[str] = []
        for schedule in db.execute(
            select(Schedule).where(Schedule.task_type == "managed_script")
        ).scalars():
            try:
                if (
                    int(
                        json.loads(schedule.task_config_json or "{}").get("vault_id")
                        or 0
                    )
                    == vault.id
                ):
                    dependent_schedules.append(schedule.name)
            except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
                continue
        if dependent_schedules:
            return _vaults_render_error(
                request,
                identity,
                db,
                "Remove this vault from these schedules first: "
                f"{', '.join(dependent_schedules)}.",
                status_code=409,
            )
        marker_prefix = f"vault.{vault_marker_name(vault.name)}."
        dependent_kickstarts = [
            kickstart.name
            for kickstart in db.execute(
                select(EsxiKickstart)
                .where(EsxiKickstart.enabled.is_(True))
                .order_by(EsxiKickstart.name)
            ).scalars()
            if any(
                name.startswith(marker_prefix)
                for name in kickstart_template_variables(kickstart.content)[0]
            )
        ]
        if dependent_kickstarts:
            return _vaults_render_error(
                request,
                identity,
                db,
                "Remove this vault from these enabled Kickstarts first: "
                f"{', '.join(dependent_kickstarts)}.",
                status_code=409,
            )
        name = vault.name
        db.delete(vault)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_vault",
            resource_type="vault",
            resource_id=str(vault_id),
            detail=f"name={name}",
        )
        return RedirectResponse("/vaults", status_code=303)

    endpoints = {
        endpoint.__name__: endpoint
        for endpoint in (
            vaults_page,
            create_vault_from_ui,
            create_vault_entry_from_ui,
            edit_vault_entry_from_ui,
            reveal_vault_entry_from_ui,
            delete_vault_entry_from_ui,
            delete_vault_from_ui,
        )
    }
    return VaultsUiRouter(router=router, endpoints=endpoints)
