"""Own Network Boot and ESXi PXE API v1 transport handlers."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Response,
    UploadFile,
)
from fastapi import Path as ApiPath
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from atlaso.app.audit import record_audit
from atlaso.app.config import Settings, get_settings
from atlaso.app.database import get_db
from atlaso.app.models import EsxiKickstart, EsxiPxeHost, utcnow
from atlaso.app.openapi import DocumentedAPIRoute
from atlaso.app.schemas import (
    EsxiCustomVariableCreate,
    EsxiCustomVariableResponse,
    EsxiCustomVariableUpdate,
    EsxiInstallerIsoResponse,
    EsxiKickstartCreate,
    EsxiKickstartDuplicateRequest,
    EsxiKickstartPreviewResponse,
    EsxiKickstartResponse,
    EsxiKickstartUpdate,
    EsxiKickstartValidationResponse,
    EsxiPxeHostCreate,
    EsxiPxeHostDeleteResponse,
    EsxiPxeHostResponse,
    ProblemDetails,
)
from atlaso.app.security import Identity, require_scope
from atlaso.app.services.esxi_pxe import (
    assign_kickstart_content,
    canonical_http_path,
    content_hash,
    custom_variable_definitions,
    decode_kickstart_upload,
    delete_custom_variable_definition,
    esxi_pxe_boot_settings,
    host_to_dict,
    host_variables_json,
    installer_iso_inventory,
    kickstart_to_dict,
    kickstart_validation,
    normalize_host_mac,
    normalize_installer_iso_path,
    normalize_kickstart_name,
    redacted_kickstart_preview,
    save_custom_variable_definition,
    store_installer_iso_upload,
    strict_validation_enabled,
    sync_esxi_pxe_host_network_records,
    validate_kickstart_custom_references,
    validate_kickstart_vault_references,
)
from atlaso.app.services.network_boot import (
    lock_esxi_host_reference_lifecycle,
    remove_esxi_host_discovery_state,
)

Endpoint = Callable[..., Any]


@dataclass(frozen=True)
class NetworkBootApiRouter:
    """Return the configured router and compatibility endpoint exports."""

    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_router() -> NetworkBootApiRouter:
    """Build the Network Boot and ESXi PXE API v1 router."""
    router = APIRouter(prefix="/api/v1", route_class=DocumentedAPIRoute)

    def _kickstart_response(
        kickstart: EsxiKickstart, identity: Identity
    ) -> EsxiKickstartResponse:
        """Return kickstart response.

        Args:
            kickstart: Kickstart supplied by the caller.
            identity: Authenticated identity authorizing the request.
        """
        include_content = identity.can("write:esxi-pxe")
        return EsxiKickstartResponse(
            **kickstart_to_dict(kickstart, include_content=include_content)
        )

    def _assign_kickstart_payload(
        kickstart: EsxiKickstart,
        payload: EsxiKickstartCreate | EsxiKickstartUpdate,
        max_bytes: int,
    ) -> None:
        """Handle assign kickstart payload.

        Args:
            kickstart: Kickstart supplied by the caller.
            payload: Validated request or operation payload.
            max_bytes: Maximum accepted payload size in bytes.
        """
        kickstart.name = normalize_kickstart_name(payload.name)
        kickstart.description = payload.description or None
        kickstart.enabled = payload.enabled
        assign_kickstart_content(kickstart, payload.content, max_bytes=max_bytes)

    @router.get(
        "/esxi-pxe/custom-variables",
        response_model=list[EsxiCustomVariableResponse],
        tags=["ESXi PXE"],
        operation_id="listEsxiCustomVariables",
    )
    def list_esxi_custom_variables(
        identity: Annotated[Identity, Depends(require_scope("read:esxi-pxe"))],
        db: Session = Depends(get_db),
    ) -> list[EsxiCustomVariableResponse]:
        """List Esxi Custom Variables.

        Requires the `read:esxi-pxe` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return [
            EsxiCustomVariableResponse(**row) for row in custom_variable_definitions(db)
        ]

    @router.post(
        "/esxi-pxe/custom-variables",
        response_model=EsxiCustomVariableResponse,
        status_code=201,
        tags=["ESXi PXE"],
        operation_id="createEsxiCustomVariable",
    )
    def create_esxi_custom_variable(
        payload: EsxiCustomVariableCreate,
        identity: Annotated[Identity, Depends(require_scope("write:esxi-pxe"))],
        db: Session = Depends(get_db),
    ) -> EsxiCustomVariableResponse:
        """Create Esxi Custom Variable.

        Requires the `write:esxi-pxe` API scope. The operation changes saved Atlaso application state;
        any appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        try:
            variable = save_custom_variable_definition(
                db,
                name=payload.name,
                description=payload.description,
                default_value=payload.default_value,
            )
            db.commit()
        except ValueError as exc:
            db.rollback()
            status_code = 409 if "already exists" in str(exc).lower() else 422
            raise HTTPException(status_code=status_code, detail=str(exc)) from exc
        record_audit(
            db,
            actor=identity.username,
            action="create_esxi_custom_variable",
            resource_type="esxi_custom_variable",
            resource_id=variable["name"],
            detail=f"name={variable['name']}",
        )
        return EsxiCustomVariableResponse(**variable)

    @router.put(
        "/esxi-pxe/custom-variables/{variable_name}",
        response_model=EsxiCustomVariableResponse,
        tags=["ESXi PXE"],
        operation_id="updateEsxiCustomVariable",
    )
    def update_esxi_custom_variable(
        variable_name: Annotated[
            str,
            ApiPath(
                description="Stable variable name identifying the resource addressed by this operation."
            ),
        ],
        payload: EsxiCustomVariableUpdate,
        identity: Annotated[Identity, Depends(require_scope("write:esxi-pxe"))],
        db: Session = Depends(get_db),
    ) -> EsxiCustomVariableResponse:
        """Update Esxi Custom Variable.

        Requires the `write:esxi-pxe` API scope. The operation updates saved Atlaso state and does not
        bypass the documented global Appliance Apply or service lifecycle boundary.

        Args:
            variable_name: Filesystem path associated with variable name.
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        if variable_name not in {
            row["name"] for row in custom_variable_definitions(db)
        }:
            raise HTTPException(status_code=404, detail="Custom variable not found")
        try:
            variable = save_custom_variable_definition(
                db,
                name=payload.name,
                description=payload.description,
                default_value=payload.default_value,
                original_name=variable_name,
            )
            db.commit()
        except ValueError as exc:
            db.rollback()
            status_code = 409 if "already exists" in str(exc).lower() else 422
            raise HTTPException(status_code=status_code, detail=str(exc)) from exc
        record_audit(
            db,
            actor=identity.username,
            action="update_esxi_custom_variable",
            resource_type="esxi_custom_variable",
            resource_id=variable["name"],
            detail=f"previous_name={variable_name} name={variable['name']}",
        )
        return EsxiCustomVariableResponse(**variable)

    @router.delete(
        "/esxi-pxe/custom-variables/{variable_name}",
        response_model=dict,
        tags=["ESXi PXE"],
        operation_id="deleteEsxiCustomVariable",
    )
    def delete_esxi_custom_variable(
        variable_name: Annotated[
            str,
            ApiPath(
                description="Stable variable name identifying the resource addressed by this operation."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("write:esxi-pxe"))],
        db: Session = Depends(get_db),
    ) -> dict:
        """Delete Esxi Custom Variable.

        Requires the `write:esxi-pxe` API scope. Removal or revocation takes effect in Atlaso
        application state; appliance host changes remain subject to the documented apply boundary for
        the resource.

        Args:
            variable_name: Filesystem path associated with variable name.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        if not delete_custom_variable_definition(db, variable_name):
            raise HTTPException(status_code=404, detail="Custom variable not found")
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_esxi_custom_variable",
            resource_type="esxi_custom_variable",
            resource_id=variable_name,
        )
        return {"deleted": True}

    @router.get(
        "/esxi-pxe/kickstarts",
        response_model=list[EsxiKickstartResponse],
        tags=["ESXi PXE"],
        operation_id="listEsxiKickstarts",
    )
    def list_esxi_kickstarts(
        identity: Annotated[Identity, Depends(require_scope("read:esxi-pxe"))],
        db: Session = Depends(get_db),
    ) -> list[EsxiKickstartResponse]:
        """List Esxi Kickstarts.

        Requires the `read:esxi-pxe` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        rows = (
            db.execute(select(EsxiKickstart).order_by(EsxiKickstart.name))
            .scalars()
            .all()
        )
        return [_kickstart_response(row, identity) for row in rows]

    @router.post(
        "/esxi-pxe/kickstarts",
        response_model=EsxiKickstartResponse,
        status_code=201,
        tags=["ESXi PXE"],
        operation_id="createEsxiKickstart",
    )
    def create_esxi_kickstart(
        payload: EsxiKickstartCreate,
        identity: Annotated[Identity, Depends(require_scope("write:esxi-pxe"))],
        db: Session = Depends(get_db),
        settings: Settings = Depends(get_settings),
    ) -> EsxiKickstartResponse:
        """Create Esxi Kickstart.

        Requires the `write:esxi-pxe` API scope. The operation changes saved Atlaso application state;
        any appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
            settings: Current Atlaso settings used to configure the operation.
        """
        kickstart = EsxiKickstart(
            name=normalize_kickstart_name(payload.name),
            content="",
            content_hash="",
            enabled=payload.enabled,
        )
        db.add(kickstart)
        db.flush()
        _assign_kickstart_payload(kickstart, payload, settings.esxi_kickstart_max_bytes)
        try:
            validate_kickstart_custom_references(db, kickstart.content)
            validate_kickstart_vault_references(db, kickstart.content)
            db.commit()
        except ValueError as exc:
            db.rollback()
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409, detail=f"Kickstart {payload.name} already exists."
            ) from exc
        db.refresh(kickstart)
        record_audit(
            db,
            actor=identity.username,
            action="create_esxi_kickstart",
            resource_type="esxi_kickstart",
            resource_id=str(kickstart.id),
            detail=f"name={kickstart.name} hash={kickstart.content_hash}",
        )
        return _kickstart_response(kickstart, identity)

    @router.get(
        "/esxi-pxe/kickstarts/{kickstart_id}",
        response_model=EsxiKickstartResponse,
        tags=["ESXi PXE"],
        operation_id="getEsxiKickstart",
    )
    def get_esxi_kickstart(
        kickstart_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the kickstart record addressed by this operation."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("read:esxi-pxe"))],
        db: Session = Depends(get_db),
    ) -> EsxiKickstartResponse:
        """Get Esxi Kickstart.

        Requires the `read:esxi-pxe` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            kickstart_id: Stable identifier of the associated kickstart resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        kickstart = db.get(EsxiKickstart, kickstart_id)
        if not kickstart:
            raise HTTPException(status_code=404, detail="Kickstart not found")
        return _kickstart_response(kickstart, identity)

    @router.put(
        "/esxi-pxe/kickstarts/{kickstart_id}",
        response_model=EsxiKickstartResponse,
        tags=["ESXi PXE"],
        operation_id="updateEsxiKickstart",
    )
    def update_esxi_kickstart(
        kickstart_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the kickstart record addressed by this operation."
            ),
        ],
        payload: EsxiKickstartUpdate,
        identity: Annotated[Identity, Depends(require_scope("write:esxi-pxe"))],
        db: Session = Depends(get_db),
        settings: Settings = Depends(get_settings),
    ) -> EsxiKickstartResponse:
        """Update Esxi Kickstart.

        Requires the `write:esxi-pxe` API scope. The operation updates saved Atlaso state and does not
        bypass the documented global Appliance Apply or service lifecycle boundary.

        Args:
            kickstart_id: Stable identifier of the associated kickstart resource.
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
            settings: Current Atlaso settings used to configure the operation.
        """
        kickstart = db.get(EsxiKickstart, kickstart_id)
        if not kickstart:
            raise HTTPException(status_code=404, detail="Kickstart not found")
        _assign_kickstart_payload(kickstart, payload, settings.esxi_kickstart_max_bytes)
        db.add(kickstart)
        try:
            validate_kickstart_custom_references(db, kickstart.content)
            validate_kickstart_vault_references(db, kickstart.content)
            db.commit()
        except ValueError as exc:
            db.rollback()
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409, detail=f"Kickstart {payload.name} already exists."
            ) from exc
        db.refresh(kickstart)
        record_audit(
            db,
            actor=identity.username,
            action="update_esxi_kickstart",
            resource_type="esxi_kickstart",
            resource_id=str(kickstart.id),
            detail=f"name={kickstart.name} hash={kickstart.content_hash}",
        )
        return _kickstart_response(kickstart, identity)

    @router.delete(
        "/esxi-pxe/kickstarts/{kickstart_id}",
        response_model=dict,
        tags=["ESXi PXE"],
        operation_id="deleteEsxiKickstart",
    )
    def delete_esxi_kickstart(
        kickstart_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the kickstart record addressed by this operation."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("write:esxi-pxe"))],
        db: Session = Depends(get_db),
    ) -> dict:
        """Delete Esxi Kickstart.

        Requires the `write:esxi-pxe` API scope. Removal or revocation takes effect in Atlaso
        application state; appliance host changes remain subject to the documented apply boundary for
        the resource.

        Args:
            kickstart_id: Stable identifier of the associated kickstart resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        kickstart = db.get(EsxiKickstart, kickstart_id)
        if not kickstart:
            raise HTTPException(status_code=404, detail="Kickstart not found")
        for host in (
            db.execute(
                select(EsxiPxeHost).where(EsxiPxeHost.kickstart_id == kickstart.id)
            )
            .scalars()
            .all()
        ):
            host.kickstart_id = None
            host.updated_at = utcnow()
            db.add(host)
        db.delete(kickstart)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_esxi_kickstart",
            resource_type="esxi_kickstart",
            resource_id=str(kickstart_id),
        )
        return {"deleted": True}

    @router.post(
        "/esxi-pxe/kickstarts/{kickstart_id}/duplicate",
        response_model=EsxiKickstartResponse,
        status_code=201,
        tags=["ESXi PXE"],
        operation_id="duplicateEsxiKickstart",
    )
    def duplicate_esxi_kickstart(
        kickstart_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the kickstart record addressed by this operation."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("write:esxi-pxe"))],
        payload: EsxiKickstartDuplicateRequest | None = None,
        db: Session = Depends(get_db),
    ) -> EsxiKickstartResponse:
        """Duplicate Esxi Kickstart.

        Requires the `write:esxi-pxe` API scope. The operation changes saved Atlaso application state;
        any appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            kickstart_id: Stable identifier of the associated kickstart resource.
            identity: Authenticated identity authorizing the operation.
            payload: Validated request or task payload consumed by the operation.
            db: Active database session used by the operation.
        """
        source = db.get(EsxiKickstart, kickstart_id)
        if not source:
            raise HTTPException(status_code=404, detail="Kickstart not found")
        name = normalize_kickstart_name(
            payload.name if payload and payload.name else f"{source.name} Copy"
        )
        duplicate = EsxiKickstart(
            name=name,
            description=source.description,
            content=source.content,
            content_hash=source.content_hash,
            rendered_content=source.rendered_content,
            enabled=source.enabled,
        )
        db.add(duplicate)
        db.flush()
        duplicate.http_path = canonical_http_path(duplicate.id, duplicate.content_hash)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409, detail=f"Kickstart {name} already exists."
            ) from exc
        db.refresh(duplicate)
        record_audit(
            db,
            actor=identity.username,
            action="duplicate_esxi_kickstart",
            resource_type="esxi_kickstart",
            resource_id=str(duplicate.id),
            detail=f"source_id={source.id} name={duplicate.name}",
        )
        return _kickstart_response(duplicate, identity)

    @router.post(
        "/esxi-pxe/kickstarts/{kickstart_id}/validate",
        response_model=EsxiKickstartValidationResponse,
        tags=["ESXi PXE"],
        operation_id="validateEsxiKickstart",
    )
    def validate_esxi_kickstart(
        kickstart_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the kickstart record addressed by this operation."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("read:esxi-pxe"))],
        db: Session = Depends(get_db),
        settings: Settings = Depends(get_settings),
    ) -> EsxiKickstartValidationResponse:
        """Validate Esxi Kickstart.

        Requires the `read:esxi-pxe` API scope. The request is evaluated without persisting desired
        state or mutating appliance runtime state.

        Args:
            kickstart_id: Stable identifier of the associated kickstart resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
            settings: Current Atlaso settings used to configure the operation.
        """
        kickstart = db.get(EsxiKickstart, kickstart_id)
        if not kickstart:
            raise HTTPException(status_code=404, detail="Kickstart not found")
        errors, warnings = kickstart_validation(
            kickstart.content,
            strict=strict_validation_enabled(db),
            max_bytes=settings.esxi_kickstart_max_bytes,
        )
        try:
            validate_kickstart_custom_references(db, kickstart.content)
            validate_kickstart_vault_references(db, kickstart.content)
        except ValueError as exc:
            errors.append(str(exc))
        record_audit(
            db,
            actor=identity.username,
            action="validate_esxi_kickstart",
            resource_type="esxi_kickstart",
            resource_id=str(kickstart.id),
            detail=f"errors={len(errors)} warnings={len(warnings)}",
        )
        return EsxiKickstartValidationResponse(
            valid=not errors,
            errors=errors,
            warnings=warnings,
            redacted_preview=redacted_kickstart_preview(kickstart.content),
        )

    @router.get(
        "/esxi-pxe/kickstarts/{kickstart_id}/preview",
        response_model=EsxiKickstartPreviewResponse,
        tags=["ESXi PXE"],
        operation_id="previewEsxiKickstart",
    )
    def preview_esxi_kickstart(
        kickstart_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the kickstart record addressed by this operation."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("read:esxi-pxe"))],
        db: Session = Depends(get_db),
    ) -> EsxiKickstartPreviewResponse:
        """Preview Esxi Kickstart.

        Requires the `read:esxi-pxe` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            kickstart_id: Stable identifier of the associated kickstart resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        kickstart = db.get(EsxiKickstart, kickstart_id)
        if not kickstart:
            raise HTTPException(status_code=404, detail="Kickstart not found")
        payload = kickstart_to_dict(kickstart)
        return EsxiKickstartPreviewResponse(
            id=kickstart.id,
            redacted_preview=payload["redacted_preview"],
            content_hash=kickstart.content_hash,
            drift_state=payload["drift_state"],
        )

    @router.get(
        "/esxi-pxe/kickstarts/{kickstart_id}/download",
        response_model=None,
        tags=["ESXi PXE"],
        operation_id="downloadEsxiKickstart",
    )
    def download_esxi_kickstart(
        kickstart_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the kickstart record addressed by this operation."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("write:esxi-pxe"))],
        db: Session = Depends(get_db),
    ) -> Response:
        """Download Esxi Kickstart.

        Requires the `write:esxi-pxe` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            kickstart_id: Stable identifier of the associated kickstart resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        kickstart = db.get(EsxiKickstart, kickstart_id)
        if not kickstart:
            raise HTTPException(status_code=404, detail="Kickstart not found")
        filename = (
            re.sub(r"[^A-Za-z0-9_.-]+", "-", kickstart.name).strip("-")
            or f"kickstart-{kickstart.id}"
        )
        return Response(
            kickstart.content,
            media_type="text/plain; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}.cfg"'},
        )

    @router.post(
        "/esxi-pxe/kickstarts/upload",
        response_model=EsxiKickstartResponse,
        status_code=201,
        tags=["ESXi PXE"],
        operation_id="uploadEsxiKickstart",
    )
    async def upload_esxi_kickstart(
        identity: Annotated[Identity, Depends(require_scope("write:esxi-pxe"))],
        upload_file: UploadFile = File(
            ..., description="Request value supplying upload file for this operation."
        ),
        name: str = Form(
            "",
            description="Stable name identifying the resource addressed by this operation.",
        ),
        description: str = Form(
            "", description="Request value supplying description for this operation."
        ),
        enabled: bool = Form(
            True, description="Request value supplying enabled for this operation."
        ),
        db: Session = Depends(get_db),
        settings: Settings = Depends(get_settings),
    ) -> EsxiKickstartResponse:
        """Upload Esxi Kickstart.

        Requires the `write:esxi-pxe` API scope. The operation changes saved Atlaso application state;
        any appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            identity: Authenticated identity authorizing the operation.
            upload_file: Upload file consumed by upload ESXi kickstart.
            name: Stable name identifying the resource or operation.
            description: Operator-facing purpose or context for the resource.
            enabled: Whether the associated resource or behavior is enabled.
            db: Active database session used by the operation.
            settings: Current Atlaso settings used to configure the operation.
        """
        raw = await upload_file.read()
        content = decode_kickstart_upload(
            raw, max_bytes=settings.esxi_kickstart_max_bytes
        )
        candidate_name = name or Path(upload_file.filename or "uploaded-kickstart").stem
        kickstart = EsxiKickstart(
            name=normalize_kickstart_name(candidate_name),
            description=description or None,
            content=content,
            content_hash=content_hash(content),
            rendered_content=content,
            enabled=enabled,
        )
        db.add(kickstart)
        db.flush()
        kickstart.http_path = canonical_http_path(kickstart.id, kickstart.content_hash)
        try:
            validate_kickstart_custom_references(db, kickstart.content)
            validate_kickstart_vault_references(db, kickstart.content)
            db.commit()
        except ValueError as exc:
            db.rollback()
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409, detail=f"Kickstart {candidate_name} already exists."
            ) from exc
        db.refresh(kickstart)
        record_audit(
            db,
            actor=identity.username,
            action="upload_esxi_kickstart",
            resource_type="esxi_kickstart",
            resource_id=str(kickstart.id),
            detail=f"name={kickstart.name} hash={kickstart.content_hash}",
        )
        return _kickstart_response(kickstart, identity)

    @router.get(
        "/esxi-pxe/isos",
        response_model=list[EsxiInstallerIsoResponse],
        tags=["ESXi PXE"],
        operation_id="listEsxiInstallerIsos",
    )
    def list_esxi_installer_isos(
        identity: Annotated[Identity, Depends(require_scope("read:esxi-pxe"))],
    ) -> list[EsxiInstallerIsoResponse]:
        """List Esxi Installer Isos.

        Requires the `read:esxi-pxe` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
        """
        return [EsxiInstallerIsoResponse(**row) for row in installer_iso_inventory()]

    @router.post(
        "/esxi-pxe/isos/upload",
        response_model=EsxiInstallerIsoResponse,
        status_code=201,
        tags=["ESXi PXE"],
        operation_id="uploadEsxiInstallerIso",
    )
    async def upload_esxi_installer_iso(
        identity: Annotated[Identity, Depends(require_scope("write:esxi-pxe"))],
        upload_file: UploadFile = File(
            ..., description="Request value supplying upload file for this operation."
        ),
        db: Session = Depends(get_db),
        settings: Settings = Depends(get_settings),
    ) -> EsxiInstallerIsoResponse:
        """Upload Esxi Installer Iso.

        Requires the `write:esxi-pxe` API scope. The operation changes saved Atlaso application state;
        any appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            identity: Authenticated identity authorizing the operation.
            upload_file: Upload file consumed by upload ESXi installer ISO.
            db: Active database session used by the operation.
            settings: Current Atlaso settings used to configure the operation.
        """
        try:
            iso = await store_installer_iso_upload(
                upload_file, max_bytes=settings.esxi_installer_iso_max_bytes
            )
        except ValueError as exc:
            status_code = 413 if "too large" in str(exc).lower() else 400
            raise HTTPException(status_code=status_code, detail=str(exc)) from exc
        record_audit(
            db,
            actor=identity.username,
            action="upload_esxi_installer_iso",
            resource_type="esxi_installer_iso",
            resource_id=iso["relative_path"],
            detail=f"path={iso['path']} size={iso['size_bytes']}",
        )
        return EsxiInstallerIsoResponse(**iso)

    @router.get(
        "/esxi-pxe/hosts",
        response_model=list[EsxiPxeHostResponse],
        tags=["ESXi PXE"],
        operation_id="listEsxiPxeHosts",
    )
    def list_esxi_pxe_hosts(
        identity: Annotated[Identity, Depends(require_scope("read:esxi-pxe"))],
        db: Session = Depends(get_db),
    ) -> list[EsxiPxeHostResponse]:
        """List Esxi Pxe Hosts.

        Requires the `read:esxi-pxe` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        rows = (
            db.execute(
                select(EsxiPxeHost)
                .options(selectinload(EsxiPxeHost.kickstart))
                .order_by(EsxiPxeHost.hostname)
            )
            .scalars()
            .all()
        )
        return [EsxiPxeHostResponse(**host_to_dict(row)) for row in rows]

    @router.post(
        "/esxi-pxe/hosts",
        response_model=EsxiPxeHostResponse,
        status_code=201,
        tags=["ESXi PXE"],
        operation_id="createEsxiPxeHost",
    )
    def create_esxi_pxe_host(
        payload: EsxiPxeHostCreate,
        identity: Annotated[Identity, Depends(require_scope("write:esxi-pxe"))],
        db: Session = Depends(get_db),
    ) -> EsxiPxeHostResponse:
        """Create Esxi Pxe Host.

        Requires the `write:esxi-pxe` API scope. The operation changes saved Atlaso application state;
        any appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        lock_esxi_host_reference_lifecycle(db)
        if payload.kickstart_id and not db.get(EsxiKickstart, payload.kickstart_id):
            raise HTTPException(status_code=404, detail="Kickstart not found")
        try:
            normalized_mac = normalize_host_mac(payload.mac_address)
            if not normalized_mac:
                raise ValueError("ESXi PXE host MAC address is invalid.")
            installer_iso_path = normalize_installer_iso_path(
                payload.installer_iso_path
            )
            variables_json = host_variables_json(payload.variables)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        host = EsxiPxeHost(
            hostname=payload.hostname.strip(),
            mac_address=normalized_mac,
            ip_address=payload.ip_address.strip(),
            kickstart_id=payload.kickstart_id,
            installer_iso_path=installer_iso_path,
            variables_json=variables_json,
            enabled=payload.enabled,
        )
        db.add(host)
        try:
            db.flush()
            sync_esxi_pxe_host_network_records(db, host, esxi_pxe_boot_settings(db))
            db.commit()
        except ValueError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409 if "already exists" in str(exc) else 400,
                detail=str(exc),
            ) from exc
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail=f"ESXi PXE host for {payload.mac_address} already exists.",
            ) from exc
        db.refresh(host)
        record_audit(
            db,
            actor=identity.username,
            action="update_esxi_pxe_host",
            resource_type="esxi_pxe_host",
            resource_id=str(host.id),
            detail=f"kickstart_id={host.kickstart_id} installer_iso={host.installer_iso_path}",
        )
        return EsxiPxeHostResponse(**host_to_dict(host))

    @router.put(
        "/esxi-pxe/hosts/{host_id}",
        response_model=EsxiPxeHostResponse,
        tags=["ESXi PXE"],
        operation_id="updateEsxiPxeHost",
    )
    def update_esxi_pxe_host(
        host_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the host record addressed by this operation."
            ),
        ],
        payload: EsxiPxeHostCreate,
        identity: Annotated[Identity, Depends(require_scope("write:esxi-pxe"))],
        db: Session = Depends(get_db),
    ) -> EsxiPxeHostResponse:
        """Update Esxi Pxe Host.

        Requires the `write:esxi-pxe` API scope. The operation updates saved Atlaso state and does not
        bypass the documented global Appliance Apply or service lifecycle boundary.

        Args:
            host_id: Stable identifier of the associated host resource.
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        lock_esxi_host_reference_lifecycle(db)
        host = db.get(EsxiPxeHost, host_id)
        if not host:
            raise HTTPException(status_code=404, detail="ESXi PXE host not found")
        if payload.kickstart_id and not db.get(EsxiKickstart, payload.kickstart_id):
            raise HTTPException(status_code=404, detail="Kickstart not found")
        try:
            normalized_mac = normalize_host_mac(payload.mac_address)
            if not normalized_mac:
                raise ValueError("ESXi PXE host MAC address is invalid.")
            installer_iso_path = normalize_installer_iso_path(
                payload.installer_iso_path
            )
            variables_json = host_variables_json(payload.variables)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        host.hostname = payload.hostname.strip()
        host.mac_address = normalized_mac
        host.ip_address = payload.ip_address.strip()
        host.kickstart_id = payload.kickstart_id
        host.installer_iso_path = installer_iso_path
        host.variables_json = variables_json
        host.enabled = payload.enabled
        host.updated_at = utcnow()
        db.add(host)
        try:
            db.flush()
            sync_esxi_pxe_host_network_records(db, host, esxi_pxe_boot_settings(db))
            db.commit()
        except ValueError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409 if "already exists" in str(exc) else 400,
                detail=str(exc),
            ) from exc
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail=f"ESXi PXE host for {payload.mac_address} already exists.",
            ) from exc
        db.refresh(host)
        record_audit(
            db,
            actor=identity.username,
            action="update_esxi_pxe_host",
            resource_type="esxi_pxe_host",
            resource_id=str(host.id),
            detail=f"kickstart_id={host.kickstart_id} installer_iso={host.installer_iso_path}",
        )
        return EsxiPxeHostResponse(**host_to_dict(host))

    @router.delete(
        "/esxi-pxe/hosts/{host_id}",
        response_model=EsxiPxeHostDeleteResponse,
        responses={
            403: {
                "model": ProblemDetails,
                "description": (
                    "The token lacks write:esxi-pxe, or optional discovery cleanup "
                    "was requested without write:pxe."
                ),
            },
            404: {
                "model": ProblemDetails,
                "description": "The ESXi Host Reference does not exist.",
            },
            409: {
                "model": ProblemDetails,
                "description": (
                    "Associated discovery cleanup was requested, but another ESXi Host "
                    "Reference still owns a reported MAC for that discovery."
                ),
            },
        },
        tags=["ESXi PXE"],
        operation_id="deleteEsxiPxeHost",
    )
    def delete_esxi_pxe_host(
        host_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the ESXi Host Reference to delete."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("write:esxi-pxe"))],
        remove_discovered_host: Annotated[
            bool,
            Query(
                description=(
                    "Also remove associated discovered-host inventory state. This optional "
                    "cleanup requires the write:pxe scope and fails when another Host "
                    "Reference owns the same discovery."
                )
            ),
        ] = False,
        db: Session = Depends(get_db),
    ) -> EsxiPxeHostDeleteResponse:
        """Delete one ESXi Host Reference with an explicit discovery-retention choice.

        Requires the `write:esxi-pxe` API scope. By default, deletion retains
        associated discovered-host inventory so it can be promoted again. Setting
        `remove_discovered_host=true` additionally requires `write:pxe` and removes
        exclusively associated commands, sessions, reports, and discovered-host rows
        in the same transaction. Cleanup returns 409 before mutation if another Host
        Reference owns any reported MAC. Saved desired state changes immediately;
        generated PXE state changes only through global Appliance Apply.

        Args:
            host_id: Stable identifier of the ESXi Host Reference.
            identity: Authenticated identity authorizing the operation.
            remove_discovered_host: Whether to remove exclusively associated inventory.
            db: Active database session used by the operation.

        Returns:
            Deletion confirmation and retained-inventory removal counts.

        Raises:
            HTTPException: If authorization, lookup, cleanup, or reconciliation fails.
        """
        if remove_discovered_host and not identity.can("write:pxe"):
            raise HTTPException(
                status_code=403,
                detail="Missing required scope: write:pxe",
            )
        lock_esxi_host_reference_lifecycle(db)
        host = db.get(EsxiPxeHost, host_id)
        if not host:
            raise HTTPException(status_code=404, detail="ESXi PXE host not found")
        hostname = host.hostname
        removal_counts = {
            "discovered_hosts_removed": 0,
            "commands": 0,
            "sessions": 0,
            "reports": 0,
        }
        try:
            if remove_discovered_host:
                removal_counts = remove_esxi_host_discovery_state(db, host)
            host.ip_address = ""
            sync_esxi_pxe_host_network_records(db, host, esxi_pxe_boot_settings(db))
            db.delete(host)
        except ValueError as exc:
            db.rollback()
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        record_audit(
            db,
            actor=identity.username,
            action="delete_esxi_pxe_host",
            resource_type="esxi_pxe_host",
            resource_id=str(host_id),
            detail=(
                f"hostname={hostname}; discovered_hosts_removed={removal_counts['discovered_hosts_removed']}; "
                f"reports={removal_counts['reports']}; sessions={removal_counts['sessions']}; "
                f"commands={removal_counts['commands']}"
            ),
        )
        return EsxiPxeHostDeleteResponse(deleted=True, **removal_counts)

    return NetworkBootApiRouter(
        router=router,
        endpoints={
            "_kickstart_response": _kickstart_response,
            "_assign_kickstart_payload": _assign_kickstart_payload,
            "list_esxi_custom_variables": list_esxi_custom_variables,
            "create_esxi_custom_variable": create_esxi_custom_variable,
            "update_esxi_custom_variable": update_esxi_custom_variable,
            "delete_esxi_custom_variable": delete_esxi_custom_variable,
            "list_esxi_kickstarts": list_esxi_kickstarts,
            "create_esxi_kickstart": create_esxi_kickstart,
            "get_esxi_kickstart": get_esxi_kickstart,
            "update_esxi_kickstart": update_esxi_kickstart,
            "delete_esxi_kickstart": delete_esxi_kickstart,
            "duplicate_esxi_kickstart": duplicate_esxi_kickstart,
            "validate_esxi_kickstart": validate_esxi_kickstart,
            "preview_esxi_kickstart": preview_esxi_kickstart,
            "download_esxi_kickstart": download_esxi_kickstart,
            "upload_esxi_kickstart": upload_esxi_kickstart,
            "list_esxi_installer_isos": list_esxi_installer_isos,
            "upload_esxi_installer_iso": upload_esxi_installer_iso,
            "list_esxi_pxe_hosts": list_esxi_pxe_hosts,
            "create_esxi_pxe_host": create_esxi_pxe_host,
            "update_esxi_pxe_host": update_esxi_pxe_host,
            "delete_esxi_pxe_host": delete_esxi_pxe_host,
        },
    )
