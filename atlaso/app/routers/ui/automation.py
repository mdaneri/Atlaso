"""Own Automation management UI transport handlers."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from atlaso.app.audit import record_audit
from atlaso.app.database import get_db
from atlaso.app.models import (
    AutomationScript,
    AutomationScriptRevision,
    Job,
    JobStatus,
    Schedule,
    Vault,
    VcfDepotDownloadProfile,
    utcnow,
)
from atlaso.app.security import Identity, require_session_identity
from atlaso.app.services.appliance_update import selected_update_streams
from atlaso.app.services.automation import (
    MAX_SCRIPT_CONTENT_BYTES,
    MAX_SCRIPT_TIMEOUT_SECONDS,
    SCRIPT_INTERPRETERS,
    enabled_script_revision,
    enqueue_schedule_now,
    next_schedule_run,
    parse_script_arguments,
    validate_schedule_values,
)
from atlaso.app.services.vaults import vault_scope_identity
from atlaso.app.ui_routes import MANAGEMENT_UI_ROOT, management_ui_path

Endpoint = Callable[..., Any]


@dataclass(frozen=True)
class AutomationUiDependencies:
    """Provide facade-owned helpers without importing the compatibility facade."""

    require_management_ui_request: Endpoint
    automation_context: Endpoint
    render: Endpoint
    require_admin_identity: Endpoint
    verify_csrf: Endpoint
    vcf_depot_download_preflight: Endpoint
    vcf_offline_depot_page: Endpoint
    create_script_revision: Endpoint
    normalize_script_content: Endpoint


@dataclass(frozen=True)
class AutomationUiRouter:
    """Return the configured router and compatibility exports."""

    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_router(dependencies: AutomationUiDependencies) -> AutomationUiRouter:
    """Build the Automation management UI router."""
    router = APIRouter(
        prefix=MANAGEMENT_UI_ROOT,
        dependencies=[Depends(dependencies.require_management_ui_request)],
    )
    automation_context = dependencies.automation_context
    render = dependencies.render
    require_admin_identity = dependencies.require_admin_identity
    verify_csrf = dependencies.verify_csrf
    vcf_depot_download_preflight = dependencies.vcf_depot_download_preflight
    vcf_offline_depot_page = dependencies.vcf_offline_depot_page
    create_script_revision = dependencies.create_script_revision
    normalize_script_content = dependencies.normalize_script_content

    @router.get("/automation", response_class=HTMLResponse, response_model=None)
    def automation_page(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the automation page endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        require_admin_identity(identity)
        return render(
            request, "automation.html", {"identity": identity, **automation_context(db)}
        )

    def _automation_render_error(
        request: Request,
        identity: Identity,
        db: Session,
        message: str,
        *,
        status_code: int = 422,
    ) -> HTMLResponse:
        """Return automation render error.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.
            message: Public-safe status or error message.
            status_code: HTTP status code for the response.
        """
        return render(
            request,
            "automation.html",
            {
                "identity": identity,
                **automation_context(db),
                "automation_error": message,
            },
            status_code=status_code,
        )

    def _automation_script_validation_message(
        interpreter: str, content: str, timeout_seconds: int
    ) -> str | None:
        """Return automation script validation message.

        Args:
            interpreter: Interpreter supplied by the caller.
            content: Document or file content to process.
            timeout_seconds: Maximum time to wait, in seconds.
        """
        if interpreter not in SCRIPT_INTERPRETERS:
            return "Interpreter must be bash, python, or powershell."
        first_line = (
            content.removeprefix("\ufeff")
            .replace("\r\n", "\n")
            .replace("\r", "\n")
            .split("\n", 1)[0]
            .strip()
        )
        try:
            normalized_content = normalize_script_content(content, interpreter)
        except ValueError:
            if interpreter == "bash" and first_line.startswith("!/"):
                return "A Bash shebang must start with #!; add the missing # or remove the shebang line."
            return "Managed script source is invalid. Review the interpreter and source, then try again."
        if not normalized_content.strip():
            return "Script content is required."
        if len(normalized_content.encode("utf-8")) > MAX_SCRIPT_CONTENT_BYTES:
            return "Script content must be 1 MiB or smaller."
        if timeout_seconds < 1 or timeout_seconds > MAX_SCRIPT_TIMEOUT_SECONDS:
            return "Script timeout must be between 1 second and 24 hours."
        return None

    def _automation_task_config(
        db: Session,
        *,
        task_type: str,
        selected_streams: list[str],
        vcf_profile_id: int | None,
        revision_id: int | None,
        vault_id: int | None,
        script_arguments: str,
    ) -> tuple[dict[str, Any], str]:
        """Return automation task config.

        Args:
            db: Active database session.
            task_type: Task type supplied by the caller.
            selected_streams: Update streams selected for the job.
            vcf_profile_id: Identifier of the vcf profile.
            revision_id: Identifier of the revision.
            vault_id: Identifier of the vault.
            script_arguments: Script arguments supplied by the caller.
        """
        if task_type in {"appliance_update_check", "appliance_update_install"}:
            return {"selected_streams": selected_update_streams(selected_streams)}, ""
        if task_type == "vcf_depot_download":
            profile = db.get(VcfDepotDownloadProfile, vcf_profile_id or 0)
            if profile is None or not profile.enabled:
                return {}, "Choose an enabled VCF Offline Depot download profile."
            return {"profile_id": profile.id}, ""
        if task_type == "managed_script":
            revision = enabled_script_revision(db, revision_id or 0)
            if revision is None:
                return {}, "Choose an enabled managed script revision."
            try:
                arguments = parse_script_arguments(
                    script_arguments, revision.interpreter
                )
            except ValueError as exc:
                return {}, str(exc)
            selected_vault_id = int(vault_id or 0)
            if selected_vault_id and db.get(Vault, selected_vault_id) is None:
                return {}, "Choose an available vault or run without vault access."
            return {
                "revision_id": revision.id,
                "arguments": arguments,
                **({"vault_id": selected_vault_id} if selected_vault_id else {}),
            }, ""
        return {}, ""

    class AutomationScheduleInputError(ValueError):
        """Report an operator-actionable schedule definition error."""

        def __init__(self, message: str, *, status_code: int = 422) -> None:
            """Initialize the schedule definition error.

            Args:
                message: Operator-facing validation detail.
                status_code: HTTP status appropriate for the validation failure.
            """
            self.public_detail = message
            self.status_code = status_code
            super().__init__(message)

    def create_automation_schedule_record(
        db: Session,
        *,
        name: str,
        task_type: str,
        selected_streams: list[str],
        vcf_profile_id: int | None,
        revision_id: int | None,
        vault_id: int | None,
        script_arguments: str,
        schedule_kind: str,
        cron_expression: str,
        run_once_at: str,
        timezone_name: str,
        enabled: bool,
        actor: str,
    ) -> Schedule:
        """Validate and persist one schedule for generic and contextual callers.

        Args:
            db: Active database session.
            name: Operator-visible schedule name.
            task_type: Allowlisted Automation task type.
            selected_streams: Appliance Update streams selected by the operator.
            vcf_profile_id: Server-validated VCF Offline Depot profile identifier.
            revision_id: Managed script revision identifier.
            vault_id: Optional scoped vault identifier.
            script_arguments: Literal managed-script arguments.
            schedule_kind: Cron or one-time schedule kind.
            cron_expression: Five-field cron expression.
            run_once_at: Local one-time value interpreted in the selected timezone.
            timezone_name: IANA timezone name.
            enabled: Whether the schedule is immediately eligible to run.
            actor: Authenticated creator identity.

        Returns:
            The persisted schedule.

        Raises:
            AutomationScheduleInputError: If validation or persistence fails.
        """
        parsed_once: datetime | None = None
        try:
            if run_once_at.strip():
                parsed_once = datetime.fromisoformat(run_once_at.strip())
                if parsed_once.tzinfo is None:
                    parsed_once = parsed_once.replace(tzinfo=ZoneInfo(timezone_name))
                parsed_once = parsed_once.astimezone(timezone.utc)
        except (ValueError, ZoneInfoNotFoundError) as exc:
            raise AutomationScheduleInputError(
                "One-time run date or timezone is invalid."
            ) from exc
        task_config, config_error = _automation_task_config(
            db,
            task_type=task_type,
            selected_streams=selected_streams,
            vcf_profile_id=vcf_profile_id,
            revision_id=revision_id,
            vault_id=vault_id,
            script_arguments=script_arguments,
        )
        if config_error:
            raise AutomationScheduleInputError(config_error)
        task_config_json = json.dumps(task_config, sort_keys=True)
        errors = validate_schedule_values(
            task_type=task_type,
            task_config_json=task_config_json,
            schedule_kind=schedule_kind,
            cron_expression=cron_expression,
            run_once_at=parsed_once,
            timezone_name=timezone_name,
        )
        if not name.strip():
            errors.insert(0, "Schedule name is required.")
        if errors:
            raise AutomationScheduleInputError(" ".join(errors))
        schedule = Schedule(
            name=name.strip(),
            task_type=task_type,
            task_config_json=task_config_json,
            schedule_kind=schedule_kind,
            cron_expression=cron_expression.strip() if schedule_kind == "cron" else "",
            run_once_at=parsed_once if schedule_kind == "once" else None,
            timezone_name=timezone_name,
            enabled=enabled,
            created_by=actor,
        )
        if schedule.enabled:
            try:
                schedule.next_run_at = next_schedule_run(schedule, after=utcnow())
            except ValueError as exc:
                raise AutomationScheduleInputError(
                    "The schedule does not have a valid future run time."
                ) from exc
            if schedule.next_run_at is None:
                raise AutomationScheduleInputError(
                    "The enabled schedule does not have a future run time."
                )
        db.add(schedule)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise AutomationScheduleInputError(
                "A schedule with this name already exists.",
                status_code=409,
            ) from exc
        return schedule

    @router.post("/automation/schedules", response_model=None)
    def create_automation_schedule(
        request: Request,
        name: str = Form(...),
        task_type: str = Form(...),
        selected_streams: list[str] = Form(default=[]),
        vcf_profile_id: int | None = Form(None),
        revision_id: int | None = Form(None),
        vault_id: int | None = Form(None),
        script_arguments: str = Form(""),
        schedule_kind: str = Form("cron"),
        cron_expression: str = Form("0 2 * * *"),
        run_once_at: str = Form(""),
        timezone_name: str = Form("UTC"),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the create automation schedule endpoint.

        Args:
            request: Incoming HTTP request.
            name: Name of the target object.
            task_type: Task type supplied by the caller.
            selected_streams: Update streams selected for the job.
            vcf_profile_id: Identifier of the vcf profile.
            revision_id: Identifier of the revision.
            vault_id: Identifier of the vault.
            script_arguments: Script arguments supplied by the caller.
            schedule_kind: Schedule kind supplied by the caller.
            cron_expression: Cron expression supplied by the caller.
            run_once_at: Run once at supplied by the caller.
            timezone_name: Timezone name supplied by the caller.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        require_admin_identity(identity)
        try:
            schedule = create_automation_schedule_record(
                db,
                name=name,
                task_type=task_type,
                selected_streams=selected_streams,
                vcf_profile_id=vcf_profile_id,
                revision_id=revision_id,
                vault_id=vault_id,
                script_arguments=script_arguments,
                schedule_kind=schedule_kind,
                cron_expression=cron_expression,
                run_once_at=run_once_at,
                timezone_name=timezone_name,
                enabled=enabled == "on",
                actor=identity.username,
            )
        except AutomationScheduleInputError as exc:
            return _automation_render_error(
                request, identity, db, exc.public_detail, status_code=exc.status_code
            )
        record_audit(
            db,
            actor=identity.username,
            action="create_automation_schedule",
            resource_type="schedule",
            resource_id=str(schedule.id),
            detail=f"task_type={task_type}",
        )
        return RedirectResponse("/automation#schedules", status_code=303)

    @router.post(
        "/vcf-offline-depot/profiles/{profile_id}/schedules", response_model=None
    )
    def create_contextual_vcf_depot_schedule(
        profile_id: int,
        request: Request,
        name: str = Form(...),
        schedule_kind: str = Form("cron"),
        cron_expression: str = Form("0 2 * * *"),
        run_once_at: str = Form(""),
        timezone_name: str = Form("UTC"),
        enabled: str | None = Form(None),
        task_type: str | None = Form(None),
        vcf_profile_id: int | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse | RedirectResponse:
        """Create a server-bound depot download schedule from its selected profile.

        Args:
            profile_id: Server-owned profile selected by the depot row action.
            request: Incoming HTTP request.
            name: Operator-visible schedule name.
            schedule_kind: Cron or one-time schedule kind.
            cron_expression: Five-field cron expression.
            run_once_at: Local one-time date and time.
            timezone_name: IANA timezone used to interpret the timing fields.
            enabled: Whether the schedule should be immediately eligible.
            task_type: Optional tamper-detection value; the server fixes the type.
            vcf_profile_id: Optional tamper-detection value; the path fixes the profile.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The created schedule metadata for in-page feedback.
        """
        verify_csrf(request, csrf)
        require_admin_identity(identity)
        wants_html = "text/html" in request.headers.get("accept", "").lower()
        if task_type is not None and task_type != "vcf_depot_download":
            return JSONResponse(
                {
                    "detail": "The contextual depot wizard can create only VCF Offline Depot download schedules."
                },
                status_code=422,
            )
        if vcf_profile_id is not None and vcf_profile_id != profile_id:
            return JSONResponse(
                {
                    "detail": "The submitted profile does not match the depot row that opened this wizard."
                },
                status_code=422,
            )
        try:
            schedule = create_automation_schedule_record(
                db,
                name=name,
                task_type="vcf_depot_download",
                selected_streams=[],
                vcf_profile_id=profile_id,
                revision_id=None,
                vault_id=None,
                script_arguments="",
                schedule_kind=schedule_kind,
                cron_expression=cron_expression,
                run_once_at=run_once_at,
                timezone_name=timezone_name,
                enabled=enabled == "on",
                actor=identity.username,
            )
        except AutomationScheduleInputError as exc:
            if wants_html:
                request.state.vcf_schedule_error = exc.public_detail
                request.state.vcf_schedule_form = {
                    "name": name,
                    "schedule_kind": schedule_kind,
                    "cron_expression": cron_expression,
                    "run_once_at": run_once_at,
                    "timezone_name": timezone_name,
                    "enabled": enabled == "on",
                }
                response = vcf_offline_depot_page(
                    request,
                    schedule_profile_id=profile_id,
                    schedule_invalid=True,
                    identity=identity,
                    db=db,
                )
                response.status_code = exc.status_code
                return response
            return JSONResponse(
                {"detail": exc.public_detail}, status_code=exc.status_code
            )
        record_audit(
            db,
            actor=identity.username,
            action="create_automation_schedule",
            resource_type="schedule",
            resource_id=str(schedule.id),
            detail=f"task_type=vcf_depot_download; profile_id={profile_id}; source=vcf_offline_depot",
        )
        if wants_html:
            return RedirectResponse(
                management_ui_path("/vcf-offline-depot#vcf-depot-profiles-panel"),
                status_code=303,
            )
        return JSONResponse(
            {
                "status": "created",
                "schedule_id": schedule.id,
                "schedule_name": schedule.name,
                "profile_id": profile_id,
                "enabled": schedule.enabled,
                "automation_url": "/ui/management/automation#schedules",
            },
            status_code=201,
        )

    @router.post("/automation/schedules/{schedule_id}/edit", response_model=None)
    def edit_automation_schedule(
        schedule_id: int,
        request: Request,
        name: str = Form(...),
        task_type: str = Form(...),
        selected_streams: list[str] = Form(default=[]),
        vcf_profile_id: int | None = Form(None),
        revision_id: int | None = Form(None),
        vault_id: int | None = Form(None),
        script_arguments: str = Form(""),
        schedule_kind: str = Form("cron"),
        cron_expression: str = Form("0 2 * * *"),
        run_once_at: str = Form(""),
        timezone_name: str = Form("UTC"),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the edit automation schedule endpoint.

        Args:
            schedule_id: Identifier of the schedule.
            request: Incoming HTTP request.
            name: Name of the target object.
            task_type: Task type supplied by the caller.
            selected_streams: Update streams selected for the job.
            vcf_profile_id: Identifier of the vcf profile.
            revision_id: Identifier of the revision.
            vault_id: Identifier of the vault.
            script_arguments: Script arguments supplied by the caller.
            schedule_kind: Schedule kind supplied by the caller.
            cron_expression: Cron expression supplied by the caller.
            run_once_at: Run once at supplied by the caller.
            timezone_name: Timezone name supplied by the caller.
            enabled: Whether the requested behavior is enabled.
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
        schedule = db.get(Schedule, schedule_id)
        if schedule is None:
            raise HTTPException(status_code=404, detail="Schedule not found.")
        parsed_once: datetime | None = None
        try:
            if run_once_at.strip():
                parsed_once = datetime.fromisoformat(run_once_at.strip())
                if parsed_once.tzinfo is None:
                    parsed_once = parsed_once.replace(tzinfo=ZoneInfo(timezone_name))
                parsed_once = parsed_once.astimezone(timezone.utc)
        except ValueError, ZoneInfoNotFoundError:
            return _automation_render_error(
                request, identity, db, "One-time run date or timezone is invalid."
            )
        task_config, config_error = _automation_task_config(
            db,
            task_type=task_type,
            selected_streams=selected_streams,
            vcf_profile_id=vcf_profile_id,
            revision_id=revision_id,
            vault_id=vault_id,
            script_arguments=script_arguments,
        )
        if config_error:
            return _automation_render_error(request, identity, db, config_error)
        task_config_json = json.dumps(task_config, sort_keys=True)
        errors = validate_schedule_values(
            task_type=task_type,
            task_config_json=task_config_json,
            schedule_kind=schedule_kind,
            cron_expression=cron_expression,
            run_once_at=parsed_once,
            timezone_name=timezone_name,
        )
        if not name.strip():
            errors.insert(0, "Schedule name is required.")
        if errors:
            return _automation_render_error(request, identity, db, " ".join(errors))
        schedule.name = name.strip()
        schedule.task_type = task_type
        schedule.task_config_json = task_config_json
        schedule.schedule_kind = schedule_kind
        schedule.cron_expression = (
            cron_expression.strip() if schedule_kind == "cron" else ""
        )
        schedule.run_once_at = parsed_once if schedule_kind == "once" else None
        schedule.timezone_name = timezone_name
        schedule.enabled = enabled == "on"
        schedule.updated_at = utcnow()
        try:
            schedule.next_run_at = (
                next_schedule_run(schedule, after=utcnow())
                if schedule.enabled
                else None
            )
        except ValueError as exc:
            db.rollback()
            return _automation_render_error(request, identity, db, str(exc))
        if schedule.enabled and schedule.next_run_at is None:
            db.rollback()
            return _automation_render_error(
                request,
                identity,
                db,
                "The enabled schedule does not have a future run time.",
            )
        db.add(schedule)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return _automation_render_error(
                request,
                identity,
                db,
                "A schedule with this name already exists.",
                status_code=409,
            )
        record_audit(
            db,
            actor=identity.username,
            action="update_automation_schedule",
            resource_type="schedule",
            resource_id=str(schedule.id),
            detail=f"task_type={task_type}",
        )
        return RedirectResponse("/automation#schedules", status_code=303)

    @router.post("/automation/schedules/{schedule_id}/run", response_model=None)
    def run_automation_schedule_now(
        schedule_id: int,
        request: Request,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the run automation schedule now endpoint.

        Args:
            schedule_id: Identifier of the schedule.
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
        schedule = db.get(Schedule, schedule_id)
        if schedule is None:
            raise HTTPException(status_code=404, detail="Schedule not found.")
        try:
            config = json.loads(schedule.task_config_json or "{}")
        except json.JSONDecodeError:
            return _automation_render_error(
                request, identity, db, "The schedule task configuration is invalid."
            )
        if (
            schedule.task_type == "managed_script"
            and enabled_script_revision(db, int(config.get("revision_id") or 0)) is None
        ):
            return _automation_render_error(
                request,
                identity,
                db,
                "Enable the scheduled script revision before running it.",
            )
        if schedule.task_type == "vcf_depot_download":
            profile = db.get(
                VcfDepotDownloadProfile, int(config.get("profile_id") or 0)
            )
            if profile is None or not profile.enabled:
                return _automation_render_error(
                    request,
                    identity,
                    db,
                    "Enable the scheduled VCF Offline Depot profile before running it.",
                )
            try:
                vcf_depot_download_preflight(db, profile)
            except ValueError as exc:
                return _automation_render_error(
                    request, identity, db, str(exc), status_code=409
                )
        try:
            job = enqueue_schedule_now(db, schedule=schedule, actor=identity.username)
        except (KeyError, ValueError) as exc:
            db.rollback()
            return _automation_render_error(
                request, identity, db, str(exc), status_code=409
            )
        return RedirectResponse(f"/tasks#{job.id}", status_code=303)

    @router.post("/automation/schedules/{schedule_id}/toggle", response_model=None)
    def toggle_automation_schedule(
        schedule_id: int,
        request: Request,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Handle the toggle automation schedule endpoint.

        Args:
            schedule_id: Identifier of the schedule.
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
        schedule = db.get(Schedule, schedule_id)
        if schedule is None:
            raise HTTPException(status_code=404, detail="Schedule not found.")
        if not schedule.enabled and schedule.task_type == "vcf_depot_download":
            try:
                config = json.loads(schedule.task_config_json or "{}")
            except json.JSONDecodeError:
                return _automation_render_error(
                    request, identity, db, "The schedule task configuration is invalid."
                )
            profile = db.get(
                VcfDepotDownloadProfile, int(config.get("profile_id") or 0)
            )
            if profile is None or not profile.enabled:
                return _automation_render_error(
                    request,
                    identity,
                    db,
                    "Enable the VCF Offline Depot profile before enabling its schedule.",
                    status_code=409,
                )
        schedule.enabled = not schedule.enabled
        try:
            schedule.next_run_at = (
                next_schedule_run(schedule, after=utcnow())
                if schedule.enabled
                else None
            )
        except ValueError as exc:
            schedule.enabled = False
            return _automation_render_error(request, identity, db, str(exc))
        if schedule.enabled and schedule.next_run_at is None:
            schedule.enabled = False
            return _automation_render_error(
                request, identity, db, "The schedule does not have a future run time."
            )
        schedule.updated_at = utcnow()
        db.add(schedule)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="enable_automation_schedule"
            if schedule.enabled
            else "disable_automation_schedule",
            resource_type="schedule",
            resource_id=str(schedule.id),
        )
        return RedirectResponse("/automation#schedules", status_code=303)

    @router.post("/automation/schedules/{schedule_id}/delete", response_model=None)
    def delete_automation_schedule(
        schedule_id: int,
        request: Request,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Handle the delete automation schedule endpoint.

        Args:
            schedule_id: Identifier of the schedule.
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
        schedule = db.get(Schedule, schedule_id)
        if schedule is None:
            raise HTTPException(status_code=404, detail="Schedule not found.")
        name = schedule.name
        for job in (
            db.execute(select(Job).where(Job.schedule_id == schedule.id))
            .scalars()
            .all()
        ):
            job.schedule_id = None
            db.add(job)
        db.delete(schedule)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_automation_schedule",
            resource_type="schedule",
            resource_id=str(schedule_id),
            detail=f"name={name}",
        )
        return RedirectResponse("/automation#schedules", status_code=303)

    @router.post("/automation/scripts", response_model=None)
    def create_automation_script_from_ui(
        request: Request,
        name: str = Form(...),
        description: str = Form(""),
        interpreter: str = Form("powershell"),
        content: str = Form(...),
        timeout_seconds: int = Form(3600),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the create automation script from ui endpoint.

        Args:
            request: Incoming HTTP request.
            name: Name of the target object.
            description: Human-readable description of the resource.
            interpreter: Interpreter supplied by the caller.
            content: Document or file content to process.
            timeout_seconds: Maximum time to wait, in seconds.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        require_admin_identity(identity)
        wizard_request = request.headers.get("X-Atlaso-Wizard") == "1"
        if not name.strip():
            if wizard_request:
                return JSONResponse(
                    {
                        "status": "error",
                        "detail": "Script name is required.",
                        "errors": ["Script name is required."],
                    },
                    status_code=422,
                )
            return _automation_render_error(
                request, identity, db, "Script name is required."
            )
        validation_message = _automation_script_validation_message(
            interpreter, content, timeout_seconds
        )
        if validation_message:
            if wizard_request:
                return JSONResponse(
                    {
                        "status": "error",
                        "detail": validation_message,
                        "errors": [validation_message],
                    },
                    status_code=422,
                )
            return _automation_render_error(request, identity, db, validation_message)
        script = AutomationScript(
            name=name.strip(),
            description=description.strip(),
            created_by=identity.username,
        )
        db.add(script)
        try:
            db.flush()
            create_script_revision(
                db,
                script=script,
                interpreter=interpreter,
                content=content,
                timeout_seconds=timeout_seconds,
                actor=identity.username,
            )
            db.commit()
        except IntegrityError:
            db.rollback()
            message = "A script with this name already exists."
            if wizard_request:
                return JSONResponse(
                    {"status": "error", "detail": message, "errors": [message]},
                    status_code=409,
                )
            return _automation_render_error(
                request, identity, db, message, status_code=409
            )
        except ValueError:
            db.rollback()
            message = "Managed script validation failed."
            if wizard_request:
                return JSONResponse(
                    {"status": "error", "detail": message, "errors": [message]},
                    status_code=422,
                )
            return _automation_render_error(request, identity, db, message)
        record_audit(
            db,
            actor=identity.username,
            action="create_automation_script",
            resource_type="automation_script",
            resource_id=str(script.id),
        )
        if wizard_request:
            return JSONResponse({"status": "saved", "script_id": script.id})
        return RedirectResponse("/automation#scripts", status_code=303)

    @router.post("/automation/scripts/{script_id}/revisions", response_model=None)
    def create_automation_script_revision_from_ui(
        script_id: int,
        request: Request,
        interpreter: str = Form("powershell"),
        content: str = Form(...),
        timeout_seconds: int = Form(3600),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the create automation script revision from ui endpoint.

        Args:
            script_id: Identifier of the script.
            request: Incoming HTTP request.
            interpreter: Interpreter supplied by the caller.
            content: Document or file content to process.
            timeout_seconds: Maximum time to wait, in seconds.
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
        script = db.get(AutomationScript, script_id)
        if script is None:
            raise HTTPException(status_code=404, detail="Managed script not found.")
        validation_message = _automation_script_validation_message(
            interpreter, content, timeout_seconds
        )
        if validation_message:
            return _automation_render_error(request, identity, db, validation_message)
        try:
            revision = create_script_revision(
                db,
                script=script,
                interpreter=interpreter,
                content=content,
                timeout_seconds=timeout_seconds,
                actor=identity.username,
            )
            script.updated_at = utcnow()
            db.add(script)
            db.commit()
        except ValueError:
            db.rollback()
            return _automation_render_error(
                request, identity, db, "Managed script validation failed."
            )
        record_audit(
            db,
            actor=identity.username,
            action="create_automation_script_revision",
            resource_type="automation_script_revision",
            resource_id=str(revision.id),
            detail=f"script={script.name}; revision={revision.revision}",
        )
        return RedirectResponse("/automation#scripts", status_code=303)

    @router.post("/automation/scripts/{script_id}/edit", response_model=None)
    def edit_automation_script_from_ui(
        script_id: int,
        request: Request,
        name: str = Form(...),
        description: str = Form(""),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the edit automation script from ui endpoint.

        Args:
            script_id: Identifier of the script.
            request: Incoming HTTP request.
            name: Name of the target object.
            description: Human-readable description of the resource.
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
        script = db.get(AutomationScript, script_id)
        if script is None:
            raise HTTPException(status_code=404, detail="Managed script not found.")
        normalized_name = name.strip()
        if not normalized_name:
            return _automation_render_error(
                request, identity, db, "Script name is required."
            )
        script.name = normalized_name
        script.description = description.strip()
        script.updated_at = utcnow()
        db.add(script)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return _automation_render_error(
                request,
                identity,
                db,
                "A script with this name already exists.",
                status_code=409,
            )
        record_audit(
            db,
            actor=identity.username,
            action="edit_automation_script",
            resource_type="automation_script",
            resource_id=str(script.id),
        )
        return RedirectResponse("/automation#scripts", status_code=303)

    @router.post("/automation/scripts/{script_id}/delete", response_model=None)
    def delete_automation_script_from_ui(
        script_id: int,
        request: Request,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the delete automation script from ui endpoint.

        Args:
            script_id: Identifier of the script.
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
        script = db.execute(
            select(AutomationScript)
            .options(selectinload(AutomationScript.revisions))
            .where(AutomationScript.id == script_id)
        ).scalar_one_or_none()
        if script is None:
            raise HTTPException(status_code=404, detail="Managed script not found.")
        revision_ids = {revision.id for revision in script.revisions}
        dependent_schedules: list[str] = []
        for schedule in (
            db.execute(select(Schedule).where(Schedule.task_type == "managed_script"))
            .scalars()
            .all()
        ):
            try:
                revision_id = json.loads(schedule.task_config_json or "{}").get(
                    "revision_id"
                )
            except AttributeError, json.JSONDecodeError:
                continue
            if revision_id in revision_ids:
                dependent_schedules.append(schedule.name)
        if dependent_schedules:
            return _automation_render_error(
                request,
                identity,
                db,
                f"Delete or reassign schedules using this script first: {', '.join(dependent_schedules)}.",
                status_code=409,
            )
        name = script.name
        db.delete(script)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_automation_script",
            resource_type="automation_script",
            resource_id=str(script_id),
            detail=f"name={name}",
        )
        return RedirectResponse("/automation#scripts", status_code=303)

    @router.post(
        "/automation/scripts/revisions/{revision_id}/toggle", response_model=None
    )
    def toggle_automation_script_revision(
        revision_id: int,
        request: Request,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Handle the toggle automation script revision endpoint.

        Args:
            revision_id: Identifier of the revision.
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
        revision = db.get(AutomationScriptRevision, revision_id)
        if revision is None:
            raise HTTPException(
                status_code=404, detail="Managed script revision not found."
            )
        if revision.enabled:
            dependent_schedules: list[str] = []
            for schedule in (
                db.execute(
                    select(Schedule).where(
                        Schedule.task_type == "managed_script",
                        Schedule.enabled.is_(True),
                    )
                )
                .scalars()
                .all()
            ):
                try:
                    configured_revision_id = json.loads(
                        schedule.task_config_json or "{}"
                    ).get("revision_id")
                except AttributeError, json.JSONDecodeError:
                    continue
                if configured_revision_id == revision.id:
                    dependent_schedules.append(schedule.name)
            if dependent_schedules:
                return _automation_render_error(
                    request,
                    identity,
                    db,
                    f"Disable or edit schedules using this revision first: {', '.join(dependent_schedules)}.",
                    status_code=409,
                )
        revision.enabled = not revision.enabled
        db.add(revision)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="enable_automation_script_revision"
            if revision.enabled
            else "disable_automation_script_revision",
            resource_type="automation_script_revision",
            resource_id=str(revision.id),
            detail=f"sha256={revision.content_sha256}",
        )
        return RedirectResponse("/automation#scripts", status_code=303)

    @router.post("/automation/scripts/revisions/{revision_id}/run", response_model=None)
    def run_automation_script_revision(
        revision_id: int,
        request: Request,
        csrf: str = Form(...),
        script_arguments: str = Form(""),
        vault_id: int | None = Form(None),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Handle the run automation script revision endpoint.

        Args:
            revision_id: Identifier of the revision.
            request: Incoming HTTP request.
            csrf: Validated CSRF token authorizing the request.
            script_arguments: Script arguments supplied by the caller.
            vault_id: Identifier of the vault.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        require_admin_identity(identity)
        revision = db.get(AutomationScriptRevision, revision_id)
        if revision is None or not revision.enabled:
            raise HTTPException(
                status_code=400,
                detail="Enable the managed script revision before running it.",
            )
        try:
            arguments = parse_script_arguments(script_arguments, revision.interpreter)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        selected_vault_id = int(vault_id or 0)
        selected_vault = db.get(Vault, selected_vault_id) if selected_vault_id else None
        if selected_vault_id and selected_vault is None:
            raise HTTPException(
                status_code=400,
                detail="Choose an available vault or run without vault access.",
            )
        task_config = {"arguments": arguments, "revision_id": revision.id}
        if selected_vault is not None:
            task_config["vault_id"] = selected_vault.id
            task_config["vault_scope"] = vault_scope_identity(selected_vault)
        job = Job(
            id=f"job_{uuid4().hex[:12]}",
            type="managed-script",
            status=JobStatus.PENDING.value,
            created_by=identity.username,
            progress_percent=0,
            trigger="manual",
            task_config_json=json.dumps(task_config, sort_keys=True),
            result=json.dumps(
                {"status": "pending", "revision_id": revision.id}, indent=2
            ),
        )
        db.add(job)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="queue_managed_script",
            resource_type="job",
            resource_id=job.id,
            detail=f"revision_id={revision.id}; sha256={revision.content_sha256}; arguments_count={len(arguments)}",
        )
        return RedirectResponse("/tasks", status_code=303)

    return AutomationUiRouter(
        router=router,
        endpoints={
            "automation_page": automation_page,
            "_automation_render_error": _automation_render_error,
            "_automation_script_validation_message": _automation_script_validation_message,
            "_automation_task_config": _automation_task_config,
            "AutomationScheduleInputError": AutomationScheduleInputError,
            "create_automation_schedule_record": create_automation_schedule_record,
            "create_automation_schedule": create_automation_schedule,
            "create_contextual_vcf_depot_schedule": create_contextual_vcf_depot_schedule,
            "edit_automation_schedule": edit_automation_schedule,
            "run_automation_schedule_now": run_automation_schedule_now,
            "toggle_automation_schedule": toggle_automation_schedule,
            "delete_automation_schedule": delete_automation_schedule,
            "create_automation_script_from_ui": create_automation_script_from_ui,
            "create_automation_script_revision_from_ui": create_automation_script_revision_from_ui,
            "edit_automation_script_from_ui": edit_automation_script_from_ui,
            "delete_automation_script_from_ui": delete_automation_script_from_ui,
            "toggle_automation_script_revision": toggle_automation_script_revision,
            "run_automation_script_revision": run_automation_script_revision,
        },
    )
