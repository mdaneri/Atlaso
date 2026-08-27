"""Own Appliance Settings and Backup Restore management UI transports."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.audit import record_audit
from atlaso.app.database import get_db
from atlaso.app.models import PhysicalInterface, VlanInterface, utcnow
from atlaso.app.security import Identity, require_session_identity
from atlaso.app.ui_routes import MANAGEMENT_UI_ROOT

Endpoint = Callable[..., Any]


@dataclass(frozen=True)
class SettingsBackupUiDependencies:
    """Provide facade-owned helpers without importing the compatibility facade."""

    require_management_ui_request: Endpoint
    require_admin_identity: Endpoint
    render: Endpoint
    verify_csrf: Endpoint
    backup_restore_context: Endpoint
    export_settings_archive: Endpoint
    archive_summary: Endpoint
    restore_settings_archive: Endpoint
    get_runtime_settings: Endpoint
    factory_password_policy: Mapping[str, bool | int]
    validate_password: Endpoint
    stage_appliance_apply_config: Endpoint
    system_adapter_factory: Endpoint
    replace_database_with_factory_candidate: Endpoint
    invalidate_appliance_apply_status_projection: Endpoint
    management_ui_path: Endpoint
    factory_reset_staged_credentials_path: str
    appliance_settings_context: Endpoint
    appliance_apply_status: Endpoint
    get_appliance_settings_row: Endpoint
    get_dns_settings_row: Endpoint
    appliance_settings_management_context: Endpoint
    web_terminal_interface_options: Endpoint
    normalized_web_terminal_interfaces: Endpoint
    web_terminal_interfaces_to_json: Endpoint
    get_ca_settings_row: Endpoint
    normalize_fqdn: Endpoint
    normalize_service_dns_target_naming: Endpoint
    normalize_multiline_values: Endpoint
    validate_appliance_settings: Endpoint
    appliance_dns_record_conflict: Endpoint
    ensure_ca_state: Endpoint
    ca_managed_certificate_paths: Endpoint
    ca_certificate_available: Endpoint
    ensure_dns_for_appliance_settings: Endpoint
    reconcile_factory_service_identities: Endpoint
    reconcile_service_dns_aliases: Endpoint
    save_logging_preferences: Endpoint
    configure_operational_logging: Endpoint
    logging_preferences_to_dict: Endpoint
    appliance_settings_staged_config_path: str


@dataclass(frozen=True)
class SettingsBackupUiRouter:
    """Return the configured router and compatibility endpoint exports."""

    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_router(dependencies: SettingsBackupUiDependencies) -> SettingsBackupUiRouter:
    """Build the Appliance Settings and Backup Restore management UI router.

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
    backup_restore_context = dependencies.backup_restore_context
    export_settings_archive = dependencies.export_settings_archive
    archive_summary = dependencies.archive_summary
    restore_settings_archive = dependencies.restore_settings_archive
    get_runtime_settings = dependencies.get_runtime_settings
    factory_password_policy = dict(dependencies.factory_password_policy)
    validate_password = dependencies.validate_password
    stage_appliance_apply_config = dependencies.stage_appliance_apply_config
    system_adapter_factory = dependencies.system_adapter_factory
    replace_database_with_factory_candidate = (
        dependencies.replace_database_with_factory_candidate
    )
    invalidate_appliance_apply_status_projection = (
        dependencies.invalidate_appliance_apply_status_projection
    )
    management_ui_path = dependencies.management_ui_path
    FACTORY_RESET_STAGED_CREDENTIALS_PATH = (
        dependencies.factory_reset_staged_credentials_path
    )
    appliance_settings_context = dependencies.appliance_settings_context
    appliance_apply_status = dependencies.appliance_apply_status
    get_appliance_settings_row = dependencies.get_appliance_settings_row
    get_dns_settings_row = dependencies.get_dns_settings_row
    appliance_settings_management_context = (
        dependencies.appliance_settings_management_context
    )
    web_terminal_interface_options = dependencies.web_terminal_interface_options
    normalized_web_terminal_interfaces = dependencies.normalized_web_terminal_interfaces
    web_terminal_interfaces_to_json = dependencies.web_terminal_interfaces_to_json
    get_ca_settings_row = dependencies.get_ca_settings_row
    normalize_fqdn = dependencies.normalize_fqdn
    normalize_service_dns_target_naming = (
        dependencies.normalize_service_dns_target_naming
    )
    normalize_multiline_values = dependencies.normalize_multiline_values
    validate_appliance_settings = dependencies.validate_appliance_settings
    appliance_dns_record_conflict = dependencies.appliance_dns_record_conflict
    ensure_ca_state = dependencies.ensure_ca_state
    ca_managed_certificate_paths = dependencies.ca_managed_certificate_paths
    ca_certificate_available = dependencies.ca_certificate_available
    ensure_dns_for_appliance_settings = dependencies.ensure_dns_for_appliance_settings
    reconcile_factory_service_identities = (
        dependencies.reconcile_factory_service_identities
    )
    reconcile_service_dns_aliases = dependencies.reconcile_service_dns_aliases
    save_logging_preferences = dependencies.save_logging_preferences
    configure_operational_logging = dependencies.configure_operational_logging
    logging_preferences_to_dict = dependencies.logging_preferences_to_dict
    APPLIANCE_SETTINGS_STAGED_CONFIG_PATH = (
        dependencies.appliance_settings_staged_config_path
    )

    @router.get("/backup-restore", response_class=HTMLResponse, response_model=None)
    def backup_restore_page(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse | RedirectResponse:
        """Handle the backup restore page endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            A safe login handoff after the dedicated reset is accepted or completed.
        """
        require_admin_identity(identity)
        return render(
            request,
            "backup_restore.html",
            {"identity": identity, **backup_restore_context(db)},
        )

    @router.post("/backup-restore/export", response_model=None)
    def export_backup_restore_archive(
        request: Request,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the export backup restore archive endpoint.

        Args:
            request: Incoming HTTP request.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        require_admin_identity(identity)
        verify_csrf(request, csrf)
        archive = export_settings_archive(db, actor=identity.username)
        exported_at = utcnow().strftime("%Y%m%d-%H%M%SZ")
        record_audit(
            db,
            actor=identity.username,
            action="export_settings_backup",
            resource_type="settings_backup",
            detail=f"{sum(len(value) for value in archive['data'].values() if isinstance(value, list))} desired-state rows",
            request_id=request.state.request_id,
        )
        return Response(
            json.dumps(archive, indent=2, sort_keys=True),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="atlaso-settings-{exported_at}.json"'
            },
        )

    @router.post(
        "/backup-restore/restore", response_class=HTMLResponse, response_model=None
    )
    async def restore_backup_restore_archive(
        request: Request,
        archive_file: UploadFile = File(...),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the restore backup restore archive endpoint.

        Args:
            request: Incoming HTTP request.
            archive_file: Archive file supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        require_admin_identity(identity)
        verify_csrf(request, csrf)
        raw_archive = await archive_file.read()
        if len(raw_archive) > 3_000_000:
            return render(
                request,
                "backup_restore.html",
                {
                    "identity": identity,
                    **backup_restore_context(
                        db, error="The settings archive is too large."
                    ),
                },
                status_code=413,
            )
        try:
            archive = json.loads(raw_archive.decode("utf-8"))
            summary = archive_summary(archive)
            counts = restore_settings_archive(db, archive)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            return render(
                request,
                "backup_restore.html",
                {"identity": identity, **backup_restore_context(db, error=str(exc))},
                status_code=400,
            )
        record_audit(
            db,
            actor=identity.username,
            action="restore_settings_backup",
            resource_type="settings_backup",
            detail=f"Restored {sum(counts.values())} desired-state rows from {archive_file.filename or 'uploaded archive'}; services forced stopped/unconfigured.",
            request_id=request.state.request_id,
        )
        return render(
            request,
            "backup_restore.html",
            {
                "identity": identity,
                **backup_restore_context(
                    db,
                    result={
                        "title": "Settings restored",
                        "message": "Desired-state settings were restored. Services are stopped and unconfigured until reviewed and applied through the global appliance workflow.",
                        "summary": summary,
                        "counts": counts,
                    },
                ),
            },
        )

    @router.post(
        "/backup-restore/factory-reset",
        response_class=HTMLResponse,
        response_model=None,
    )
    def factory_reset_backup_restore(
        request: Request,
        admin_password_action: str = Form(...),
        admin_password: str = Form(""),
        admin_password_confirm: str = Form(""),
        root_password_action: str = Form(...),
        root_password: str = Form(""),
        root_password_confirm: str = Form(""),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the factory reset backup restore endpoint.

        Args:
            request: Incoming HTTP request.
            admin_password_action: Whether to keep or change the bootstrap administrator password.
            admin_password: New bootstrap administrator password when change is selected.
            admin_password_confirm: Repeated bootstrap administrator password.
            root_password_action: Whether to keep or change the root password.
            root_password: New root password when change is selected.
            root_password_confirm: Repeated root password.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        require_admin_identity(identity)
        verify_csrf(request, csrf)
        settings = get_runtime_settings()
        password_plan: dict[str, str | int] = {"schema_version": 1}
        policy = factory_password_policy
        validation_errors: list[str] = []
        account_inputs = (
            (
                "admin",
                "Bootstrap administrator",
                settings.bootstrap_admin_username,
                admin_password_action,
                admin_password,
                admin_password_confirm,
            ),
            (
                "root",
                "Root",
                "root",
                root_password_action,
                root_password,
                root_password_confirm,
            ),
        )
        for key, label, username, action, password, confirmation in account_inputs:
            if action not in {"keep", "change"}:
                validation_errors.append(f"Choose whether to keep or change the {label.lower()} password.")
                continue
            password_plan[f"{key}_action"] = action
            if action == "keep":
                if password or confirmation:
                    validation_errors.append(
                        f"Clear the new {label.lower()} password fields or choose Change password."
                    )
                continue
            if password != confirmation:
                validation_errors.append(f"The new {label.lower()} passwords do not match.")
                continue
            if any(character in password for character in ("\x00", "\r", "\n")):
                validation_errors.append(
                    f"The new {label.lower()} password contains unsupported characters."
                )
                continue
            password_errors = validate_password(password, username, policy)
            validation_errors.extend(
                f"{label}: {error}" for error in password_errors
            )
            if not password_errors:
                password_plan[f"{key}_password"] = password
        if validation_errors:
            return render(
                request,
                "backup_restore.html",
                {
                    "identity": identity,
                    **backup_restore_context(db, error=" ".join(validation_errors)),
                },
                status_code=422,
            )
        if settings.environment == "appliance" and not settings.dry_run_system_adapters:
            staging_template = Path(FACTORY_RESET_STAGED_CREDENTIALS_PATH)
            request_credentials_path = staging_template.with_name(
                f"{staging_template.stem}-{uuid4().hex}{staging_template.suffix}"
            )
            credentials_path = stage_appliance_apply_config(
                str(request_credentials_path),
                json.dumps(password_plan, sort_keys=True),
            )
            scheduled = system_adapter_factory(dry_run=False).schedule_factory_reset(
                credentials_path
            )
            if scheduled.returncode != 0:
                Path(credentials_path).unlink(missing_ok=True)
                detail = (
                    scheduled.stderr
                    or scheduled.stdout
                    or "Factory reset could not be scheduled."
                ).strip()
                return render(
                    request,
                    "backup_restore.html",
                    {"identity": identity, **backup_restore_context(db, error=detail)},
                    status_code=503,
                )
            request.session.clear()
            return RedirectResponse(
                f"{management_ui_path('/login')}?factory_reset=scheduled",
                status_code=303,
            )

        if any(password_plan[f"{account}_action"] == "change" for account in ("admin", "root")):
            return render(
                request,
                "backup_restore.html",
                {
                    "identity": identity,
                    **backup_restore_context(
                        db,
                        error="Password changes require the appliance runtime. Choose Keep current password for both accounts in development.",
                    ),
                },
                status_code=422,
            )

        replace_database_with_factory_candidate(
            db,
            database_url=settings.database_url,
            adapter=system_adapter_factory(dry_run=True),
            credential_plan={
                key: str(value)
                for key, value in password_plan.items()
                if key != "schema_version"
            },
        )
        invalidate_appliance_apply_status_projection()
        request.session.clear()
        request.session["factory_reset_completed"] = True
        return RedirectResponse(
            f"{management_ui_path('/login')}?factory_reset=complete",
            status_code=303,
        )

    @router.get("/settings", response_class=HTMLResponse, response_model=None)
    def settings_page(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the settings page endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        return render(
            request,
            "settings.html",
            {
                "identity": identity,
                **appliance_settings_context(db),
                "appliance_apply_status": appliance_apply_status(
                    db, "appliance_settings"
                ),
            },
        )

    @router.post("/settings", response_model=None)
    def update_settings_from_ui(
        request: Request,
        fqdn: str = Form("core.atlaso.internal"),
        management_https_enabled: bool = Form(False),
        web_terminal_enabled: bool = Form(False),
        web_terminal_interfaces: list[str] = Form(default_factory=list),
        web_terminal_interfaces_present: str | None = Form(None),
        root_ssh_enabled: bool = Form(False),
        service_dns_target_naming: str = Form("ip"),
        external_dns_servers: str = Form(""),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the update settings from ui endpoint.

        Args:
            request: Incoming HTTP request.
            fqdn: Fully qualified domain name to validate or use.
            management_https_enabled: Management https enabled supplied by the caller.
            web_terminal_enabled: Web terminal enabled supplied by the caller.
            web_terminal_interfaces: Web terminal interfaces supplied by the caller.
            web_terminal_interfaces_present: Web terminal interfaces present supplied by the caller.
            root_ssh_enabled: Root ssh enabled supplied by the caller.
            service_dns_target_naming: Service dns target naming supplied by the caller.
            external_dns_servers: External dns servers supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        settings = get_appliance_settings_row(db)
        previous_fqdn = settings.fqdn
        previous_service_dns_target_naming = normalize_service_dns_target_naming(
            settings.service_dns_target_naming
        )
        settings.fqdn = normalize_fqdn(fqdn) or "core.atlaso.internal"
        settings.management_https_enabled = bool(management_https_enabled)
        settings.web_terminal_enabled = bool(web_terminal_enabled)
        settings.root_ssh_enabled = bool(root_ssh_enabled)
        settings.service_dns_target_naming = normalize_service_dns_target_naming(
            service_dns_target_naming
        )
        settings.external_dns_servers = normalize_multiline_values(external_dns_servers)
        settings.config_path = APPLIANCE_SETTINGS_STAGED_CONFIG_PATH
        settings.updated_at = utcnow()
        dns_settings = get_dns_settings_row(db)
        management = appliance_settings_management_context(db)
        physical_interfaces = (
            db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name))
            .scalars()
            .all()
        )
        vlan_interfaces = (
            db.execute(
                select(VlanInterface).order_by(
                    VlanInterface.parent_interface, VlanInterface.vlan_id
                )
            )
            .scalars()
            .all()
        )
        terminal_options = web_terminal_interface_options(
            physical_interfaces, vlan_interfaces
        )
        requested_terminal_interfaces = (
            web_terminal_interfaces
            if web_terminal_interfaces_present is not None
            else normalized_web_terminal_interfaces(settings, management)
        )
        if settings.web_terminal_enabled and management.get("name"):
            requested_terminal_interfaces = [
                management["name"],
                *[
                    name
                    for name in requested_terminal_interfaces
                    if name != management["name"]
                ],
            ]
        settings.web_terminal_interfaces_json = web_terminal_interfaces_to_json(
            requested_terminal_interfaces
        )
        ca_settings = get_ca_settings_row(db)
        preflight_errors, _preflight_warnings = validate_appliance_settings(
            settings,
            local_dns_enabled=bool(dns_settings.enabled),
            management_interface=management,
            dns_record_conflict=bool(dns_settings.enabled)
            and appliance_dns_record_conflict(db, settings.fqdn),
            ca_enabled=bool(ca_settings.enabled),
            management_https_cert_available=True,
            web_terminal_options=terminal_options,
        )
        reconciled_service_identities = reconcile_factory_service_identities(
            db,
            previous_appliance_fqdn=previous_fqdn,
        )
        ca_state_errors: list[str] = []
        if (
            settings.management_https_enabled
            and ca_settings.enabled
            and not preflight_errors
        ):
            ca_state_errors = ensure_ca_state(db)
            management = appliance_settings_management_context(db)
            ca_settings = get_ca_settings_row(db)
        (
            management_https_cert_path,
            management_https_key_path,
            _management_https_chain_path,
        ) = ca_managed_certificate_paths(db, "appliance:https")
        management_https_cert_available = bool(
            management_https_cert_path
            and management_https_key_path
            and ca_certificate_available(db, "appliance:https")
        )
        validation_errors, _validation_warnings = validate_appliance_settings(
            settings,
            local_dns_enabled=bool(dns_settings.enabled),
            management_interface=management,
            dns_record_conflict=bool(dns_settings.enabled)
            and appliance_dns_record_conflict(db, settings.fqdn),
            ca_enabled=bool(ca_settings.enabled),
            management_https_cert_available=management_https_cert_available,
            web_terminal_options=terminal_options,
        )
        validation_errors = [*ca_state_errors, *validation_errors]
        dns_record_action = None
        if not validation_errors:
            dns_record_action = ensure_dns_for_appliance_settings(
                db, settings, previous_fqdn=previous_fqdn, actor=identity.username
            )
            if previous_service_dns_target_naming != settings.service_dns_target_naming:
                reconcile_service_dns_aliases(db, actor=identity.username)
        if reconciled_service_identities:
            reconcile_service_dns_aliases(db, actor=identity.username)
        db.add(settings)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="update_appliance_settings",
            resource_type="settings",
            resource_id=str(settings.id),
        )
        if request.headers.get("X-Atlaso-Autosave") == "1":
            context = appliance_settings_context(
                db, reconcile_dns=not validation_errors
            )
            saved = context["appliance_settings"]
            return JSONResponse(
                {
                    "status": "saved",
                    "updated_at": saved.updated_at.isoformat(),
                    "fqdn": saved.fqdn,
                    "management_https_enabled": saved.management_https_enabled,
                    "web_terminal_enabled": saved.web_terminal_enabled,
                    "web_terminal_interfaces": context[
                        "selected_web_terminal_interfaces"
                    ],
                    "web_terminal_addresses": context["web_terminal_addresses"],
                    "management_https_cert_available": context[
                        "management_https_cert_available"
                    ],
                    "root_ssh_enabled": saved.root_ssh_enabled,
                    "service_dns_target_naming": normalize_service_dns_target_naming(
                        saved.service_dns_target_naming
                    ),
                    "external_dns_servers": context["appliance_settings_json"][
                        "external_dns_servers"
                    ],
                    "resolver_mode": context["appliance_settings_resolver_mode"],
                    "observed_dhcp_dns_servers": context[
                        "appliance_settings_observed_dhcp_dns_servers"
                    ],
                    "local_dns_enabled": context["local_dns_enabled"],
                    "management_interface": context["management_interface"],
                    "dns_record_action": dns_record_action,
                    "valid": not context["appliance_settings_validation_errors"],
                    "validation_errors": context[
                        "appliance_settings_validation_errors"
                    ],
                    "validation_warnings": context[
                        "appliance_settings_validation_warnings"
                    ],
                    "config_path": saved.config_path,
                    "config_preview": context["appliance_settings_config_preview"],
                }
            )
        return RedirectResponse("/settings", status_code=303)

    @router.post("/settings/vmware-ceip", response_model=None)
    def update_vmware_ceip_from_ui(
        request: Request,
        vmware_ceip_enabled: bool = Form(False),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the update vmware ceip from ui endpoint.

        Args:
            request: Incoming HTTP request.
            vmware_ceip_enabled: Vmware ceip enabled supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        settings = get_appliance_settings_row(db)
        settings.vmware_ceip_enabled = bool(vmware_ceip_enabled)
        settings.config_path = APPLIANCE_SETTINGS_STAGED_CONFIG_PATH
        settings.updated_at = utcnow()
        db.add(settings)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="update_vmware_ceip_policy",
            resource_type="settings",
            resource_id=str(settings.id),
            detail=f"enabled={str(settings.vmware_ceip_enabled).lower()}",
        )
        if request.headers.get("X-Atlaso-Autosave") == "1":
            context = appliance_settings_context(db)
            saved = context["appliance_settings"]
            return JSONResponse(
                {
                    "status": "saved",
                    "updated_at": saved.updated_at.isoformat(),
                    "fqdn": saved.fqdn,
                    "management_https_enabled": saved.management_https_enabled,
                    "web_terminal_enabled": saved.web_terminal_enabled,
                    "web_terminal_interfaces": context[
                        "selected_web_terminal_interfaces"
                    ],
                    "web_terminal_addresses": context["web_terminal_addresses"],
                    "management_https_cert_available": context[
                        "management_https_cert_available"
                    ],
                    "root_ssh_enabled": saved.root_ssh_enabled,
                    "vmware_ceip_enabled": saved.vmware_ceip_enabled,
                    "service_dns_target_naming": normalize_service_dns_target_naming(
                        saved.service_dns_target_naming
                    ),
                    "external_dns_servers": context["appliance_settings_json"][
                        "external_dns_servers"
                    ],
                    "resolver_mode": context["appliance_settings_resolver_mode"],
                    "observed_dhcp_dns_servers": context[
                        "appliance_settings_observed_dhcp_dns_servers"
                    ],
                    "local_dns_enabled": context["local_dns_enabled"],
                    "management_interface": context["management_interface"],
                    "dns_record_action": None,
                    "valid": not context["appliance_settings_validation_errors"],
                    "validation_errors": context[
                        "appliance_settings_validation_errors"
                    ],
                    "validation_warnings": context[
                        "appliance_settings_validation_warnings"
                    ],
                    "config_path": saved.config_path,
                    "config_preview": context["appliance_settings_config_preview"],
                }
            )
        return RedirectResponse("/settings", status_code=303)

    @router.post("/settings/logging", response_model=None)
    def update_logging_settings_from_ui(
        request: Request,
        level: str = Form("INFO"),
        syslog_enabled: bool = Form(False),
        syslog_host: str = Form(""),
        syslog_port: str = Form("514"),
        syslog_protocol: str = Form("udp"),
        syslog_facility: str = Form("local0"),
        syslog_level: str = Form("INFO"),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the update logging settings from ui endpoint.

        Args:
            request: Incoming HTTP request.
            level: Level supplied by the caller.
            syslog_enabled: Syslog enabled supplied by the caller.
            syslog_host: Syslog host supplied by the caller.
            syslog_port: Syslog port supplied by the caller.
            syslog_protocol: Syslog protocol supplied by the caller.
            syslog_facility: Syslog facility supplied by the caller.
            syslog_level: Syslog level supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        try:
            preferences = save_logging_preferences(
                db,
                level=level,
                syslog_enabled=bool(syslog_enabled),
                syslog_host=syslog_host,
                syslog_port=syslog_port,
                syslog_protocol=syslog_protocol,
                syslog_facility=syslog_facility,
                syslog_level=syslog_level,
            )
        except ValueError as exc:
            if request.headers.get("X-Atlaso-Autosave") == "1":
                return JSONResponse(
                    {"status": "error", "message": str(exc)}, status_code=422
                )
            return render(
                request,
                "settings.html",
                {
                    "identity": identity,
                    **appliance_settings_context(db),
                    "appliance_apply_status": appliance_apply_status(
                        db, "appliance_settings"
                    ),
                    "logging_settings_error": str(exc),
                },
                status_code=422,
            )
        db.commit()
        configure_operational_logging(db)
        record_audit(
            db,
            actor=identity.username,
            action="update_operational_logging_settings",
            resource_type="logging",
            detail=(
                f"level={preferences.level} syslog={'enabled' if preferences.syslog_enabled else 'disabled'} "
                f"syslog_level={preferences.syslog_level} syslog_protocol={preferences.syslog_protocol} "
                f"syslog_facility={preferences.syslog_facility}"
            ),
            request_id=request.state.request_id,
        )
        if request.headers.get("X-Atlaso-Autosave") == "1":
            return JSONResponse(
                {
                    "status": "saved",
                    "logging_preferences": logging_preferences_to_dict(preferences),
                }
            )
        return RedirectResponse("/settings", status_code=303)

    endpoints = {
        endpoint.__name__: endpoint
        for endpoint in (
            backup_restore_page,
            export_backup_restore_archive,
            restore_backup_restore_archive,
            factory_reset_backup_restore,
            settings_page,
            update_settings_from_ui,
            update_vmware_ceip_from_ui,
            update_logging_settings_from_ui,
        )
    }
    return SettingsBackupUiRouter(router=router, endpoints=endpoints)
