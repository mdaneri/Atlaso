"""Own VCF workflow management UI transport handlers."""

from __future__ import annotations

import json
import re
import ssl
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from threading import Lock
from typing import Any
from urllib.parse import quote, urlsplit
from uuid import uuid4

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
)
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import desc, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from atlaso.app.audit import record_audit
from atlaso.app.config import get_settings
from atlaso.app.database import get_db
from atlaso.app.models import (
    AuditEvent,
    Job,
    JobStatus,
    User,
    Vault,
    VaultEntry,
    VcfDepotDownloadProfile,
    VcfRegistryBundle,
    utcnow,
)
from atlaso.app.operational_logging import log_audit_event
from atlaso.app.secrets import decrypt_secret
from atlaso.app.security import Identity, require_session_identity
from atlaso.app.services.dnsmasq import split_addresses, split_interfaces
from atlaso.app.services.local_users import has_pending_os_password
from atlaso.app.services.vaults import (
    VaultEntryInput,
    redact_secret_values,
    upsert_vault_entry,
    vault_entry_metadata,
)
from atlaso.app.services.vcf_backups import (
    VCF_BACKUP_DEFAULT_USERNAME,
    VCF_BACKUP_DEFAULT_VOLUME_MOUNT,
    VCF_BACKUP_EFFECTIVE_CONFIG_PATH,
    vcf_backup_remote_directory,
)
from atlaso.app.services.vcf_depot_downloads import (
    ActiveVcfDepotDownloadError,
    VcfDepotExclusiveOperationError,
    VcfDepotProfileUnavailableError,
    acquire_vcf_depot_admission_gate,
    active_vcf_depot_download_jobs,
    active_vcf_depot_exclusive_job,
    disable_vcf_depot_profile_schedules,
    enqueue_vcf_depot_download,
    lock_vcf_depot_profile_for_deletion,
    vcf_depot_job_profile_id,
    vcf_depot_schedules_for_profile,
    vcf_depot_task_log_reference,
)
from atlaso.app.services.vcf_depot_target import (
    VcfDepotTargetError,
    inspect_target_depot,
)
from atlaso.app.services.vcf_offline_depot import (
    VCF_DEPOT_ACTIVATION_NAME_KEY,
    VCF_DEPOT_ACTIVATION_VALUE_KEY,
    VCF_DEPOT_APPLICATION_PROPERTIES_CONTENT_KEY,
    VCF_DEPOT_APPLICATION_PROPERTIES_NAME,
    VCF_DEPOT_APPLICATION_PROPERTIES_SOURCE_KEY,
    VCF_DEPOT_APPLICATION_PROPERTIES_UPDATED_AT_KEY,
    VCF_DEPOT_DEFAULT_CONFIG_PATH,
    VCF_DEPOT_DEFAULT_STORE_PATH,
    VCF_DEPOT_DEFAULT_USERNAME,
    VCF_DEPOT_TOKEN_NAME_KEY,
    VCF_DEPOT_TOKEN_VALUE_KEY,
    render_vcfdt_command_preview,
    vcf_depot_profile_to_dict,
)
from atlaso.app.services.vcf_private_registry import (
    VCF_REGISTRY_DEFAULT_CONFIG_PATH,
    VCF_REGISTRY_DEFAULT_PROJECT,
    VCF_REGISTRY_DEFAULT_STORAGE_PATH,
    default_target_reference,
    vcf_registry_bundle_to_dict,
)
from atlaso.app.services.vcf_sddc_deployment import (
    VcfSddcDeploymentError,
    complete_property_mapping,
    inspect_ova,
    normalize_disk_provisioning,
    tls_sha256_fingerprint,
    vsphere_inventory,
    vsphere_ovf_descriptor,
)
from atlaso.app.services.vcf_trust import (
    VcfTrustCredentials,
    VcfTrustError,
    inspect_vcf_trust_target,
    root_ca_info,
    sanitized_result,
)
from atlaso.app.ui_routes import MANAGEMENT_UI_ROOT

Endpoint = Callable[..., Any]
VCF_FQDN_POPULATION_MAX_AGE_SECONDS = 15 * 60


def _vcf_fqdn_population_serializer() -> URLSafeTimedSerializer:
    """Return the signer used for bounded VCF FQDN review revisions."""
    return URLSafeTimedSerializer(
        get_settings().secret_key,
        salt="atlaso-vcf-fqdn-population-v1",
    )


def _vcf_fqdn_input_revision(
    *,
    actor: str,
    target: str,
    domain: str,
    prefix: str,
    suffix: str,
    start_ipv4: str,
    network_prefix: str,
    component_keys: list[str],
    hostnames: list[str],
) -> dict[str, object]:
    """Return the exact browser inputs bound to one populated review."""
    return {
        "actor": actor,
        "target": target,
        "domain": domain,
        "prefix": prefix,
        "suffix": suffix,
        "start_ipv4": start_ipv4,
        "network_prefix": network_prefix,
        "component_keys": list(component_keys),
        "hostnames": list(hostnames),
    }


def _vcf_fqdn_population_token(**revision: object) -> str:
    """Sign one exact populated VCF FQDN input revision."""
    return _vcf_fqdn_population_serializer().dumps(revision)


def _vcf_fqdn_population_matches(token: str, **revision: object) -> bool:
    """Return whether a bounded token matches the exact submitted revision."""
    if not token:
        return False
    try:
        populated = _vcf_fqdn_population_serializer().loads(
            token,
            max_age=VCF_FQDN_POPULATION_MAX_AGE_SECONDS,
        )
    except (BadSignature, SignatureExpired):
        return False
    return populated == revision


@dataclass(frozen=True)
class VcfWorkflowsUiDependencies:
    """Provide facade-owned helpers without importing the compatibility facade."""

    require_management_ui_request: Endpoint
    vcf_depot_submit_lock: Lock
    vcf_depot_vdt_log_path: PurePosixPath
    vcf_helper_default_target: str
    vcf_generated_fqdn_preview: Endpoint
    job_payload: Endpoint
    normalize_vcf_trust_address: Endpoint
    task_row: Endpoint
    vcf_trust_target: Endpoint
    active_vcf_depot_execution_job: Endpoint
    appliance_apply_client_status: Endpoint
    appliance_apply_status: Endpoint
    confirmed_tls_fingerprint: Endpoint
    create_vcf_generated_dns_records: Endpoint
    allocate_vcf_generated_records: Endpoint
    delete_vcf_generated_dns_records: Endpoint
    disable_default_vcf_backup_user_when_service_off: Endpoint
    disable_default_vcf_depot_user_when_service_off: Endpoint
    dnsmasq_apply_status: Endpoint
    dnsmasq_context: Endpoint
    discover_vcf_passwords: Endpoint
    ensure_dns_for_vcf_offline_depot: Endpoint
    ensure_dns_for_vcf_registry: Endpoint
    ensure_vcf_depot_software_id_task_steps: Endpoint
    get_appliance_settings_row: Endpoint
    get_ca_settings_row: Endpoint
    get_vcf_backup_settings_row: Endpoint
    get_vcf_offline_depot_settings_row: Endpoint
    get_vcf_private_registry_settings_row: Endpoint
    grid_request: Endpoint
    grid_saved_response: Endpoint
    local_vcf_depot_target_context: Endpoint
    primary_listen_address: Endpoint
    primary_listen_interface: Endpoint
    queue_vcf_sddc_deployment_job: Endpoint
    queue_vcf_target_depot_job: Endpoint
    queue_vcf_trust_job: Endpoint
    render: Endpoint
    require_admin_identity: Endpoint
    require_vcf_helper_write: Endpoint
    reset_vcf_depot_tool_staging: Endpoint
    resolve_vcf_helper_credentials: Endpoint
    resolve_service_bind_targets: Endpoint
    resolve_vcf_depot_download_mode_flags: Endpoint
    run_vcf_depot_software_id_job: Endpoint
    set_setting_value: Endpoint
    stage_vcf_depot_runtime_secrets_after_upload: Endpoint
    store_pasted_vcf_depot_secret: Endpoint
    store_uploaded_vcf_depot_archive: Endpoint
    store_uploaded_vcf_depot_secret: Endpoint
    store_uploaded_vcf_registry_ca_bundle: Endpoint
    tail_fixed_log_file: Endpoint
    vcf_backup_context: Endpoint
    vcf_depot_command_entry: Endpoint
    vcf_depot_download_job_rows: Endpoint
    vcf_depot_download_preflight: Endpoint
    vcf_depot_execution_conflict_detail: Endpoint
    vcf_depot_profile_start_states: Endpoint
    vcf_depot_secret_context: Endpoint
    vcf_depot_software_depot_id_context: Endpoint
    vcf_depot_task_log_path: Endpoint
    vcf_depot_tool_installed: Endpoint
    vcf_helper_context: Endpoint
    vcf_ldap_helper_context: Endpoint
    vcf_offline_depot_context: Endpoint
    vcf_private_registry_context: Endpoint
    vcf_registry_ca_bundle_context: Endpoint
    vcf_trust_context: Endpoint
    verify_csrf: Endpoint


@dataclass(frozen=True)
class VcfWorkflowsUiRouter:
    """Return the configured router and compatibility endpoint exports."""

    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_router(dependencies: VcfWorkflowsUiDependencies) -> VcfWorkflowsUiRouter:
    """Build the VCF workflows management UI router.

    Args:
        dependencies: Stable facade dependencies used by VCF workflow transports.
    """
    router = APIRouter(
        prefix=MANAGEMENT_UI_ROOT,
        dependencies=[Depends(dependencies.require_management_ui_request)],
    )
    VCF_DEPOT_SUBMIT_LOCK = dependencies.vcf_depot_submit_lock
    VCF_DEPOT_VDT_LOG_PATH = dependencies.vcf_depot_vdt_log_path
    VCF_HELPER_DEFAULT_TARGET = dependencies.vcf_helper_default_target
    vcf_generated_fqdn_preview = dependencies.vcf_generated_fqdn_preview
    _job_payload = dependencies.job_payload
    _normalize_vcf_trust_address = dependencies.normalize_vcf_trust_address
    _task_row = dependencies.task_row
    _vcf_trust_target = dependencies.vcf_trust_target
    active_vcf_depot_execution_job = dependencies.active_vcf_depot_execution_job
    appliance_apply_client_status = dependencies.appliance_apply_client_status
    appliance_apply_status = dependencies.appliance_apply_status
    _confirmed_tls_fingerprint = dependencies.confirmed_tls_fingerprint
    create_vcf_generated_dns_records = dependencies.create_vcf_generated_dns_records
    allocate_vcf_generated_records = dependencies.allocate_vcf_generated_records
    delete_vcf_generated_dns_records = dependencies.delete_vcf_generated_dns_records
    disable_default_vcf_backup_user_when_service_off = (
        dependencies.disable_default_vcf_backup_user_when_service_off
    )
    disable_default_vcf_depot_user_when_service_off = (
        dependencies.disable_default_vcf_depot_user_when_service_off
    )
    dnsmasq_apply_status = dependencies.dnsmasq_apply_status
    dnsmasq_context = dependencies.dnsmasq_context
    discover_vcf_passwords = dependencies.discover_vcf_passwords
    ensure_dns_for_vcf_offline_depot = dependencies.ensure_dns_for_vcf_offline_depot
    ensure_dns_for_vcf_registry = dependencies.ensure_dns_for_vcf_registry
    ensure_vcf_depot_software_id_task_steps = (
        dependencies.ensure_vcf_depot_software_id_task_steps
    )
    get_appliance_settings_row = dependencies.get_appliance_settings_row
    get_ca_settings_row = dependencies.get_ca_settings_row
    get_vcf_backup_settings_row = dependencies.get_vcf_backup_settings_row
    get_vcf_offline_depot_settings_row = dependencies.get_vcf_offline_depot_settings_row
    get_vcf_private_registry_settings_row = (
        dependencies.get_vcf_private_registry_settings_row
    )
    grid_request = dependencies.grid_request
    grid_saved_response = dependencies.grid_saved_response
    local_vcf_depot_target_context = dependencies.local_vcf_depot_target_context
    primary_listen_address = dependencies.primary_listen_address
    primary_listen_interface = dependencies.primary_listen_interface
    queue_vcf_sddc_deployment_job = dependencies.queue_vcf_sddc_deployment_job
    queue_vcf_target_depot_job = dependencies.queue_vcf_target_depot_job
    queue_vcf_trust_job = dependencies.queue_vcf_trust_job
    render = dependencies.render
    require_admin_identity = dependencies.require_admin_identity
    require_vcf_helper_write = dependencies.require_vcf_helper_write
    reset_vcf_depot_tool_staging = dependencies.reset_vcf_depot_tool_staging
    resolve_vcf_helper_credentials = dependencies.resolve_vcf_helper_credentials
    resolve_service_bind_targets = dependencies.resolve_service_bind_targets
    resolve_vcf_depot_download_mode_flags = (
        dependencies.resolve_vcf_depot_download_mode_flags
    )
    run_vcf_depot_software_id_job = dependencies.run_vcf_depot_software_id_job
    set_setting_value = dependencies.set_setting_value
    stage_vcf_depot_runtime_secrets_after_upload = (
        dependencies.stage_vcf_depot_runtime_secrets_after_upload
    )
    store_pasted_vcf_depot_secret = dependencies.store_pasted_vcf_depot_secret
    store_uploaded_vcf_depot_archive = dependencies.store_uploaded_vcf_depot_archive
    store_uploaded_vcf_depot_secret = dependencies.store_uploaded_vcf_depot_secret
    store_uploaded_vcf_registry_ca_bundle = (
        dependencies.store_uploaded_vcf_registry_ca_bundle
    )
    tail_fixed_log_file = dependencies.tail_fixed_log_file
    vcf_backup_context = dependencies.vcf_backup_context
    vcf_depot_command_entry = dependencies.vcf_depot_command_entry
    vcf_depot_download_job_rows = dependencies.vcf_depot_download_job_rows
    vcf_depot_download_preflight = dependencies.vcf_depot_download_preflight
    vcf_depot_execution_conflict_detail = (
        dependencies.vcf_depot_execution_conflict_detail
    )
    vcf_depot_profile_start_states = dependencies.vcf_depot_profile_start_states
    vcf_depot_secret_context = dependencies.vcf_depot_secret_context
    vcf_depot_software_depot_id_context = (
        dependencies.vcf_depot_software_depot_id_context
    )
    vcf_depot_task_log_path = dependencies.vcf_depot_task_log_path
    vcf_depot_tool_installed = dependencies.vcf_depot_tool_installed
    vcf_helper_context = dependencies.vcf_helper_context
    vcf_ldap_helper_context = dependencies.vcf_ldap_helper_context
    vcf_offline_depot_context = dependencies.vcf_offline_depot_context
    vcf_private_registry_context = dependencies.vcf_private_registry_context
    vcf_registry_ca_bundle_context = dependencies.vcf_registry_ca_bundle_context
    vcf_trust_context = dependencies.vcf_trust_context
    verify_csrf = dependencies.verify_csrf

    @router.get("/https-repository", response_model=None)
    def legacy_https_repository_redirect(
        identity: Identity = Depends(require_session_identity),
    ) -> RedirectResponse:
        """Handle the legacy https repository redirect endpoint.

        Args:
            identity: Authenticated identity authorizing the request.

        Returns:
            The endpoint response.
        """
        return RedirectResponse("/vcf-offline-depot", status_code=307)

    @router.get("/vcf-helper", response_class=HTMLResponse, response_model=None)
    def vcf_helper_page(
        request: Request,
        ldap_organization_id: int | None = Query(None),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the vcf helper page endpoint.

        Args:
            request: Incoming HTTP request.
            ldap_organization_id: Identifier of the ldap organization.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        return render(
            request,
            "vcf_helper.html",
            vcf_helper_page_context(
                db,
                identity,
                selected_ldap_organization_id=ldap_organization_id,
                ldap_vcf_auto_open=request.query_params.get("ldap_vcf") == "1",
                vcf_trust_auto_open=request.query_params.get("vcf_trust") == "1",
            ),
        )

    def vcf_helper_page_context(
        db: Session,
        identity: Identity,
        *,
        selected_ldap_organization_id: int | None = None,
        ldap_vcf_auto_open: bool = False,
        ldap_generate_auto_open: bool = False,
        vcf_trust_auto_open: bool = False,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Return vcf helper page context.

        Args:
            db: Active database session.
            identity: Authenticated identity authorizing the request.
            selected_ldap_organization_id: Identifier of the selected ldap organization.
            ldap_vcf_auto_open: Ldap vcf auto open supplied by the caller.
            ldap_generate_auto_open: Ldap generate auto open supplied by the caller.
            vcf_trust_auto_open: Vcf trust auto open supplied by the caller.
            extra: Extra supplied by the caller.
        """
        dns_context = dnsmasq_context(db)
        vcf_vaults = (
            db.execute(
                select(Vault).options(selectinload(Vault.entries)).order_by(Vault.name)
            )
            .scalars()
            .all()
        )
        credential_options = []
        if identity.has_role("admin"):
            credential_options = [
                {
                    "id": vault.id,
                    "name": vault.name,
                    "entries": [
                        vault_entry_metadata(entry)
                        for entry in sorted(vault.entries, key=lambda item: item.key)
                    ],
                }
                for vault in vcf_vaults
                if vault.entries
            ]
        ldap_context_data: dict[str, Any] = {
            "vcf_ldap_authorized": False,
            "vcf_ldap_available": False,
            "vcf_ldap_organizations": [],
            "vcf_ldap_selected_organization": None,
            "vcf_ldap_mapping": {},
            "vcf_ldap_missing_password_count": 0,
        }
        if identity.has_role("admin"):
            ldap_context_data = {
                "vcf_ldap_authorized": True,
                **vcf_ldap_helper_context(
                    db, selected_organization_id=selected_ldap_organization_id
                ),
            }
        return {
            "identity": identity,
            **vcf_helper_context(db),
            **vcf_trust_context(db),
            **ldap_context_data,
            "vcf_vaults": vcf_vaults,
            "vcf_vault_credential_options": credential_options,
            "vcf_trust_auto_open": vcf_trust_auto_open,
            "ldap_vcf_auto_open": ldap_vcf_auto_open,
            "ldap_generate_auto_open": ldap_generate_auto_open,
            "appliance_apply_status": dnsmasq_apply_status(db, dns_context),
            **(extra or {}),
        }

    def vcf_submitted_fqdn_page_context(
        db: Session,
        identity: Identity,
        *,
        target: str,
        domain: str,
        prefix: str,
        suffix: str,
        start_ipv4: str,
        component_keys: list[str],
        hostnames: list[str],
    ) -> dict[str, Any]:
        """Preserve the submitted FQDN review in the server-rendered fallback.

        Args:
            db: Active database session.
            identity: Authenticated identity authorizing the request.
            target: Resource targeted by the operation.
            domain: Managed DNS domain affected by the operation.
            prefix: Prefix supplied by the caller.
            suffix: Suffix supplied by the caller.
            start_ipv4: Start ipv4 supplied by the caller.
            component_keys: Catalog component keys submitted by the caller.
            hostnames: Reviewed hostname labels paired with the submitted component keys.

        Returns:
            Page context retaining the submitted review fields and rows.
        """
        mapping = {
            component_key.strip().lower(): hostname.strip().lower()
            for component_key, hostname in zip(component_keys, hostnames, strict=False)
        }
        context = vcf_helper_page_context(db, identity)
        context.update(
            {
                "vcf_helper_default_target": target.strip().lower(),
                "vcf_helper_default_domain": domain.strip().strip(".").lower(),
                "vcf_helper_default_prefix": prefix,
                "vcf_helper_default_suffix": suffix,
                "vcf_helper_default_start_ipv4": start_ipv4,
                "vcf_helper_rows": vcf_generated_fqdn_preview(
                    domain,
                    prefix,
                    suffix,
                    target,
                    mapping,
                ),
            }
        )
        return context

    async def _vcf_helper_json(request: Request) -> dict[str, Any]:
        """Return vcf helper json.

        Args:
            request: Incoming HTTP request.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        try:
            payload = await request.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise HTTPException(
                status_code=400, detail="Submit a valid JSON request."
            ) from exc
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="Submit a JSON object.")
        verify_csrf(request, str(payload.get("csrf") or ""))
        return payload

    def _confirmed_tls_fingerprint_impl(
        address: str, port: int, confirmed: str
    ) -> tuple[str, JSONResponse | None]:
        """Return confirmed tls fingerprint.

        Args:
            address: Network address contacted or validated by the operation.
            port: Network port contacted, validated, or configured by the operation.
            confirmed: Confirmed consumed by confirmed TLS fingerprint.


        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        try:
            fingerprint = tls_sha256_fingerprint(address, port)
        except (OSError, ssl.SSLError) as exc:
            raise HTTPException(
                status_code=422,
                detail=f"Could not read the target TLS certificate: {exc}",
            ) from exc
        if confirmed.strip().upper() != fingerprint.upper():
            return fingerprint, JSONResponse(
                {
                    "status": "tls-confirmation-required",
                    "address": address,
                    "port": port,
                    "fingerprint": fingerprint,
                },
                status_code=409,
            )
        return fingerprint, None

    def _split_vcf_endpoint_address_port(
        raw_address: Any, raw_port: Any = None
    ) -> tuple[str, int]:
        """Return split vcf endpoint address port.

        Args:
            raw_address: Raw address consumed by split VCF endpoint address port.
            raw_port: Raw port consumed by split VCF endpoint address port.


        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        endpoint = str(raw_address or "").strip()
        port = 443
        if raw_port not in (None, ""):
            try:
                port = int(raw_port)
            except (TypeError, ValueError) as exc:
                raise HTTPException(
                    status_code=422,
                    detail="Target endpoint port must be a number from 1 to 65535.",
                ) from exc
        if not endpoint:
            return "", port
        if "://" in endpoint:
            parsed = urlsplit(endpoint)
            address = parsed.hostname or ""
            try:
                port = parsed.port or port
            except ValueError as exc:
                raise HTTPException(
                    status_code=422,
                    detail="Target endpoint port must be a number from 1 to 65535.",
                ) from exc
        elif endpoint.startswith("[") and "]" in endpoint:
            closing = endpoint.find("]")
            address = endpoint[1:closing]
            suffix = endpoint[closing + 1 :]
            if suffix.startswith(":") and suffix[1:]:
                try:
                    port = int(suffix[1:])
                except ValueError as exc:
                    raise HTTPException(
                        status_code=422,
                        detail="Target endpoint port must be a number from 1 to 65535.",
                    ) from exc
        elif endpoint.count(":") == 1 and endpoint.rsplit(":", 1)[1].isdigit():
            address, port_text = endpoint.rsplit(":", 1)
            port = int(port_text)
        else:
            address = endpoint.strip("[]")
        address = address.strip()
        if not 0 < port <= 65535:
            raise HTTPException(
                status_code=422,
                detail="Target endpoint port must be a number from 1 to 65535.",
            )
        return address, port

    def _resolve_vcf_helper_credentials_impl(
        db: Session,
        identity: Identity,
        values: dict[str, Any],
        *,
        username_field: str,
        password_field: str,
        purpose: str,
    ) -> tuple[str, str]:
        """Return vcf helper credentials.

        Args:
            db: Active database session.
            identity: Authenticated identity authorizing the request.
            values: Values to normalize, validate, or persist.
            username_field: Username field supplied by the caller.
            password_field: Password field supplied by the caller.
            purpose: Purpose supplied by the caller.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        raw_vault_id = values.get("credential_vault_id")
        raw_entry_id = values.get("credential_entry_id")
        if raw_vault_id in (None, "") and raw_entry_id in (None, ""):
            return str(values.get(username_field) or "").strip(), str(
                values.get(password_field) or ""
            )
        require_admin_identity(identity)
        try:
            vault_id = int(raw_vault_id or 0)
            entry_id = int(raw_entry_id or 0)
        except (TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=422, detail="Choose a valid vault and key."
            ) from exc
        entry = db.execute(
            select(VaultEntry).where(
                VaultEntry.id == entry_id, VaultEntry.vault_id == vault_id
            )
        ).scalar_one_or_none()
        if entry is None:
            raise HTTPException(status_code=422, detail="Choose a valid vault and key.")
        username = str(entry.username or "").strip()
        if not username:
            raise HTTPException(
                status_code=422,
                detail="The selected vault key does not have a username.",
            )
        password = decrypt_secret(entry.encrypted_value)
        record_audit(
            db,
            actor=identity.username,
            action="use_vcf_helper_vault_credential",
            resource_type="vault_entry",
            resource_id=str(entry.id),
            detail=f"purpose={purpose}; vault_id={vault_id}; key={entry.key}",
        )
        return username, password

    @router.post(
        "/vcf-helper/vault-import/inspect",
        response_class=JSONResponse,
        response_model=None,
    )
    async def inspect_vcf_vault_import(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Handle the inspect vcf vault import endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        require_admin_identity(identity)
        payload = await _vcf_helper_json(request)
        address, port = _split_vcf_endpoint_address_port(
            payload.get("address"), payload.get("port")
        )
        if not address:
            raise HTTPException(
                status_code=422, detail="Enter the VCF appliance address."
            )
        fingerprint, confirmation = _confirmed_tls_fingerprint(
            address,
            port,
            str(payload.get("confirmed_fingerprint") or ""),
        )
        if confirmation is not None:
            return confirmation
        try:
            source_username, source_password = resolve_vcf_helper_credentials(
                db,
                identity,
                payload,
                username_field="username",
                password_field="password",
                purpose="vault_import_inspect",
            )
            candidates = discover_vcf_passwords(
                source_type=str(payload.get("source_type") or ""),
                address=address,
                port=port,
                username=source_username,
                password=source_password,
                expected_fingerprint=fingerprint,
            )
        except VcfDepotTargetError as exc:
            raise HTTPException(
                status_code=422,
                detail=redact_secret_values(str(exc), [source_password]),
            ) from exc
        return JSONResponse(
            {"candidates": [candidate.sanitized() for candidate in candidates]},
            headers={"Cache-Control": "no-store, private", "Pragma": "no-cache"},
        )

    @router.post(
        "/vcf-helper/vault-import", response_class=JSONResponse, response_model=None
    )
    async def import_vcf_passwords_to_vault(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Handle the import vcf passwords to vault endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
            VcfDepotTargetError: If the operation encounters an invalid state.
        """
        require_admin_identity(identity)
        payload = await _vcf_helper_json(request)
        try:
            vault_id = int(payload.get("vault_id") or 0)
        except (TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=422, detail="Choose a destination vault."
            ) from exc
        vault = db.get(Vault, vault_id)
        if vault is None:
            raise HTTPException(status_code=422, detail="Choose a destination vault.")
        selected = payload.get("candidate_ids")
        if (
            not isinstance(selected, list)
            or not selected
            or any(not isinstance(item, str) for item in selected)
        ):
            raise HTTPException(
                status_code=422, detail="Select at least one password to import."
            )
        address, port = _split_vcf_endpoint_address_port(
            payload.get("address"), payload.get("port")
        )
        fingerprint, confirmation = _confirmed_tls_fingerprint(
            address,
            port,
            str(payload.get("confirmed_fingerprint") or ""),
        )
        if confirmation is not None:
            return confirmation
        source_type = str(payload.get("source_type") or "")
        source_username, source_password = resolve_vcf_helper_credentials(
            db,
            identity,
            payload,
            username_field="username",
            password_field="password",
            purpose="vault_import",
        )
        try:
            candidates = discover_vcf_passwords(
                source_type=source_type,
                address=address,
                port=port,
                username=source_username,
                password=source_password,
                expected_fingerprint=fingerprint,
            )
            by_id = {candidate.candidate_id: candidate for candidate in candidates}
            missing = [
                candidate_id for candidate_id in selected if candidate_id not in by_id
            ]
            if missing:
                raise VcfDepotTargetError(
                    "The selected VCF password set changed; inspect the source again."
                )
            imported: list[str] = []
            created_count = 0
            for candidate_id in selected:
                candidate = by_id[candidate_id]
                entry, created = upsert_vault_entry(
                    db,
                    vault=vault,
                    entry=VaultEntryInput(
                        key=candidate.key,
                        description=candidate.description,
                        secret_type=candidate.secret_type,
                        value=candidate.value,
                        username=candidate.username,
                        resource_name=candidate.resource_name,
                        source_type=source_type,
                        source_endpoint=f"{address}:{port}",
                        imported_at=utcnow(),
                    ),
                    actor=identity.username,
                )
                imported.append(entry.key)
                created_count += int(created)
            db.commit()
        except (IntegrityError, VcfDepotTargetError, ValueError) as exc:
            db.rollback()
            raise HTTPException(
                status_code=422,
                detail=redact_secret_values(str(exc), [source_password]),
            ) from exc
        record_audit(
            db,
            actor=identity.username,
            action="import_vcf_vault_entries",
            resource_type="vault",
            resource_id=str(vault.id),
            detail=f"source_type={source_type}; imported={len(imported)}; created={created_count}; rotated={len(imported) - created_count}",
        )
        return JSONResponse(
            {
                "status": "imported",
                "vault_id": vault.id,
                "imported_keys": imported,
                "created": created_count,
                "rotated": len(imported) - created_count,
            },
            headers={"Cache-Control": "no-store, private", "Pragma": "no-cache"},
        )

    def _validate_vcf_sddc_property_values(
        descriptor: Any, values: dict[str, str]
    ) -> list[str]:
        """Validate vcf sddc property values.

        Args:
            descriptor: Candidate descriptor to validate.
            values: Candidate values consumed by validate VCF SDDC property values.


        Returns:
            The validate vcf sddc property values result.
        """
        properties = {item.key: item for item in descriptor.properties}
        required = {"ROOT_PASSWORD", "LOCAL_USER_PASSWORD", "vami.hostname"}
        address_version = values.get(
            "ip_address_version",
            properties.get("ip_address_version").default
            if properties.get("ip_address_version")
            else "IPv4",
        )
        if "IPv4" in str(address_version):
            required.update({"ip0", "netmask0", "gateway", "DNS"})
        if "IPv6" in str(address_version):
            required.update({"ipv6", "ipv6_prefix", "ipv6_gateway"})
        missing = [
            key
            for key in sorted(required)
            if key in properties and not values.get(key, "").strip()
        ]
        invalid = []
        for key, property_info in properties.items():
            value = values.get(key, "")
            min_match = re.search(r"MinLen\((\d+)\)", property_info.qualifiers or "")
            max_match = re.search(r"MaxLen\((\d+)\)", property_info.qualifiers or "")
            if min_match and value and len(value) < int(min_match.group(1)):
                invalid.append(
                    f"{property_info.label or key} must be at least {min_match.group(1)} characters."
                )
            if max_match and value and len(value) > int(max_match.group(1)):
                invalid.append(
                    f"{property_info.label or key} must be at most {max_match.group(1)} characters."
                )
        if missing:
            labels = [properties[key].label or key for key in missing]
            invalid.insert(0, f"Complete required OVA properties: {', '.join(labels)}.")
        return invalid

    @router.post("/vcf-helper/sddc-manager/inventory", response_model=None)
    async def vcf_sddc_manager_inventory(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Handle the vcf sddc manager inventory endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        require_vcf_helper_write(identity)
        payload = await _vcf_helper_json(request)
        address, port = _split_vcf_endpoint_address_port(
            payload.get("address"), payload.get("port")
        )
        if not address:
            raise HTTPException(status_code=422, detail="Target address is required.")
        fingerprint, confirmation = _confirmed_tls_fingerprint(
            address, port, str(payload.get("confirmed_tls_fingerprint") or "")
        )
        if confirmation:
            return confirmation
        username, password = resolve_vcf_helper_credentials(
            db,
            identity,
            payload,
            username_field="username",
            password_field="password",
            purpose="sddc_inventory",
        )
        if not address or not username or not password:
            raise HTTPException(
                status_code=422,
                detail="Target address, username, and password are required.",
            )
        try:
            descriptor = inspect_ova(str(payload.get("ova_path") or ""))
            inventory = vsphere_inventory(
                address,
                username,
                password,
                port=port,
                expected_fingerprint=fingerprint,
                descriptor=descriptor,
                deployment_option=str(payload.get("deployment_option") or ""),
            )
        except VcfSddcDeploymentError as exc:
            raise HTTPException(
                status_code=422,
                detail=redact_secret_values(str(exc), [password]),
            ) from exc
        return JSONResponse(
            {
                "status": "ready",
                "tls_fingerprint": fingerprint,
                "inventory": inventory,
                "ova": inventory.pop("ova", descriptor.public_dict()),
            }
        )

    @router.post("/vcf-helper/sddc-manager/deploy", response_model=None)
    async def deploy_vcf_sddc_manager_from_ui(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Handle the deploy vcf sddc manager from ui endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        require_vcf_helper_write(identity)
        payload = await _vcf_helper_json(request)
        address, port = _split_vcf_endpoint_address_port(
            payload.get("address"), payload.get("port")
        )
        if not address:
            raise HTTPException(status_code=422, detail="Target address is required.")
        _fingerprint, confirmation = _confirmed_tls_fingerprint(
            address, port, str(payload.get("confirmed_tls_fingerprint") or "")
        )
        if confirmation:
            return confirmation
        username, password = resolve_vcf_helper_credentials(
            db,
            identity,
            payload,
            username_field="username",
            password_field="password",
            purpose="sddc_deploy",
        )
        if not address or not username or not password:
            raise HTTPException(
                status_code=422,
                detail="Target address, username, and password are required.",
            )
        try:
            descriptor = inspect_ova(str(payload.get("ova_path") or ""))
        except VcfSddcDeploymentError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        raw_properties = payload.get("properties") or {}
        if not isinstance(raw_properties, dict):
            raise HTTPException(
                status_code=422, detail="OVA properties must be an object."
            )
        submitted_properties = {str(key): str(value) for key, value in raw_properties.items()}
        deployment_option = str(payload.get("deployment_option") or "")
        try:
            descriptor = vsphere_ovf_descriptor(
                address,
                username,
                password,
                descriptor,
                port=port,
                expected_fingerprint=str(payload.get("confirmed_tls_fingerprint") or ""),
                deployment_option=deployment_option,
                property_values=submitted_properties,
            )
            property_values = complete_property_mapping(descriptor, submitted_properties)
        except VcfSddcDeploymentError as exc:
            raise HTTPException(
                status_code=422,
                detail=redact_secret_values(str(exc), [password, *submitted_properties.values()]),
            ) from exc
        invalid_properties = _validate_vcf_sddc_property_values(
            descriptor, property_values
        )
        if invalid_properties:
            raise HTTPException(status_code=422, detail=" ".join(invalid_properties))
        destination = payload.get("destination") or {}
        if (
            not isinstance(destination, dict)
            or not destination.get("resource_pool_id")
            or not destination.get("datastore_id")
        ):
            raise HTTPException(
                status_code=422, detail="Select a resource pool and datastore."
            )
        network_ids = destination.get("network_ids") or {}
        if any(
            not str(dict(network_ids).get(name) or "") for name in descriptor.networks
        ):
            raise HTTPException(
                status_code=422, detail="Map every OVA network before deployment."
            )
        options = payload.get("options") or {}
        if not isinstance(options, dict):
            options = {}
        power_on = bool(options.get("power_on", True))
        add_dns = bool(options.get("add_dns"))
        apply_trust = bool(options.get("apply_trust")) if power_on else False
        configure_offline_depot = (
            bool(options.get("configure_offline_depot")) if power_on else False
        )
        if not power_on and any(
            bool(options.get(key)) for key in ("apply_trust", "configure_offline_depot")
        ):
            raise HTTPException(
                status_code=422,
                detail="VCF certificate trust and offline depot configuration require Power on after deployment.",
            )
        try:
            disk_provisioning = normalize_disk_provisioning(
                str(options.get("disk_provisioning") or "thin")
            )
        except VcfSddcDeploymentError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        depot_password = str(payload.get("depot_password") or "")
        if configure_offline_depot:
            local = local_vcf_depot_target_context(db)
            if not local["available"]:
                raise HTTPException(status_code=422, detail=" ".join(local["reasons"]))
            if not depot_password:
                raise HTTPException(
                    status_code=422,
                    detail="Enter the one-time local depot HTTP password.",
                )
        vm_name = str(payload.get("vm_name") or descriptor.vm_name).strip()
        if not vm_name:
            raise HTTPException(
                status_code=422, detail="Virtual machine name is required."
            )
        job = Job(
            id=f"job_{uuid4().hex[:12]}",
            type="vcf-sddc-manager-deploy",
            status=JobStatus.PENDING.value,
            created_by=identity.username,
            progress_percent=0,
            result=json.dumps(
                {
                    "state": "queued",
                    "ova": descriptor.relative_path,
                    "vm_name": vm_name,
                    "endpoint": address,
                    "disk_provisioning": disk_provisioning,
                    "deployment_option": descriptor.selected_deployment_option,
                    "power_on": power_on,
                    "property_keys": sorted(property_values),
                    "password_property_keys": sorted(
                        item.key
                        for item in descriptor.properties
                        if item.password and item.key in property_values
                    ),
                    "options": {
                        "add_dns": add_dns,
                        "apply_trust": apply_trust,
                        "configure_offline_depot": configure_offline_depot,
                    },
                },
                sort_keys=True,
            ),
        )
        db.add(job)
        db.commit()
        queue_vcf_sddc_deployment_job(
            job.id,
            ova_path=descriptor.path,
            endpoint=address,
            endpoint_username=username,
            endpoint_password=password,
            endpoint_fingerprint=str(payload.get("confirmed_tls_fingerprint") or ""),
            destination={**destination, "port": port},
            vm_name=vm_name,
            disk_provisioning=disk_provisioning,
            deployment_option=descriptor.selected_deployment_option,
            power_on=power_on,
            property_values=property_values,
            add_dns=add_dns,
            apply_trust=apply_trust,
            configure_offline_depot=configure_offline_depot,
            depot_password=depot_password,
        )
        record_audit(
            db,
            actor=identity.username,
            action="queue_vcf_sddc_manager_deployment",
            resource_type="job",
            resource_id=job.id,
            detail=f"ova={descriptor.relative_path}; vm_name={vm_name}; endpoint={address}",
        )
        return JSONResponse({"status": "queued", "job_id": job.id}, status_code=202)

    @router.get("/vcf-helper/sddc-manager/tasks/{job_id}", response_model=None)
    def vcf_sddc_manager_task_status(
        job_id: str,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Handle the vcf sddc manager task status endpoint.

        Args:
            job_id: Identifier of the job.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        require_vcf_helper_write(identity)
        job = db.get(Job, job_id)
        if not job or job.type != "vcf-sddc-manager-deploy":
            raise HTTPException(
                status_code=404, detail="SDDC Manager deployment task not found."
            )
        return JSONResponse(
            {
                "job_id": job.id,
                "status": job.status,
                "progress_percent": job.progress_percent,
                "error": job.error or "",
                "result": _job_payload(job),
            }
        )

    @router.post("/vcf-helper/offline-depot/inspect-target", response_model=None)
    async def inspect_vcf_offline_depot_target_from_ui(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Handle the inspect vcf offline depot target from ui endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If authorization, target validation, or target inspection fails.
        """
        require_vcf_helper_write(identity)
        payload = await _vcf_helper_json(request)
        local = local_vcf_depot_target_context(db)
        if not local["available"]:
            raise HTTPException(status_code=422, detail=" ".join(local["reasons"]))
        try:
            address, port = _split_vcf_endpoint_address_port(
                payload.get("address"), payload.get("port")
            )
        except HTTPException as exc:
            raise exc
        if not address:
            raise HTTPException(status_code=422, detail="Target address is required.")
        fingerprint, confirmation = _confirmed_tls_fingerprint(
            address, port, str(payload.get("confirmed_tls_fingerprint") or "")
        )
        if confirmation:
            return confirmation
        api_username, api_password = resolve_vcf_helper_credentials(
            db,
            identity,
            payload,
            username_field="api_username",
            password_field="api_password",
            purpose="offline_depot_inspect",
        )
        try:
            target = inspect_target_depot(
                address,
                api_username,
                api_password,
                port=port,
                expected_fingerprint=fingerprint,
            )
        except VcfDepotTargetError as exc:
            raise HTTPException(
                status_code=422,
                detail=redact_secret_values(str(exc), [api_password]),
            ) from exc
        current = target["depot"]
        replacement_required = bool(
            current.get("hostname") or current.get("url") or current.get("username")
        ) and not (
            str(current.get("hostname") or "").lower() == str(local["hostname"]).lower()
            and int(current.get("port") or 0) == int(local["port"])
        )
        return JSONResponse(
            {
                "status": "ready",
                "address": address,
                "port": port,
                "tls_fingerprint": fingerprint,
                "target": target,
                "local_depot": {
                    key: local[key] for key in ("hostname", "port", "url", "username")
                },
                "replacement_required": replacement_required,
            }
        )

    @router.post("/vcf-helper/offline-depot/configure", response_model=None)
    async def configure_vcf_offline_depot_target_from_ui(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Handle the configure vcf offline depot target from ui endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If authorization, target validation, or target configuration fails.
        """
        require_vcf_helper_write(identity)
        payload = await _vcf_helper_json(request)
        local = local_vcf_depot_target_context(db)
        if not local["available"]:
            raise HTTPException(status_code=422, detail=" ".join(local["reasons"]))
        try:
            address, port = _split_vcf_endpoint_address_port(
                payload.get("address"), payload.get("port")
            )
        except HTTPException as exc:
            raise exc
        if not address:
            raise HTTPException(status_code=422, detail="Target address is required.")
        fingerprint, confirmation = _confirmed_tls_fingerprint(
            address, port, str(payload.get("confirmed_tls_fingerprint") or "")
        )
        if confirmation:
            return confirmation
        api_username, api_password = resolve_vcf_helper_credentials(
            db,
            identity,
            payload,
            username_field="api_username",
            password_field="api_password",
            purpose="offline_depot_configure",
        )
        depot_password = str(payload.get("depot_password") or "")
        if not address or not api_username or not api_password or not depot_password:
            raise HTTPException(
                status_code=422,
                detail="Target API credentials and the one-time depot password are required.",
            )
        replace_existing = bool(payload.get("replace_existing"))
        try:
            current = inspect_target_depot(
                address,
                api_username,
                api_password,
                port=port,
                expected_fingerprint=fingerprint,
            )["depot"]
        except VcfDepotTargetError as exc:
            raise HTTPException(
                status_code=422,
                detail=redact_secret_values(str(exc), [api_password, depot_password]),
            ) from exc
        has_different = bool(
            current.get("hostname") or current.get("url") or current.get("username")
        ) and not (
            str(current.get("hostname") or "").lower() == str(local["hostname"]).lower()
            and int(current.get("port") or 0) == int(local["port"])
        )
        if has_different and not replace_existing:
            return JSONResponse(
                {"status": "replacement-confirmation-required", "current": current},
                status_code=409,
            )
        job = Job(
            id=f"job_{uuid4().hex[:12]}",
            type="vcf-offline-depot-target-config",
            status=JobStatus.PENDING.value,
            created_by=identity.username,
            progress_percent=0,
            result=json.dumps(
                {
                    "state": "queued",
                    "target": address,
                    "port": port,
                    "local_depot": {
                        key: local[key]
                        for key in ("hostname", "port", "url", "username")
                    },
                },
                sort_keys=True,
            ),
        )
        db.add(job)
        db.commit()
        queue_vcf_target_depot_job(
            job.id,
            address=address,
            port=port,
            api_username=api_username,
            api_password=api_password,
            depot_password=depot_password,
            replace_existing=replace_existing,
            expected_fingerprint=fingerprint,
        )
        record_audit(
            db,
            actor=identity.username,
            action="queue_vcf_offline_depot_target_configuration",
            resource_type="job",
            resource_id=job.id,
            detail=f"target={address}:{port}; depot={local['hostname']}:{local['port']}",
        )
        return JSONResponse(
            {
                "status": "queued",
                "job_id": job.id,
                "redirect": f"/tasks?job_id={job.id}",
            },
            status_code=202,
        )

    @router.get("/vcf-helper/offline-depot/tasks/{job_id}", response_model=None)
    def vcf_offline_depot_target_task_status(
        job_id: str,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Handle the vcf offline depot target task status endpoint.

        Args:
            job_id: Identifier of the job.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        require_vcf_helper_write(identity)
        job = db.get(Job, job_id)
        if not job or job.type != "vcf-offline-depot-target-config":
            raise HTTPException(
                status_code=404, detail="VCF Offline Depot target task not found."
            )
        return JSONResponse(
            {
                "job_id": job.id,
                "status": job.status,
                "progress_percent": job.progress_percent,
                "error": job.error or "",
                "result": _job_payload(job),
            }
        )

    @router.get("/vcf-trust", response_class=HTMLResponse, response_model=None)
    def vcf_trust_page(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Handle the vcf trust page endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        return RedirectResponse("/vcf-helper?vcf_trust=1", status_code=307)

    @router.post("/vcf-helper/trust-root-ca/inspect-target", response_model=None)
    async def inspect_vcf_trust_target_from_ui(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Handle the inspect vcf trust target from ui endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        require_vcf_helper_write(identity)
        payload = await _vcf_helper_json(request)
        try:
            address, port = _split_vcf_endpoint_address_port(
                payload.get("address"), payload.get("port")
            )
        except HTTPException as exc:
            return JSONResponse(
                {"status": "error", "errors": [str(exc.detail)]},
                status_code=exc.status_code,
            )
        normalized_address, errors = _normalize_vcf_trust_address(address)
        if errors:
            return JSONResponse({"status": "error", "errors": errors}, status_code=422)
        fingerprint, confirmation = _confirmed_tls_fingerprint(
            normalized_address,
            port,
            str(payload.get("confirmed_tls_fingerprint") or ""),
        )
        if confirmation:
            return confirmation
        api_username, api_password = resolve_vcf_helper_credentials(
            db,
            identity,
            payload,
            username_field="api_username",
            password_field="api_password",
            purpose="trust_inspect",
        )
        if not api_username or not api_password:
            return JSONResponse(
                {
                    "status": "error",
                    "errors": ["VCF API administrator credentials are required."],
                },
                status_code=422,
            )
        try:
            appliance = inspect_vcf_trust_target(
                normalized_address,
                port,
                VcfTrustCredentials(
                    api_username=api_username, api_password=api_password
                ),
                expected_fingerprint=fingerprint,
            )
        except VcfTrustError:
            return JSONResponse(
                {
                    "status": "error",
                    "errors": [
                        "Could not inspect the target VCF API. Verify the endpoint, credentials, and TLS fingerprint."
                    ],
                },
                status_code=422,
            )
        return JSONResponse(
            {
                "status": "ready",
                "address": normalized_address,
                "port": port,
                "tls_fingerprint": fingerprint,
                "appliance": appliance,
            }
        )

    @router.post("/vcf-trust/root-ca", response_model=None)
    @router.post("/vcf-helper/trust-root-ca", response_model=None)
    def trust_vcf_root_ca_from_ui(
        request: Request,
        address: str = Form(...),
        api_username: str = Form(""),
        api_password: str = Form(""),
        credential_vault_id: str = Form(""),
        credential_entry_id: str = Form(""),
        confirmed_tls_fingerprint: str = Form(""),
        awaiting_job_id: str = Form(""),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse | RedirectResponse | JSONResponse:
        """Handle the trust vcf root ca from ui endpoint.

        Args:
            request: Incoming HTTP request.
            address: Network address of the target service or interface.
            api_username: Api username supplied by the caller.
            api_password: Api password supplied by the caller.
            credential_vault_id: Identifier of the credential vault.
            credential_entry_id: Identifier of the credential entry.
            confirmed_tls_fingerprint: Confirmed tls fingerprint supplied by the caller.
            awaiting_job_id: Identifier of the awaiting job.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        require_vcf_helper_write(identity)
        verify_csrf(request, csrf)
        try:
            endpoint_address, port = _split_vcf_endpoint_address_port(address, None)
        except HTTPException as exc:
            endpoint_address = ""
            port = 443
            errors = [str(exc.detail)]
        else:
            normalized_address, errors = _normalize_vcf_trust_address(endpoint_address)
        try:
            ca = root_ca_info(get_ca_settings_row(db))
        except VcfTrustError as exc:
            errors.append(str(exc))
            ca = None
        if not errors:
            try:
                fingerprint, confirmation = _confirmed_tls_fingerprint(
                    normalized_address, port, confirmed_tls_fingerprint
                )
            except Exception as exc:  # noqa: BLE001 - surfaced as sanitized form validation.
                errors.append(str(exc))
                fingerprint = ""
                confirmation = None
            if confirmation:
                if request.headers.get("X-Atlaso-VCF-Trust") == "1":
                    return confirmation
                errors.append(
                    "Confirm the VCF appliance HTTPS TLS fingerprint before queueing the task."
                )
        if not errors:
            api_username, api_password = resolve_vcf_helper_credentials(
                db,
                identity,
                {
                    "api_username": api_username,
                    "api_password": api_password,
                    "credential_vault_id": credential_vault_id,
                    "credential_entry_id": credential_entry_id,
                },
                username_field="api_username",
                password_field="api_password",
                purpose="trust_queue",
            )
            if not api_username.strip() or not api_password:
                errors.append("VCF API administrator credentials are required.")

        if errors:
            if request.headers.get("X-Atlaso-VCF-Trust") == "1":
                return JSONResponse(
                    {"status": "error", "errors": errors}, status_code=422
                )
            page_context = vcf_helper_page_context(
                db,
                identity,
                vcf_trust_auto_open=True,
                extra={"vcf_trust_errors": errors},
            )
            return render(request, "vcf_helper.html", page_context, status_code=422)

        assert ca is not None
        target = _vcf_trust_target(db, normalized_address, port)
        target.api_port = port
        target.tls_fingerprint = fingerprint
        target.updated_at = utcnow()
        job = db.get(Job, awaiting_job_id) if awaiting_job_id else None
        if not job or job.type != "vcf-ca-trust" or job.created_by != identity.username:
            job = Job(
                id=f"job_{uuid4().hex[:12]}",
                type="vcf-ca-trust",
                status=JobStatus.PENDING.value,
                created_by=identity.username,
            )
            db.add(job)
        else:
            job.status = JobStatus.PENDING.value
        job.result = sanitized_result(
            address=normalized_address,
            port=port,
            ca=ca,
            state="queued",
            tls_fingerprint=target.tls_fingerprint,
        )
        target.last_job_id = job.id
        db.commit()
        credentials = VcfTrustCredentials(
            api_username=api_username.strip(),
            api_password=api_password,
        )
        record_audit(
            db,
            actor=identity.username,
            action="queue_vcf_root_ca_import",
            resource_type="job",
            resource_id=job.id,
            detail=f"target={normalized_address}:{port}; ca_fingerprint={ca.fingerprint}",
        )
        queue_vcf_trust_job(job.id, target.id, credentials, ca)
        if request.headers.get("X-Atlaso-VCF-Trust") == "1":
            return JSONResponse(
                {
                    "status": "queued",
                    "job_id": job.id,
                    "redirect": f"/tasks?job_id={job.id}",
                },
                status_code=202,
            )
        return RedirectResponse(f"/tasks?job_id={job.id}", status_code=303)

    @router.post("/vcf-helper/generated-fqdns/populate", response_model=None)
    def populate_vcf_fqdns_from_ui(
        request: Request,
        target: str = Form(VCF_HELPER_DEFAULT_TARGET),
        domain: str = Form(...),
        prefix: str = Form(""),
        suffix: str = Form(""),
        start_ipv4: str = Form(...),
        network_prefix: str = Form(""),
        component_key: list[str] | None = Form(None),
        hostname: list[str] | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Validate and stage one non-mutating generated-FQDN review.

        Args:
            request: Incoming HTTP request.
            target: Selected deployment catalog.
            domain: Managed DNS domain selected for generated records.
            prefix: Optional generated-hostname prefix.
            suffix: Optional generated-hostname suffix.
            start_ipv4: Starting IPv4 or IPv6 CIDR.
            network_prefix: Legacy separate network prefix.
            component_key: Immutable catalog component keys.
            hostname: Reviewed hostname labels paired with component keys.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity staging the review.
            db: Active database session.

        Returns:
            A non-mutating allocation preview and exact signed input revision.
        """
        verify_csrf(request, csrf)
        component_keys = component_key or []
        hostnames = hostname or []
        planned, skipped, errors = allocate_vcf_generated_records(
            db,
            target=target,
            domain=domain,
            prefix=prefix,
            suffix=suffix,
            start_ipv4=start_ipv4,
            network_prefix=network_prefix,
            component_keys=component_keys,
            hostnames=hostnames,
        )
        if errors:
            return JSONResponse(
                {"status": "error", "planned": [], "skipped": skipped, "errors": errors},
                status_code=422,
            )
        revision = _vcf_fqdn_input_revision(
            actor=identity.username,
            target=target,
            domain=domain,
            prefix=prefix,
            suffix=suffix,
            start_ipv4=start_ipv4,
            network_prefix=network_prefix,
            component_keys=component_keys,
            hostnames=hostnames,
        )
        return JSONResponse(
            {
                "status": "populated",
                "planned": planned,
                "skipped": skipped,
                "populated_revision": _vcf_fqdn_population_token(**revision),
            }
        )

    @router.post("/vcf-helper/generated-fqdns", response_model=None)
    def generate_vcf_fqdns_from_ui(
        request: Request,
        target: str = Form(VCF_HELPER_DEFAULT_TARGET),
        domain: str = Form(...),
        prefix: str = Form(""),
        suffix: str = Form(""),
        start_ipv4: str = Form(...),
        network_prefix: str = Form(""),
        component_key: list[str] | None = Form(None),
        hostname: list[str] | None = Form(None),
        populated_revision: str = Form(""),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse | JSONResponse:
        """Handle the generate vcf fqdns from ui endpoint.

        Args:
            request: Incoming HTTP request.
            target: Resource targeted by the operation.
            domain: Managed DNS domain affected by the operation.
            prefix: Prefix supplied by the caller.
            suffix: Suffix supplied by the caller.
            start_ipv4: Start ipv4 supplied by the caller.
            network_prefix: Network prefix supplied by the caller.
            component_key: Catalog component keys submitted by the caller.
            hostname: Reviewed hostname labels paired with the submitted component keys.
            populated_revision: Signed exact input revision returned by Populate.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        component_keys = component_key or []
        hostnames = hostname or []
        revision = _vcf_fqdn_input_revision(
            actor=identity.username,
            target=target,
            domain=domain,
            prefix=prefix,
            suffix=suffix,
            start_ipv4=start_ipv4,
            network_prefix=network_prefix,
            component_keys=component_keys,
            hostnames=hostnames,
        )
        if not _vcf_fqdn_population_matches(populated_revision, **revision):
            errors = [
                "Select Populate and review the current generated FQDN plan before creating DNS records."
            ]
            if request.headers.get("X-Atlaso-VCF-Helper") == "1":
                return JSONResponse(
                    {"status": "error", "created": [], "skipped": [], "errors": errors},
                    status_code=422,
                )
            page_context = vcf_submitted_fqdn_page_context(
                db,
                identity,
                target=target,
                domain=domain,
                prefix=prefix,
                suffix=suffix,
                start_ipv4=start_ipv4,
                component_keys=component_keys,
                hostnames=hostnames,
            )
            return render(
                request,
                "vcf_helper.html",
                {**page_context, "vcf_helper_errors": errors},
                status_code=422,
            )
        created, skipped, errors = create_vcf_generated_dns_records(
            db,
            target=target,
            domain=domain,
            prefix=prefix,
            suffix=suffix,
            start_ipv4=start_ipv4,
            network_prefix=network_prefix,
            component_keys=component_keys,
            hostnames=hostnames,
            actor=identity.username,
        )
        if request.headers.get("X-Atlaso-VCF-Helper") == "1":
            return JSONResponse(
                {
                    "status": "error" if errors else "saved",
                    "created": created,
                    "skipped": skipped,
                    "errors": errors,
                },
                status_code=422 if errors else 200,
            )
        page_context = vcf_submitted_fqdn_page_context(
            db,
            identity,
            target=target,
            domain=domain,
            prefix=prefix,
            suffix=suffix,
            start_ipv4=start_ipv4,
            component_keys=component_keys,
            hostnames=hostnames,
        )
        if errors:
            return render(
                request,
                "vcf_helper.html",
                {**page_context, "vcf_helper_errors": errors},
                status_code=422,
            )
        return render(
            request,
            "vcf_helper.html",
            {
                **page_context,
                "vcf_helper_result": {"created": created, "skipped": skipped},
            },
        )

    @router.post("/vcf-helper/generated-fqdns/delete", response_model=None)
    def delete_vcf_fqdns_from_ui(
        request: Request,
        target: str = Form(VCF_HELPER_DEFAULT_TARGET),
        domain: str = Form(...),
        prefix: str = Form(""),
        suffix: str = Form(""),
        component_key: list[str] | None = Form(None),
        hostname: list[str] | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse | JSONResponse:
        """Handle the delete vcf fqdns from ui endpoint.

        Args:
            request: Incoming HTTP request.
            target: Resource targeted by the operation.
            domain: Managed DNS domain affected by the operation.
            prefix: Prefix supplied by the caller.
            suffix: Suffix supplied by the caller.
            component_key: Catalog component keys submitted by the caller.
            hostname: Reviewed hostname labels paired with the submitted component keys.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        deleted, preserved, errors = delete_vcf_generated_dns_records(
            db,
            target=target,
            domain=domain,
            prefix=prefix,
            suffix=suffix,
            component_keys=component_key or [],
            hostnames=hostname or [],
            actor=identity.username,
        )
        if request.headers.get("X-Atlaso-VCF-Helper") == "1":
            return JSONResponse(
                {
                    "status": "error" if errors else "deleted",
                    "deleted": deleted,
                    "preserved": preserved,
                    "errors": errors,
                },
                status_code=422 if errors else 200,
            )
        page_context = vcf_submitted_fqdn_page_context(
            db,
            identity,
            target=target,
            domain=domain,
            prefix=prefix,
            suffix=suffix,
            start_ipv4="",
            component_keys=component_key or [],
            hostnames=hostname or [],
        )
        if errors:
            return render(
                request,
                "vcf_helper.html",
                {**page_context, "vcf_helper_errors": errors},
                status_code=422,
            )
        return render(
            request,
            "vcf_helper.html",
            {
                **page_context,
                "vcf_helper_delete_result": {
                    "deleted": deleted,
                    "preserved": preserved,
                },
            },
        )

    @router.get("/vcf-offline-depot", response_class=HTMLResponse, response_model=None)
    def vcf_offline_depot_page(
        request: Request,
        schedule_profile_id: int | None = Query(None),
        schedule_invalid: bool = Query(False),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the vcf offline depot page endpoint.

        Args:
            request: Incoming HTTP request.
            schedule_profile_id: Optional profile selected by the no-script schedule fallback.
            schedule_invalid: Whether fixed validation feedback is shown for the no-script fallback.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        jobs = (
            db.execute(
                select(Job)
                .options(selectinload(Job.steps))
                .where(Job.type == "vcf-depot-download")
                .order_by(desc(Job.created_at))
                .limit(500)
            )
            .scalars()
            .all()
        )
        schedule_profile = (
            db.get(VcfDepotDownloadProfile, schedule_profile_id)
            if schedule_profile_id is not None
            else None
        )
        schedule_error = str(getattr(request.state, "vcf_schedule_error", ""))
        if not schedule_error and schedule_invalid:
            schedule_error = (
                "Review the schedule fields and provide a valid timing definition."
            )
        schedule_form = getattr(request.state, "vcf_schedule_form", {})
        if not isinstance(schedule_form, dict):
            schedule_form = {}
        schedule_read_only = False
        if schedule_profile is not None and not schedule_profile.enabled:
            if schedule_error and schedule_form:
                schedule_read_only = True
            else:
                schedule_profile = None
                schedule_error = (
                    "Enable the VCFDT download profile before scheduling it."
                )
        schedule_unavailable_error = schedule_error if schedule_profile is None else ""
        return render(
            request,
            "vcf_offline_depot.html",
            {
                "identity": identity,
                **vcf_offline_depot_context(db),
                "vcf_depot_task_rows": [_task_row(job, identity) for job in jobs],
                "vcf_depot_task_component_options": ["VCF Depot Download"],
                "appliance_apply_status": appliance_apply_status(
                    db, "vcf_offline_depot"
                ),
                "vcf_depot_contextual_schedule_profile": schedule_profile,
                "vcf_depot_contextual_schedule_error": schedule_error,
                "vcf_depot_contextual_schedule_form": schedule_form,
                "vcf_depot_contextual_schedule_read_only": schedule_read_only,
                "vcf_depot_contextual_schedule_unavailable_error": schedule_unavailable_error,
            },
        )

    @router.get(
        "/vcf-offline-depot/tasks/{job_id}/log",
        response_class=HTMLResponse,
        response_model=None,
    )
    def vcf_offline_depot_task_log_page(
        job_id: str,
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the vcf offline depot task log page endpoint.

        Args:
            job_id: Identifier of the job.
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        job = db.get(Job, job_id)
        if job is None or job.type != "vcf-depot-download":
            raise HTTPException(status_code=404, detail="VCFDT task not found.")
        profile_name = ""
        try:
            profile_name = str(json.loads(job.result or "{}").get("profile_name") or "")
        except json.JSONDecodeError:
            pass
        if job.status == JobStatus.RUNNING.value:
            task_log = tail_fixed_log_file(VCF_DEPOT_VDT_LOG_PATH)
        else:
            task_log = tail_fixed_log_file(
                Path(
                    str(
                        json.loads(job.result or "{}").get("log_path")
                        or vcf_depot_task_log_path(job.id, profile_name)
                    )
                )
            )
        if request.headers.get("X-Atlaso-Task-Log") == "1":
            return JSONResponse(
                {
                    "job_id": job.id,
                    "profile_name": profile_name,
                    "status": job.status,
                    "path": task_log["path"],
                    "updated_at": task_log.get("updated_at", ""),
                    "available": task_log["available"],
                    "text": "\n".join(task_log["lines"])
                    if task_log["available"]
                    else "No task log is available.",
                }
            )
        return render(
            request,
            "vcf_offline_depot_task_log.html",
            {
                "identity": identity,
                "job": job,
                "profile_name": profile_name,
                "task_log": task_log,
            },
        )

    @router.get("/vcf-offline-depot/tasks/status", response_model=None)
    def vcf_offline_depot_task_status(
        page: int = Query(1, ge=1),
        size: int = Query(10, ge=5, le=100),
        _identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Handle the vcf offline depot task status endpoint.

        Args:
            page: Page supplied by the caller.
            size: Size supplied by the caller.
            _identity: Authenticated identity supplied by the dependency layer.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        tasks, total = vcf_depot_download_job_rows(db, page=page, page_size=size)
        active_jobs = active_vcf_depot_download_jobs(db)
        active_job = active_jobs[0] if active_jobs else None
        exclusive_job = active_vcf_depot_exclusive_job(db)
        last_page = max(1, (total + size - 1) // size)
        return JSONResponse(
            {
                "data": tasks,
                "tasks": tasks,
                "last_page": last_page,
                "last_row": total,
                "download_active": active_job is not None,
                "active_job_id": active_job.id if active_job is not None else "",
                "active_downloads": [
                    {
                        "job_id": job.id,
                        "profile_id": vcf_depot_job_profile_id(job),
                        "status": job.status,
                    }
                    for job in active_jobs
                ],
                "profile_start_states": vcf_depot_profile_start_states(db),
                "active_exclusive_operation": (
                    {
                        "job_id": exclusive_job.id,
                        "status": exclusive_job.status,
                        "type": exclusive_job.type,
                        "detail": vcf_depot_execution_conflict_detail(exclusive_job),
                    }
                    if exclusive_job is not None
                    else None
                ),
            }
        )

    @router.post("/vcf-offline-depot/settings", response_model=None)
    def update_vcf_offline_depot_settings_from_ui(
        request: Request,
        enabled: str | None = Form(None),
        hostname: str = Form(""),
        listen_interfaces: list[str] = Form(default_factory=list),
        listen_addresses: list[str] = Form(default_factory=list),
        listen_interfaces_present: str | None = Form(None),
        listen_addresses_present: str | None = Form(None),
        listen_interface: str = Form(""),
        listen_address: str = Form(""),
        port: int = Form(443),
        http_user_id: str = Form(""),
        allow_unauthenticated_access: str | None = Form(None),
        server_certificate: str | None = Form(None),
        tool_archive_file: UploadFile | None = File(None),
        download_token_file: UploadFile | None = File(None),
        activation_code_file: UploadFile | None = File(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the update vcf offline depot settings from ui endpoint.

        Args:
            request: Incoming HTTP request.
            enabled: Whether the requested behavior is enabled.
            hostname: DNS hostname of the target resource.
            listen_interfaces: Interfaces on which the service should listen.
            listen_addresses: Addresses on which the service should listen.
            listen_interfaces_present: Whether the caller supplied listen interfaces.
            listen_addresses_present: Whether the caller supplied listen addresses.
            listen_interface: Interface on which the service should listen.
            listen_address: Address on which the service should listen.
            port: TCP or UDP port of the target service.
            http_user_id: Identifier of the http user.
            allow_unauthenticated_access: Allow unauthenticated access supplied by the caller.
            server_certificate: Server certificate supplied by the caller.
            tool_archive_file: Tool archive file supplied by the caller.
            download_token_file: Download token file supplied by the caller.
            activation_code_file: Activation code file supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        settings = get_vcf_offline_depot_settings_row(db, reconcile_default_user=False)
        previous_hostname = settings.hostname
        user_id = int(http_user_id) if str(http_user_id).strip() else None
        if user_id and not db.get(User, user_id):
            raise HTTPException(
                status_code=400,
                detail="Selected VCF Offline Depot HTTP user does not exist.",
            )
        selected_interfaces, selected_addresses = resolve_service_bind_targets(
            db,
            [*listen_interfaces, listen_interface],
            [*listen_addresses, listen_address],
            current_interface=settings.listen_interface,
            current_address=settings.listen_address,
            listen_interfaces_present=listen_interfaces_present,
            listen_addresses_present=listen_addresses_present,
        )

        settings.enabled = enabled == "on"
        settings.hostname = hostname.strip() or settings.hostname
        settings.listen_interface = selected_interfaces
        settings.listen_address = selected_addresses
        settings.port = port
        settings.http_user_id = user_id
        settings.allow_unauthenticated_access = allow_unauthenticated_access == "on"
        settings.server_certificate = settings.hostname
        settings.depot_store_path = VCF_DEPOT_DEFAULT_STORE_PATH
        settings.config_path = VCF_DEPOT_DEFAULT_CONFIG_PATH
        uploaded_archive_name = store_uploaded_vcf_depot_archive(
            settings, tool_archive_file
        )
        uploaded_token_name = store_uploaded_vcf_depot_secret(
            db,
            download_token_file,
            name_key=VCF_DEPOT_TOKEN_NAME_KEY,
            value_key=VCF_DEPOT_TOKEN_VALUE_KEY,
            actor=identity.username,
            action="upload_vcf_depot_download_token",
        )
        uploaded_activation_name = store_uploaded_vcf_depot_secret(
            db,
            activation_code_file,
            name_key=VCF_DEPOT_ACTIVATION_NAME_KEY,
            value_key=VCF_DEPOT_ACTIVATION_VALUE_KEY,
            actor=identity.username,
            action="upload_vcf_depot_activation_code",
        )
        settings.updated_at = utcnow()
        selected_user = db.get(User, user_id) if user_id else None
        if (
            settings.enabled
            and selected_user
            and selected_user.username == VCF_DEPOT_DEFAULT_USERNAME
            and not selected_user.enabled
        ):
            if (
                has_pending_os_password(selected_user)
                or selected_user.os_password_applied_at
            ):
                selected_user.enabled = True
                selected_user.os_sync_status = "pending"
                db.add(selected_user)
        disabled_default_user = disable_default_vcf_depot_user_when_service_off(
            db, settings, actor=identity.username
        )
        dns_record_action = ensure_dns_for_vcf_offline_depot(
            db, settings, identity.username, previous_hostname=previous_hostname
        )
        db.commit()
        if uploaded_token_name or uploaded_activation_name:
            stage_vcf_depot_runtime_secrets_after_upload(db)
        record_audit(
            db,
            actor=identity.username,
            action="update_vcf_offline_depot_settings",
            resource_type="vcf_offline_depot",
            resource_id=str(settings.id),
        )
        if disabled_default_user:
            record_audit(
                db,
                actor=identity.username,
                action="disable_vcf_depot_default_user",
                resource_type="user",
                resource_id=str(user_id or ""),
            )

        if request.headers.get("X-Atlaso-Autosave") == "1":
            context = vcf_offline_depot_context(db)
            saved_settings = context["vcf_depot_settings"]
            validation_errors = context["vcf_depot_validation_errors"]
            validation_warnings = context["vcf_depot_validation_warnings"]
            token_state = context["vcf_depot_download_token"]
            activation_state = context["vcf_depot_activation_code"]
            application_properties = context["vcf_depot_application_properties"]
            software_depot_id = context["vcf_depot_software_depot_id"]
            return JSONResponse(
                {
                    "status": "saved",
                    "updated_at": saved_settings.updated_at.isoformat(),
                    "hostname": saved_settings.hostname,
                    "endpoint": context["vcf_depot_endpoint"],
                    "listen_interface": primary_listen_interface(
                        saved_settings.listen_interface
                    ),
                    "listen_address": primary_listen_address(
                        saved_settings.listen_address
                    ),
                    "listen_interfaces": split_interfaces(
                        saved_settings.listen_interface
                    ),
                    "listen_addresses": split_addresses(saved_settings.listen_address),
                    "port": saved_settings.port,
                    "http_username": saved_settings.http_user.username
                    if saved_settings.http_user
                    else "",
                    "allow_unauthenticated_access": saved_settings.allow_unauthenticated_access,
                    "server_certificate": saved_settings.server_certificate,
                    "depot_store_path": saved_settings.depot_store_path,
                    "tool_archive_name": uploaded_archive_name
                    or Path(saved_settings.tool_archive_path).name
                    if saved_settings.tool_archive_path
                    else "",
                    "tool_archive_uploaded": bool(uploaded_archive_name),
                    "tool_version": context["vcf_depot_tool_display_version"],
                    "software_depot_id": software_depot_id["id"],
                    "software_depot_id_generated_at": software_depot_id["generated_at"],
                    "software_depot_id_error": software_depot_id["error"],
                    "download_token_present": token_state.present,
                    "download_token_name": uploaded_token_name or token_state.filename,
                    "download_token_updated_at": token_state.updated_at,
                    "activation_code_present": activation_state.present,
                    "activation_code_name": uploaded_activation_name
                    or activation_state.filename,
                    "activation_code_updated_at": activation_state.updated_at,
                    "application_properties_present": application_properties["present"],
                    "application_properties_saved": application_properties["saved"],
                    "application_properties_source": application_properties["source"],
                    "application_properties_updated_at": application_properties[
                        "updated_at"
                    ],
                    "vmware_ceip_enabled": context["vmware_ceip_enabled"],
                    "dns_record_action": dns_record_action,
                    "config_path": saved_settings.config_path,
                    "valid": not validation_errors,
                    "validation_errors": validation_errors,
                    "validation_warnings": validation_warnings,
                    "https_config_preview": context["vcf_depot_https_config_preview"],
                    "command_preview": context["vcf_depot_command_preview"],
                }
            )
        return RedirectResponse("/vcf-offline-depot", status_code=303)

    @router.post("/vcf-offline-depot/tool-package", response_model=None)
    def upload_vcf_depot_tool_package_from_ui(
        request: Request,
        tool_archive_file: UploadFile | None = File(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Handle the upload vcf depot tool package from ui endpoint.

        Args:
            request: Incoming HTTP request.
            tool_archive_file: Tool archive file supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        settings = get_vcf_offline_depot_settings_row(db)
        uploaded_archive_name = store_uploaded_vcf_depot_archive(
            settings, tool_archive_file
        )
        if not uploaded_archive_name:
            raise HTTPException(
                status_code=400, detail="Choose a VCF Download Tool package to upload."
            )
        settings.updated_at = utcnow()
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="upload_vcf_depot_tool_package",
            resource_type="vcf_offline_depot",
            resource_id=str(settings.id),
            detail=uploaded_archive_name,
        )
        context = vcf_offline_depot_context(db)
        token_state = context["vcf_depot_download_token"]
        activation_state = context["vcf_depot_activation_code"]
        application_properties = context["vcf_depot_application_properties"]
        software_depot_id = context["vcf_depot_software_depot_id"]
        return JSONResponse(
            {
                "status": "saved",
                "tool_archive_name": uploaded_archive_name,
                "tool_archive_uploaded": True,
                "tool_version": context["vcf_depot_tool_display_version"],
                "software_depot_id": software_depot_id["id"],
                "software_depot_id_generated_at": software_depot_id["generated_at"],
                "software_depot_id_error": software_depot_id["error"],
                "download_token_present": token_state.present,
                "activation_code_present": activation_state.present,
                "application_properties_present": application_properties["present"],
                "application_properties_saved": application_properties["saved"],
                "application_properties_source": application_properties["source"],
                "application_properties_updated_at": application_properties[
                    "updated_at"
                ],
                "valid": not context["vcf_depot_validation_errors"],
                "validation_errors": context["vcf_depot_validation_errors"],
                "validation_warnings": context["vcf_depot_validation_warnings"],
                "https_config_preview": context["vcf_depot_https_config_preview"],
                "command_preview": context["vcf_depot_command_preview"],
            }
        )

    @router.post("/vcf-offline-depot/tool/reset", response_model=None)
    def reset_vcf_depot_tool_from_ui(
        request: Request,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Handle the reset vcf depot tool from ui endpoint.

        Args:
            request: Incoming HTTP request.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        settings = get_vcf_offline_depot_settings_row(db)
        reset_vcf_depot_tool_staging(db, settings)
        record_audit(
            db,
            actor=identity.username,
            action="reset_vcf_depot_tool",
            resource_type="vcf_offline_depot",
            resource_id=str(settings.id),
            detail="VCFDT package and configuration reset.",
        )
        db.commit()
        return RedirectResponse("/vcf-offline-depot", status_code=303)

    def _store_vcf_depot_credential_from_ui(
        db: Session,
        *,
        credential_type: str,
        credential_text: str,
        credential_file: UploadFile | None,
        actor: str,
        pending_audits: list[AuditEvent] | None = None,
    ) -> str:
        """Persist vcf depot credential from ui.

        Args:
            db: Active database session.
            credential_type: Credential type supplied by the caller.
            credential_text: Credential text supplied by the caller.
            credential_file: Credential file supplied by the caller.
            actor: Authenticated identity attributed to the audit record.
            pending_audits: Pending audits supplied by the caller.

        Returns:
            The store vcf depot credential from ui result.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        if credential_type == "activation_code":
            display_name = store_uploaded_vcf_depot_secret(
                db,
                credential_file,
                name_key=VCF_DEPOT_ACTIVATION_NAME_KEY,
                value_key=VCF_DEPOT_ACTIVATION_VALUE_KEY,
                actor=actor,
                action="upload_vcf_depot_activation_code",
                pending_audits=pending_audits,
            )
            if not display_name:
                display_name = store_pasted_vcf_depot_secret(
                    db,
                    credential_text,
                    name_key=VCF_DEPOT_ACTIVATION_NAME_KEY,
                    value_key=VCF_DEPOT_ACTIVATION_VALUE_KEY,
                    display_name="pasted activation code",
                    actor=actor,
                    action="paste_vcf_depot_activation_code",
                    pending_audits=pending_audits,
                )
            return display_name
        if credential_type != "download_token":
            raise HTTPException(
                status_code=400,
                detail="Credential type must be download token or activation code.",
            )
        display_name = store_uploaded_vcf_depot_secret(
            db,
            credential_file,
            name_key=VCF_DEPOT_TOKEN_NAME_KEY,
            value_key=VCF_DEPOT_TOKEN_VALUE_KEY,
            actor=actor,
            action="upload_vcf_depot_download_token",
            pending_audits=pending_audits,
        )
        if not display_name:
            display_name = store_pasted_vcf_depot_secret(
                db,
                credential_text,
                name_key=VCF_DEPOT_TOKEN_NAME_KEY,
                value_key=VCF_DEPOT_TOKEN_VALUE_KEY,
                display_name="pasted token",
                actor=actor,
                action="paste_vcf_depot_download_token",
                pending_audits=pending_audits,
            )
        return display_name

    def _save_vcf_depot_application_properties(
        db: Session,
        *,
        application_properties: str,
        actor: str,
        pending_audits: list[AuditEvent] | None = None,
    ) -> None:
        """Persist vcf depot application properties.

        Args:
            db: Active database session.
            application_properties: Application properties supplied by the caller.
            actor: Authenticated identity attributed to the audit record.
            pending_audits: Pending audits supplied by the caller.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        content = application_properties.replace("\r\n", "\n").replace("\r", "\n")
        if len(content.encode("utf-8")) > 512 * 1024:
            raise HTTPException(
                status_code=400,
                detail="application-prodv2.properties must be 512 KB or smaller.",
            )
        if not content.strip():
            raise HTTPException(
                status_code=400, detail="application-prodv2.properties cannot be empty."
            )
        updated_at = utcnow().isoformat()
        content_setting = set_setting_value(
            db, VCF_DEPOT_APPLICATION_PROPERTIES_CONTENT_KEY, content
        )
        set_setting_value(
            db, VCF_DEPOT_APPLICATION_PROPERTIES_SOURCE_KEY, "operator saved"
        )
        set_setting_value(
            db, VCF_DEPOT_APPLICATION_PROPERTIES_UPDATED_AT_KEY, updated_at
        )
        if pending_audits is None:
            record_audit(
                db,
                actor=actor,
                action="update_vcf_depot_application_properties",
                resource_type="setting",
                resource_id=str(content_setting.id),
                detail=VCF_DEPOT_APPLICATION_PROPERTIES_NAME,
            )
        else:
            audit = AuditEvent(
                actor=actor,
                action="update_vcf_depot_application_properties",
                resource_type="setting",
                resource_id=str(content_setting.id),
                detail=VCF_DEPOT_APPLICATION_PROPERTIES_NAME,
            )
            db.add(audit)
            pending_audits.append(audit)

    def _vcf_depot_tool_configuration_response(db: Session) -> dict[str, Any]:
        """Return vcf depot tool configuration response.

        Args:
            db: Active database session.
        """
        context = vcf_offline_depot_context(db)
        token_state = context["vcf_depot_download_token"]
        activation_state = context["vcf_depot_activation_code"]
        properties = context["vcf_depot_application_properties"]
        software_depot_id = context["vcf_depot_software_depot_id"]
        validation_errors = context["vcf_depot_validation_errors"]
        return {
            "status": "saved",
            "download_token_present": token_state.present,
            "download_token_name": token_state.filename,
            "download_token_updated_at": token_state.updated_at,
            "activation_code_present": activation_state.present,
            "activation_code_name": activation_state.filename,
            "activation_code_updated_at": activation_state.updated_at,
            "application_properties_present": properties["present"],
            "application_properties_saved": properties["saved"],
            "application_properties_name": properties["filename"],
            "application_properties_source": properties["source"],
            "application_properties_updated_at": properties["updated_at"],
            "software_depot_id": software_depot_id["id"],
            "software_depot_id_generated_at": software_depot_id["generated_at"],
            "software_depot_id_error": software_depot_id["error"],
            "tool_version": context["vcf_depot_tool_display_version"],
            "valid": not validation_errors,
            "validation_errors": validation_errors,
            "validation_warnings": context["vcf_depot_validation_warnings"],
            "config_path": context["vcf_depot_settings"].config_path,
            "https_config_preview": context["vcf_depot_https_config_preview"],
            "command_preview": context["vcf_depot_command_preview"],
        }

    @router.post("/vcf-offline-depot/credentials", response_model=None)
    def paste_vcf_depot_credential_from_ui(
        request: Request,
        credential_type: str = Form("download_token"),
        credential_text: str = Form(""),
        credential_file: UploadFile | None = File(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the paste vcf depot credential from ui endpoint.

        Args:
            request: Incoming HTTP request.
            credential_type: Credential type supplied by the caller.
            credential_text: Credential text supplied by the caller.
            credential_file: Credential file supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        display_name = _store_vcf_depot_credential_from_ui(
            db,
            credential_type=credential_type,
            credential_text=credential_text,
            credential_file=credential_file,
            actor=identity.username,
        )
        db.commit()
        stage_vcf_depot_runtime_secrets_after_upload(db)
        if request.headers.get("X-Atlaso-Autosave") == "1":
            context = vcf_offline_depot_context(db)
            token_state = context["vcf_depot_download_token"]
            activation_state = context["vcf_depot_activation_code"]
            validation_errors = context["vcf_depot_validation_errors"]
            validation_warnings = context["vcf_depot_validation_warnings"]
            return JSONResponse(
                {
                    "status": "saved",
                    "credential_type": credential_type,
                    "credential_name": display_name,
                    "download_token_present": token_state.present,
                    "download_token_name": token_state.filename,
                    "download_token_updated_at": token_state.updated_at,
                    "activation_code_present": activation_state.present,
                    "activation_code_name": activation_state.filename,
                    "activation_code_updated_at": activation_state.updated_at,
                    "valid": not validation_errors,
                    "validation_errors": validation_errors,
                    "validation_warnings": validation_warnings,
                    "config_path": context["vcf_depot_settings"].config_path,
                    "https_config_preview": context["vcf_depot_https_config_preview"],
                    "command_preview": context["vcf_depot_command_preview"],
                }
            )
        return RedirectResponse("/vcf-offline-depot", status_code=303)

    @router.post("/vcf-offline-depot/download-token", response_model=None)
    def paste_vcf_depot_download_token_from_ui(
        request: Request,
        download_token_text: str = Form(""),
        download_token_file: UploadFile | None = File(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the paste vcf depot download token from ui endpoint.

        Args:
            request: Incoming HTTP request.
            download_token_text: Download token text supplied by the caller.
            download_token_file: Download token file supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        display_name = store_uploaded_vcf_depot_secret(
            db,
            download_token_file,
            name_key=VCF_DEPOT_TOKEN_NAME_KEY,
            value_key=VCF_DEPOT_TOKEN_VALUE_KEY,
            actor=identity.username,
            action="upload_vcf_depot_download_token",
        )
        if not display_name:
            display_name = store_pasted_vcf_depot_secret(
                db,
                download_token_text,
                name_key=VCF_DEPOT_TOKEN_NAME_KEY,
                value_key=VCF_DEPOT_TOKEN_VALUE_KEY,
                display_name="pasted token",
                actor=identity.username,
                action="paste_vcf_depot_download_token",
            )
        db.commit()
        stage_vcf_depot_runtime_secrets_after_upload(db)
        if request.headers.get("X-Atlaso-Autosave") == "1":
            context = vcf_offline_depot_context(db)
            token_state = context["vcf_depot_download_token"]
            validation_errors = context["vcf_depot_validation_errors"]
            validation_warnings = context["vcf_depot_validation_warnings"]
            return JSONResponse(
                {
                    "status": "saved",
                    "download_token_present": token_state.present,
                    "download_token_name": display_name,
                    "download_token_updated_at": token_state.updated_at,
                    "valid": not validation_errors,
                    "validation_errors": validation_errors,
                    "validation_warnings": validation_warnings,
                    "config_path": context["vcf_depot_settings"].config_path,
                    "https_config_preview": context["vcf_depot_https_config_preview"],
                    "command_preview": context["vcf_depot_command_preview"],
                }
            )
        return RedirectResponse("/vcf-offline-depot", status_code=303)

    @router.post("/vcf-offline-depot/activation-code", response_model=None)
    def paste_vcf_depot_activation_code_from_ui(
        request: Request,
        activation_code_text: str = Form(""),
        activation_code_file: UploadFile | None = File(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the paste vcf depot activation code from ui endpoint.

        Args:
            request: Incoming HTTP request.
            activation_code_text: Activation code text supplied by the caller.
            activation_code_file: Activation code file supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        display_name = store_uploaded_vcf_depot_secret(
            db,
            activation_code_file,
            name_key=VCF_DEPOT_ACTIVATION_NAME_KEY,
            value_key=VCF_DEPOT_ACTIVATION_VALUE_KEY,
            actor=identity.username,
            action="upload_vcf_depot_activation_code",
        )
        if not display_name:
            display_name = store_pasted_vcf_depot_secret(
                db,
                activation_code_text,
                name_key=VCF_DEPOT_ACTIVATION_NAME_KEY,
                value_key=VCF_DEPOT_ACTIVATION_VALUE_KEY,
                display_name="pasted activation code",
                actor=identity.username,
                action="paste_vcf_depot_activation_code",
            )
        db.commit()
        stage_vcf_depot_runtime_secrets_after_upload(db)
        if request.headers.get("X-Atlaso-Autosave") == "1":
            context = vcf_offline_depot_context(db)
            activation_state = context["vcf_depot_activation_code"]
            validation_errors = context["vcf_depot_validation_errors"]
            validation_warnings = context["vcf_depot_validation_warnings"]
            return JSONResponse(
                {
                    "status": "saved",
                    "activation_code_present": activation_state.present,
                    "activation_code_name": display_name,
                    "activation_code_updated_at": activation_state.updated_at,
                    "valid": not validation_errors,
                    "validation_errors": validation_errors,
                    "validation_warnings": validation_warnings,
                    "config_path": context["vcf_depot_settings"].config_path,
                    "https_config_preview": context["vcf_depot_https_config_preview"],
                    "command_preview": context["vcf_depot_command_preview"],
                }
            )
        return RedirectResponse("/vcf-offline-depot", status_code=303)

    @router.post("/vcf-offline-depot/tool-configuration", response_model=None)
    def save_vcf_depot_tool_configuration_from_ui(
        request: Request,
        application_properties: str = Form(...),
        replace_download_token: str | None = Form(None),
        download_token_text: str = Form(""),
        download_token_file: UploadFile | None = File(None),
        replace_activation_code: str | None = Form(None),
        activation_code_text: str = Form(""),
        activation_code_file: UploadFile | None = File(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the save vcf depot tool configuration from ui endpoint.

        Args:
            request: Incoming HTTP request.
            application_properties: Application properties supplied by the caller.
            replace_download_token: Replace download token supplied by the caller.
            download_token_text: Download token text supplied by the caller.
            download_token_file: Download token file supplied by the caller.
            replace_activation_code: Replace activation code supplied by the caller.
            activation_code_text: Activation code text supplied by the caller.
            activation_code_file: Activation code file supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        if replace_download_token == "on" and replace_activation_code == "on":
            raise HTTPException(
                status_code=400,
                detail="Replace only one Broadcom credential per VCFDT configuration save.",
            )
        pending_audits: list[AuditEvent] = []
        try:
            _save_vcf_depot_application_properties(
                db,
                application_properties=application_properties,
                actor=identity.username,
                pending_audits=pending_audits,
            )
            credentials_changed = False
            if replace_download_token == "on":
                _store_vcf_depot_credential_from_ui(
                    db,
                    credential_type="download_token",
                    credential_text=download_token_text,
                    credential_file=download_token_file,
                    actor=identity.username,
                    pending_audits=pending_audits,
                )
                credentials_changed = True
            if replace_activation_code == "on":
                _store_vcf_depot_credential_from_ui(
                    db,
                    credential_type="activation_code",
                    credential_text=activation_code_text,
                    credential_file=activation_code_file,
                    actor=identity.username,
                    pending_audits=pending_audits,
                )
                credentials_changed = True
            db.commit()
        except Exception:
            db.rollback()
            raise
        for audit in pending_audits:
            log_audit_event(audit)
        if credentials_changed:
            stage_vcf_depot_runtime_secrets_after_upload(db)
        if request.headers.get("X-Atlaso-Autosave") == "1":
            return JSONResponse(_vcf_depot_tool_configuration_response(db))
        return RedirectResponse("/vcf-offline-depot", status_code=303)

    @router.post("/vcf-offline-depot/application-properties", response_model=None)
    def save_vcf_depot_application_properties_from_ui(
        request: Request,
        application_properties: str = Form(""),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the save vcf depot application properties from ui endpoint.

        Args:
            request: Incoming HTTP request.
            application_properties: Application properties supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        _save_vcf_depot_application_properties(
            db,
            application_properties=application_properties,
            actor=identity.username,
        )
        db.commit()
        if request.headers.get("X-Atlaso-Autosave") == "1":
            context = vcf_offline_depot_context(db)
            properties = context["vcf_depot_application_properties"]
            validation_errors = context["vcf_depot_validation_errors"]
            validation_warnings = context["vcf_depot_validation_warnings"]
            return JSONResponse(
                {
                    "status": "saved",
                    "application_properties_present": properties["present"],
                    "application_properties_saved": properties["saved"],
                    "application_properties_source": properties["source"],
                    "application_properties_updated_at": properties["updated_at"],
                    "valid": not validation_errors,
                    "validation_errors": validation_errors,
                    "validation_warnings": validation_warnings,
                    "config_path": context["vcf_depot_settings"].config_path,
                    "https_config_preview": context["vcf_depot_https_config_preview"],
                    "command_preview": context["vcf_depot_command_preview"],
                }
            )
        return RedirectResponse("/vcf-offline-depot", status_code=303)

    @router.post("/vcf-offline-depot/software-depot-id/generate", response_model=None)
    def generate_vcf_depot_software_depot_id_from_ui(
        request: Request,
        background_tasks: BackgroundTasks,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the generate vcf depot software depot id from ui endpoint.

        Args:
            request: Incoming HTTP request.
            background_tasks: Background tasks supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        settings = get_vcf_offline_depot_settings_row(db)
        if not settings.tool_archive_path:
            raise HTTPException(
                status_code=400,
                detail="Upload VCFDT before generating the software depot ID.",
            )
        with VCF_DEPOT_SUBMIT_LOCK:
            db.expire_all()
            acquire_vcf_depot_admission_gate(db)
            active = active_vcf_depot_execution_job(db)
            if active is not None:
                return JSONResponse(
                    {
                        "detail": vcf_depot_execution_conflict_detail(active),
                        "job_id": active.id,
                    },
                    status_code=409,
                )
            job = Job(
                id=f"job_{uuid4().hex[:12]}",
                type="vcf-depot-software-id",
                status=JobStatus.PENDING.value,
                vcf_depot_operation=True,
                created_by=identity.username,
                progress_percent=0,
                result=json.dumps(
                    {
                        "state": JobStatus.PENDING.value,
                        "target": "Generate Software Depot ID",
                        "refresh_existing": bool(
                            vcf_depot_software_depot_id_context(db).get("id")
                        ),
                    },
                    indent=2,
                ),
            )
            db.add(job)
            ensure_vcf_depot_software_id_task_steps(db, job)
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                active = active_vcf_depot_execution_job(db)
                detail = (
                    vcf_depot_execution_conflict_detail(active)
                    if active is not None
                    else "Another VCFDT operation became active. Wait for it to finish and try again."
                )
                return JSONResponse(
                    {
                        "detail": detail,
                        "job_id": active.id if active is not None else "",
                    },
                    status_code=409,
                )
            record_audit(
                db,
                actor=identity.username,
                action="create_vcf_depot_software_id_task",
                resource_type="job",
                resource_id=job.id,
                detail="execution=queued",
            )
        background_tasks.add_task(run_vcf_depot_software_id_job, job.id)
        db.refresh(job)
        if (
            "application/json" in request.headers.get("accept", "")
            or request.headers.get("X-Atlaso-Autosave") == "1"
        ):
            return JSONResponse(
                {
                    "status": "pending",
                    "job_id": job.id,
                    "task": _task_row(job, identity),
                    "status_url": f"/tasks/{job.id}/status",
                },
                status_code=202,
            )
        return RedirectResponse(f"/tasks?job_id={quote(job.id)}", status_code=303)

    @router.get("/vcf-offline-depot/profiles/{profile_id}/preview", response_model=None)
    def preview_vcf_depot_profile_from_ui(
        profile_id: int,
        _identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> JSONResponse:
        """Handle the preview vcf depot profile from ui endpoint.

        Args:
            profile_id: Identifier of the profile.
            _identity: Authenticated identity supplied by the dependency layer.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        profile = db.get(VcfDepotDownloadProfile, profile_id)
        if profile is None:
            raise HTTPException(
                status_code=404, detail="VCFDT download profile not found"
            )
        settings = get_vcf_offline_depot_settings_row(db)
        appliance_settings = get_appliance_settings_row(db)
        secrets = vcf_depot_secret_context(db)
        script = render_vcfdt_command_preview(
            settings,
            [profile],
            vmware_ceip_enabled=bool(appliance_settings.vmware_ceip_enabled),
            download_token_present=bool(secrets["download_token_present"]),
            activation_code_present=bool(secrets["activation_code_present"]),
            preferred_credential_type=str(secrets["download_credential_type"]),
            include_disabled_profiles=True,
        )
        return JSONResponse(
            {"profile_id": profile.id, "profile_name": profile.name, "script": script}
        )

    @router.post("/vcf-offline-depot/profiles", response_model=None)
    def create_vcf_depot_profile_from_ui(
        request: Request,
        name: str = Form(...),
        profile_type: str = Form("binaries"),
        sku: str = Form("VCF"),
        vcf_version: str = Form("9.1.0"),
        binary_type: str = Form("INSTALL"),
        automated_install: str | None = Form(None),
        upgrades_only: str | None = Form(None),
        patches_only: str | None = Form(None),
        component: str = Form(""),
        component_version: str = Form(""),
        disabled_platforms: str = Form(""),
        enabled: str | None = Form(None),
        status: str = Form("planned"),
        notes: str = Form(""),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the create vcf depot profile from ui endpoint.

        Args:
            request: Incoming HTTP request.
            name: Name of the target object.
            profile_type: Profile type supplied by the caller.
            sku: Sku supplied by the caller.
            vcf_version: Vcf version supplied by the caller.
            binary_type: Binary type supplied by the caller.
            automated_install: Automated install supplied by the caller.
            upgrades_only: Upgrades only supplied by the caller.
            patches_only: Patches only supplied by the caller.
            component: Component supplied by the caller.
            component_version: Component version supplied by the caller.
            disabled_platforms: Disabled platforms supplied by the caller.
            enabled: Whether the requested behavior is enabled.
            status: Status supplied by the caller.
            notes: Notes supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        automated_install_selected, upgrades_only_selected, patches_only_selected = (
            resolve_vcf_depot_download_mode_flags(
                automated_install, upgrades_only, patches_only
            )
        )
        settings = get_vcf_offline_depot_settings_row(db)
        profile = VcfDepotDownloadProfile(
            name=name.strip(),
            profile_type=profile_type.strip() or "binaries",
            sku=sku.strip() or "VCF",
            vcf_version=vcf_version.strip() or "9.1.0",
            binary_type=binary_type.strip() or "INSTALL",
            automated_install=automated_install_selected,
            upgrades_only=upgrades_only_selected,
            patches_only=patches_only_selected,
            component=component.strip(),
            component_version=component_version.strip(),
            disabled_platforms=disabled_platforms.strip(),
            enabled=enabled == "on" and vcf_depot_tool_installed(settings),
            status=status.strip() or "planned",
            notes=notes.strip() or None,
        )
        db.add(profile)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=400,
                detail="A VCFDT download profile with this name already exists.",
            ) from exc
        record_audit(
            db,
            actor=identity.username,
            action="create_vcf_depot_profile",
            resource_type="vcf_depot_profile",
            resource_id=str(profile.id),
        )
        db.refresh(profile)
        secrets = vcf_depot_secret_context(db)
        return grid_saved_response(
            request,
            redirect_url="/vcf-offline-depot",
            resource_name="profile",
            resource=vcf_depot_profile_to_dict(
                profile,
                download_token_present=bool(secrets["download_token_present"]),
                activation_code_present=bool(secrets["activation_code_present"]),
            ),
        )

    @router.post("/vcf-offline-depot/profiles/{profile_id}/edit", response_model=None)
    def edit_vcf_depot_profile_from_ui(
        request: Request,
        profile_id: int,
        name: str = Form(...),
        profile_type: str = Form("binaries"),
        sku: str = Form("VCF"),
        vcf_version: str = Form("9.1.0"),
        binary_type: str = Form("INSTALL"),
        automated_install: str | None = Form(None),
        upgrades_only: str | None = Form(None),
        patches_only: str | None = Form(None),
        component: str = Form(""),
        component_version: str = Form(""),
        disabled_platforms: str = Form(""),
        enabled: str | None = Form(None),
        status: str | None = Form(None),
        notes: str = Form(""),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the edit vcf depot profile from ui endpoint.

        Args:
            request: Incoming HTTP request.
            profile_id: Identifier of the profile.
            name: Name of the target object.
            profile_type: Profile type supplied by the caller.
            sku: Sku supplied by the caller.
            vcf_version: Vcf version supplied by the caller.
            binary_type: Binary type supplied by the caller.
            automated_install: Automated install supplied by the caller.
            upgrades_only: Upgrades only supplied by the caller.
            patches_only: Patches only supplied by the caller.
            component: Component supplied by the caller.
            component_version: Component version supplied by the caller.
            disabled_platforms: Disabled platforms supplied by the caller.
            enabled: Whether the requested behavior is enabled.
            status: Status supplied by the caller.
            notes: Notes supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        automated_install_selected, upgrades_only_selected, patches_only_selected = (
            resolve_vcf_depot_download_mode_flags(
                automated_install, upgrades_only, patches_only
            )
        )
        profile = db.get(VcfDepotDownloadProfile, profile_id)
        if not profile:
            raise HTTPException(
                status_code=404, detail="VCFDT download profile not found."
            )
        settings = get_vcf_offline_depot_settings_row(db)
        profile.name = name.strip()
        profile.profile_type = profile_type.strip() or "binaries"
        profile.sku = sku.strip() or "VCF"
        profile.vcf_version = vcf_version.strip() or "9.1.0"
        profile.binary_type = binary_type.strip() or "INSTALL"
        profile.automated_install = automated_install_selected
        profile.upgrades_only = upgrades_only_selected
        profile.patches_only = patches_only_selected
        profile.component = component.strip()
        profile.component_version = component_version.strip()
        profile.disabled_platforms = disabled_platforms.strip()
        profile.enabled = enabled == "on" and vcf_depot_tool_installed(settings)
        disabled_schedules = (
            disable_vcf_depot_profile_schedules(db, profile.id)
            if not profile.enabled
            else []
        )
        if status is not None:
            profile.status = status.strip() or profile.status
        profile.notes = notes.strip() or None
        profile.updated_at = utcnow()
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=400,
                detail="A VCFDT download profile with this name already exists.",
            ) from exc
        record_audit(
            db,
            actor=identity.username,
            action="update_vcf_depot_profile",
            resource_type="vcf_depot_profile",
            resource_id=str(profile.id),
            detail=(
                "disabled_schedules="
                + ",".join(schedule.name for schedule in disabled_schedules)
                if disabled_schedules
                else None
            ),
        )
        db.refresh(profile)
        secrets = vcf_depot_secret_context(db)
        return grid_saved_response(
            request,
            redirect_url="/vcf-offline-depot",
            resource_name="profile",
            resource=vcf_depot_profile_to_dict(
                profile,
                download_token_present=bool(secrets["download_token_present"]),
                activation_code_present=bool(secrets["activation_code_present"]),
            ),
        )

    @router.post(
        "/vcf-offline-depot/profiles/{profile_id}/download", response_model=None
    )
    def start_vcf_depot_profile_download_from_ui(
        request: Request,
        profile_id: int,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the start vcf depot profile download from ui endpoint.

        Args:
            request: Incoming HTTP request.
            profile_id: Identifier of the profile.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        profile = db.get(VcfDepotDownloadProfile, profile_id)
        if not profile:
            raise HTTPException(
                status_code=404, detail="VCFDT download profile not found."
            )
        try:
            _settings, raw_commands, validation_warnings = vcf_depot_download_preflight(
                db, profile
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        system_dry_run = get_settings().dry_run_system_adapters
        commands = [
            vcf_depot_command_entry(command, dry_run=False) for command in raw_commands
        ]
        if not commands:
            raise HTTPException(
                status_code=400,
                detail="The VCFDT download profile did not produce any commands.",
            )
        try:
            job = enqueue_vcf_depot_download(
                db,
                profile=profile,
                actor=identity.username,
                trigger="manual",
            )
        except (
            ActiveVcfDepotDownloadError,
            VcfDepotExclusiveOperationError,
            VcfDepotProfileUnavailableError,
        ) as exc:
            db.rollback()
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        job_result = json.loads(job.result or "{}")
        job_result.update(
            {
                "dry_run": False,
                "system_adapter_dry_run": system_dry_run,
                "validation_warnings": validation_warnings,
            }
        )
        job.result = json.dumps(job_result, indent=2, sort_keys=True)
        db.add(job)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="start_vcf_depot_profile_download",
            resource_type="job",
            resource_id=job.id,
            detail=f"profile={profile.name}; log={vcf_depot_task_log_reference(job.id, profile.name)}",
        )
        if request.headers.get("X-Atlaso-Autosave") == "1":
            return JSONResponse(
                {
                    "status": "started",
                    "job_id": job.id,
                    "job_status": JobStatus.PENDING.value,
                    "profile_id": profile.id,
                    "profile_name": profile.name,
                    "profile_status": profile.status,
                    "dry_run": False,
                    "system_adapter_dry_run": system_dry_run,
                    "log_path": str(vcf_depot_task_log_reference(job.id, profile.name)),
                    "commands": commands,
                    "validation_warnings": validation_warnings,
                }
            )
        return RedirectResponse("/vcf-offline-depot", status_code=303)

    @router.post("/vcf-offline-depot/profiles/{profile_id}/delete", response_model=None)
    def delete_vcf_depot_profile_from_ui(
        request: Request,
        profile_id: int,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | Response:
        """Handle the delete vcf depot profile from ui endpoint.

        Args:
            request: Incoming HTTP request.
            profile_id: Identifier of the profile.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        try:
            profile = lock_vcf_depot_profile_for_deletion(db, profile_id)
        except VcfDepotProfileUnavailableError as exc:
            db.rollback()
            raise HTTPException(
                status_code=404,
                detail="VCFDT download profile not found.",
            ) from exc
        except ActiveVcfDepotDownloadError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Wait for active VCFDT task {exc.active_job_id} to finish "
                    "before deleting this profile."
                ),
            ) from exc
        schedules = vcf_depot_schedules_for_profile(db, profile.id)
        if schedules:
            schedule_names = ", ".join(schedule.name for schedule in schedules)
            raise HTTPException(
                status_code=409,
                detail=f"Delete the attached Automation schedule(s) first: {schedule_names}.",
            )
        db.delete(profile)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_vcf_depot_profile",
            resource_type="vcf_depot_profile",
            resource_id=str(profile_id),
        )
        if grid_request(request):
            return Response(status_code=204)
        return RedirectResponse("/vcf-offline-depot", status_code=303)

    @router.get(
        "/vcf-private-registry", response_class=HTMLResponse, response_model=None
    )
    def vcf_private_registry_page(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the vcf private registry page endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        return render(
            request,
            "vcf_private_registry.html",
            {
                "identity": identity,
                **vcf_private_registry_context(db),
                "appliance_apply_status": appliance_apply_status(
                    db, "vcf_private_registry"
                ),
            },
        )

    @router.post("/vcf-private-registry/settings", response_model=None)
    def update_vcf_private_registry_settings_from_ui(
        request: Request,
        enabled: str | None = Form(None),
        hostname: str = Form(""),
        listen_interfaces: list[str] = Form(default_factory=list),
        listen_addresses: list[str] = Form(default_factory=list),
        listen_interfaces_present: str | None = Form(None),
        listen_addresses_present: str | None = Form(None),
        listen_interface: str = Form(""),
        listen_address: str = Form(""),
        port: int = Form(443),
        harbor_project: str = Form(VCF_REGISTRY_DEFAULT_PROJECT),
        server_certificate: str = Form(""),
        robot_account: str = Form("robot$vcf-supervisor-services"),
        relocation_dry_run: str | None = Form(None),
        ca_bundle_file: UploadFile | None = File(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the update vcf private registry settings from ui endpoint.

        Args:
            request: Incoming HTTP request.
            enabled: Whether the requested behavior is enabled.
            hostname: DNS hostname of the target resource.
            listen_interfaces: Interfaces on which the service should listen.
            listen_addresses: Addresses on which the service should listen.
            listen_interfaces_present: Whether the caller supplied listen interfaces.
            listen_addresses_present: Whether the caller supplied listen addresses.
            listen_interface: Interface on which the service should listen.
            listen_address: Address on which the service should listen.
            port: TCP or UDP port of the target service.
            harbor_project: Harbor project supplied by the caller.
            server_certificate: Server certificate supplied by the caller.
            robot_account: Robot account supplied by the caller.
            relocation_dry_run: Relocation dry run supplied by the caller.
            ca_bundle_file: Ca bundle file supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        settings = get_vcf_private_registry_settings_row(db)
        previous_hostname = settings.hostname
        selected_interfaces, selected_addresses = resolve_service_bind_targets(
            db,
            [*listen_interfaces, listen_interface],
            [*listen_addresses, listen_address],
            current_interface=settings.listen_interface,
            current_address=settings.listen_address,
            listen_interfaces_present=listen_interfaces_present,
            listen_addresses_present=listen_addresses_present,
        )
        settings.enabled = enabled == "on"
        settings.hostname = hostname.strip() or settings.hostname
        settings.listen_interface = selected_interfaces
        settings.listen_address = selected_addresses
        settings.port = port
        settings.harbor_project = harbor_project.strip() or VCF_REGISTRY_DEFAULT_PROJECT
        settings.storage_path = VCF_REGISTRY_DEFAULT_STORAGE_PATH
        settings.config_path = VCF_REGISTRY_DEFAULT_CONFIG_PATH
        uploaded_ca_bundle_name = store_uploaded_vcf_registry_ca_bundle(
            db, ca_bundle_file, identity.username
        )
        ca_bundle_context = vcf_registry_ca_bundle_context(db)
        settings.ca_bundle_path = str(ca_bundle_context["path"])
        settings.server_certificate = server_certificate.strip() or settings.hostname
        settings.robot_account = (
            robot_account.strip() or f"robot${settings.harbor_project}"
        )
        settings.relocation_dry_run = relocation_dry_run == "on"
        settings.updated_at = utcnow()
        dns_record_action = ensure_dns_for_vcf_registry(
            db, settings, identity.username, previous_hostname=previous_hostname
        )
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="update_vcf_private_registry_settings",
            resource_type="vcf_private_registry",
            resource_id=str(settings.id),
        )
        if request.headers.get("X-Atlaso-Autosave") == "1":
            context = vcf_private_registry_context(db)
            saved_settings = context["vcf_registry_settings"]
            validation_errors = context["vcf_registry_validation_errors"]
            validation_warnings = context["vcf_registry_validation_warnings"]
            return JSONResponse(
                {
                    "status": "saved",
                    "updated_at": saved_settings.updated_at.isoformat(),
                    "hostname": saved_settings.hostname,
                    "listen_interface": primary_listen_interface(
                        saved_settings.listen_interface
                    ),
                    "listen_address": primary_listen_address(
                        saved_settings.listen_address
                    ),
                    "listen_interfaces": split_interfaces(
                        saved_settings.listen_interface
                    ),
                    "listen_addresses": split_addresses(saved_settings.listen_address),
                    "port": saved_settings.port,
                    "endpoint": context["vcf_registry_endpoint"],
                    "harbor_project": saved_settings.harbor_project,
                    "storage_path": saved_settings.storage_path,
                    "config_path": saved_settings.config_path,
                    "ca_bundle_path": saved_settings.ca_bundle_path,
                    "ca_bundle_source": context["vcf_registry_ca_bundle_source"],
                    "ca_bundle_source_label": context[
                        "vcf_registry_ca_bundle_source_label"
                    ],
                    "ca_bundle_available": context["vcf_registry_ca_bundle_available"],
                    "ca_bundle_uploaded_name": uploaded_ca_bundle_name
                    or context["vcf_registry_uploaded_ca_bundle_name"],
                    "server_certificate": saved_settings.server_certificate,
                    "robot_account": saved_settings.robot_account,
                    "relocation_dry_run": saved_settings.relocation_dry_run,
                    "dns_record_action": dns_record_action,
                    "valid": not validation_errors,
                    "validation_errors": validation_errors,
                    "validation_warnings": validation_warnings,
                    "harbor_config_preview": context[
                        "vcf_registry_harbor_config_preview"
                    ],
                    "relocation_preview": context["vcf_registry_relocation_preview"],
                }
            )
        return RedirectResponse("/vcf-private-registry", status_code=303)

    @router.post("/vcf-private-registry/bundles", response_model=None)
    def create_vcf_registry_bundle_from_ui(
        request: Request,
        name: str = Form(...),
        source_reference: str = Form(""),
        target_reference: str = Form(""),
        enabled: str | None = Form(None),
        status: str = Form("planned"),
        notes: str = Form(""),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the create vcf registry bundle from ui endpoint.

        Args:
            request: Incoming HTTP request.
            name: Name of the target object.
            source_reference: Source reference supplied by the caller.
            target_reference: Target reference supplied by the caller.
            enabled: Whether the requested behavior is enabled.
            status: Status supplied by the caller.
            notes: Notes supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        settings = get_vcf_private_registry_settings_row(db)
        bundle = VcfRegistryBundle(
            name=name.strip(),
            source_reference=source_reference.strip(),
            target_reference=target_reference.strip()
            or default_target_reference(settings, source_reference),
            enabled=enabled == "on",
            status=status.strip() or "planned",
            notes=notes.strip() or None,
        )
        db.add(bundle)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=400,
                detail="A Supervisor Service bundle with this name already exists.",
            ) from exc
        record_audit(
            db,
            actor=identity.username,
            action="create_vcf_registry_bundle",
            resource_type="vcf_registry_bundle",
            resource_id=str(bundle.id),
        )
        db.refresh(bundle)
        return grid_saved_response(
            request,
            redirect_url="/vcf-private-registry",
            resource_name="bundle",
            resource=vcf_registry_bundle_to_dict(bundle),
        )

    @router.post("/vcf-private-registry/bundles/{bundle_id}/edit", response_model=None)
    def edit_vcf_registry_bundle_from_ui(
        request: Request,
        bundle_id: int,
        name: str = Form(...),
        source_reference: str = Form(""),
        target_reference: str = Form(""),
        enabled: str | None = Form(None),
        status: str = Form("planned"),
        notes: str = Form(""),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the edit vcf registry bundle from ui endpoint.

        Args:
            request: Incoming HTTP request.
            bundle_id: Identifier of the bundle.
            name: Name of the target object.
            source_reference: Source reference supplied by the caller.
            target_reference: Target reference supplied by the caller.
            enabled: Whether the requested behavior is enabled.
            status: Status supplied by the caller.
            notes: Notes supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        settings = get_vcf_private_registry_settings_row(db)
        bundle = db.get(VcfRegistryBundle, bundle_id)
        if not bundle:
            raise HTTPException(
                status_code=404, detail="Supervisor Service bundle not found."
            )
        bundle.name = name.strip()
        bundle.source_reference = source_reference.strip()
        bundle.target_reference = target_reference.strip() or default_target_reference(
            settings, source_reference
        )
        bundle.enabled = enabled == "on"
        bundle.status = status.strip() or "planned"
        bundle.notes = notes.strip() or None
        bundle.updated_at = utcnow()
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=400,
                detail="A Supervisor Service bundle with this name already exists.",
            ) from exc
        record_audit(
            db,
            actor=identity.username,
            action="update_vcf_registry_bundle",
            resource_type="vcf_registry_bundle",
            resource_id=str(bundle.id),
        )
        db.refresh(bundle)
        return grid_saved_response(
            request,
            redirect_url="/vcf-private-registry",
            resource_name="bundle",
            resource=vcf_registry_bundle_to_dict(bundle),
        )

    @router.post(
        "/vcf-private-registry/bundles/{bundle_id}/delete", response_model=None
    )
    def delete_vcf_registry_bundle_from_ui(
        request: Request,
        bundle_id: int,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | Response:
        """Handle the delete vcf registry bundle from ui endpoint.

        Args:
            request: Incoming HTTP request.
            bundle_id: Identifier of the bundle.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        bundle = db.get(VcfRegistryBundle, bundle_id)
        if not bundle:
            raise HTTPException(
                status_code=404, detail="Supervisor Service bundle not found."
            )
        db.delete(bundle)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_vcf_registry_bundle",
            resource_type="vcf_registry_bundle",
            resource_id=str(bundle_id),
        )
        if grid_request(request):
            return Response(status_code=204)
        return RedirectResponse("/vcf-private-registry", status_code=303)

    @router.get("/vcf-backups", response_class=HTMLResponse, response_model=None)
    def vcf_backups_page(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the vcf backups page endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        return render(
            request,
            "vcf_backups.html",
            {
                "identity": identity,
                **vcf_backup_context(db),
                "appliance_apply_status": appliance_apply_status(db, "vcf_backups"),
            },
        )

    @router.post("/vcf-backups/settings", response_model=None)
    def update_vcf_backup_settings_from_ui(
        request: Request,
        enabled: str | None = Form(None),
        listen_interfaces: list[str] = Form(default_factory=list),
        listen_addresses: list[str] = Form(default_factory=list),
        listen_interfaces_present: str | None = Form(None),
        listen_addresses_present: str | None = Form(None),
        listen_interface: str = Form(""),
        listen_address: str = Form(""),
        port: int = Form(22),
        sftp_user_id: str = Form(""),
        chroot_enabled: str | None = Form(None),
        allow_password_auth: str | None = Form(None),
        allow_public_key_auth: str | None = Form(None),
        max_sessions: int = Form(4),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the update vcf backup settings from ui endpoint.

        Args:
            request: Incoming HTTP request.
            enabled: Whether the requested behavior is enabled.
            listen_interfaces: Interfaces on which the service should listen.
            listen_addresses: Addresses on which the service should listen.
            listen_interfaces_present: Whether the caller supplied listen interfaces.
            listen_addresses_present: Whether the caller supplied listen addresses.
            listen_interface: Interface on which the service should listen.
            listen_address: Address on which the service should listen.
            port: TCP or UDP port of the target service.
            sftp_user_id: Identifier of the sftp user.
            chroot_enabled: Chroot enabled supplied by the caller.
            allow_password_auth: Allow password auth supplied by the caller.
            allow_public_key_auth: Allow public key auth supplied by the caller.
            max_sessions: Max sessions supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        settings = get_vcf_backup_settings_row(db, reconcile_default_user=False)
        user_id = int(sftp_user_id) if str(sftp_user_id).strip() else None
        if user_id and not db.get(User, user_id):
            raise HTTPException(
                status_code=400, detail="Selected SFTP user does not exist."
            )
        selected_interfaces, selected_addresses = resolve_service_bind_targets(
            db,
            [*listen_interfaces, listen_interface],
            [*listen_addresses, listen_address],
            current_interface=settings.listen_interface,
            current_address=settings.listen_address,
            listen_interfaces_present=listen_interfaces_present,
            listen_addresses_present=listen_addresses_present,
        )
        settings.enabled = enabled == "on"
        settings.listen_interface = selected_interfaces
        settings.listen_address = selected_addresses
        settings.port = port
        settings.sftp_user_id = user_id
        settings.storage_path = VCF_BACKUP_DEFAULT_VOLUME_MOUNT
        settings.chroot_enabled = chroot_enabled == "on"
        settings.allow_password_auth = allow_password_auth == "on"
        settings.allow_public_key_auth = allow_public_key_auth == "on"
        settings.max_sessions = max_sessions
        settings.config_path = VCF_BACKUP_EFFECTIVE_CONFIG_PATH
        settings.updated_at = utcnow()
        selected_user = db.get(User, user_id) if user_id else None
        if (
            settings.enabled
            and selected_user
            and selected_user.username == VCF_BACKUP_DEFAULT_USERNAME
            and not selected_user.enabled
        ):
            if (
                has_pending_os_password(selected_user)
                or selected_user.os_password_applied_at
            ):
                selected_user.enabled = True
                selected_user.os_sync_status = "pending"
                db.add(selected_user)
        disabled_default_user = disable_default_vcf_backup_user_when_service_off(
            db, settings, actor=identity.username
        )
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="update_vcf_backup_settings",
            resource_type="vcf_backups",
            resource_id=str(settings.id),
        )
        if disabled_default_user:
            record_audit(
                db,
                actor=identity.username,
                action="disable_vcf_backup_default_user",
                resource_type="user",
                resource_id=str(user_id or ""),
            )
        if request.headers.get("X-Atlaso-Autosave") == "1":
            context = vcf_backup_context(db)
            saved_settings = context["vcf_backup_settings"]
            validation_errors = context["vcf_backup_validation_errors"]
            apply_status = appliance_apply_client_status(
                appliance_apply_status(db, "vcf_backups")
            )
            return JSONResponse(
                {
                    "status": "saved",
                    "updated_at": saved_settings.updated_at.isoformat(),
                    "listen_interface": primary_listen_interface(
                        saved_settings.listen_interface
                    ),
                    "listen_address": primary_listen_address(
                        saved_settings.listen_address
                    ),
                    "listen_interfaces": split_interfaces(
                        saved_settings.listen_interface
                    ),
                    "listen_addresses": split_addresses(saved_settings.listen_address),
                    "port": saved_settings.port,
                    "sftp_username": saved_settings.sftp_user.username
                    if saved_settings.sftp_user
                    else "",
                    "storage_path": saved_settings.storage_path,
                    "remote_directory": vcf_backup_remote_directory(saved_settings),
                    "chroot_label": "appliance mount, chroot enabled"
                    if saved_settings.chroot_enabled
                    else "appliance mount",
                    "auth_methods": " + ".join(
                        [
                            label
                            for enabled_value, label in [
                                (saved_settings.allow_password_auth, "password"),
                                (saved_settings.allow_public_key_auth, "public key"),
                            ]
                            if enabled_value
                        ]
                    )
                    or "none",
                    "max_sessions": saved_settings.max_sessions,
                    "valid": not validation_errors,
                    "validation_errors": validation_errors,
                    "config_path": saved_settings.config_path,
                    "config_preview": context["vcf_backup_config_preview"],
                    "appliance_apply_status": apply_status,
                }
            )
        return RedirectResponse("/vcf-backups", status_code=303)

    return VcfWorkflowsUiRouter(
        router=router,
        endpoints={
            "legacy_https_repository_redirect": legacy_https_repository_redirect,
            "vcf_helper_page": vcf_helper_page,
            "vcf_helper_page_context": vcf_helper_page_context,
            "_vcf_helper_json": _vcf_helper_json,
            "_confirmed_tls_fingerprint": _confirmed_tls_fingerprint_impl,
            "_split_vcf_endpoint_address_port": _split_vcf_endpoint_address_port,
            "_resolve_vcf_helper_credentials": _resolve_vcf_helper_credentials_impl,
            "inspect_vcf_vault_import": inspect_vcf_vault_import,
            "import_vcf_passwords_to_vault": import_vcf_passwords_to_vault,
            "_validate_vcf_sddc_property_values": _validate_vcf_sddc_property_values,
            "vcf_sddc_manager_inventory": vcf_sddc_manager_inventory,
            "deploy_vcf_sddc_manager_from_ui": deploy_vcf_sddc_manager_from_ui,
            "vcf_sddc_manager_task_status": vcf_sddc_manager_task_status,
            "inspect_vcf_offline_depot_target_from_ui": inspect_vcf_offline_depot_target_from_ui,
            "configure_vcf_offline_depot_target_from_ui": configure_vcf_offline_depot_target_from_ui,
            "vcf_offline_depot_target_task_status": vcf_offline_depot_target_task_status,
            "vcf_trust_page": vcf_trust_page,
            "inspect_vcf_trust_target_from_ui": inspect_vcf_trust_target_from_ui,
            "trust_vcf_root_ca_from_ui": trust_vcf_root_ca_from_ui,
            "populate_vcf_fqdns_from_ui": populate_vcf_fqdns_from_ui,
            "generate_vcf_fqdns_from_ui": generate_vcf_fqdns_from_ui,
            "delete_vcf_fqdns_from_ui": delete_vcf_fqdns_from_ui,
            "vcf_offline_depot_page": vcf_offline_depot_page,
            "vcf_offline_depot_task_log_page": vcf_offline_depot_task_log_page,
            "vcf_offline_depot_task_status": vcf_offline_depot_task_status,
            "update_vcf_offline_depot_settings_from_ui": update_vcf_offline_depot_settings_from_ui,
            "upload_vcf_depot_tool_package_from_ui": upload_vcf_depot_tool_package_from_ui,
            "reset_vcf_depot_tool_from_ui": reset_vcf_depot_tool_from_ui,
            "_store_vcf_depot_credential_from_ui": _store_vcf_depot_credential_from_ui,
            "_save_vcf_depot_application_properties": _save_vcf_depot_application_properties,
            "_vcf_depot_tool_configuration_response": _vcf_depot_tool_configuration_response,
            "paste_vcf_depot_credential_from_ui": paste_vcf_depot_credential_from_ui,
            "paste_vcf_depot_download_token_from_ui": paste_vcf_depot_download_token_from_ui,
            "paste_vcf_depot_activation_code_from_ui": paste_vcf_depot_activation_code_from_ui,
            "save_vcf_depot_tool_configuration_from_ui": save_vcf_depot_tool_configuration_from_ui,
            "save_vcf_depot_application_properties_from_ui": save_vcf_depot_application_properties_from_ui,
            "generate_vcf_depot_software_depot_id_from_ui": generate_vcf_depot_software_depot_id_from_ui,
            "preview_vcf_depot_profile_from_ui": preview_vcf_depot_profile_from_ui,
            "create_vcf_depot_profile_from_ui": create_vcf_depot_profile_from_ui,
            "edit_vcf_depot_profile_from_ui": edit_vcf_depot_profile_from_ui,
            "start_vcf_depot_profile_download_from_ui": start_vcf_depot_profile_download_from_ui,
            "delete_vcf_depot_profile_from_ui": delete_vcf_depot_profile_from_ui,
            "vcf_private_registry_page": vcf_private_registry_page,
            "update_vcf_private_registry_settings_from_ui": update_vcf_private_registry_settings_from_ui,
            "create_vcf_registry_bundle_from_ui": create_vcf_registry_bundle_from_ui,
            "edit_vcf_registry_bundle_from_ui": edit_vcf_registry_bundle_from_ui,
            "delete_vcf_registry_bundle_from_ui": delete_vcf_registry_bundle_from_ui,
            "vcf_backups_page": vcf_backups_page,
            "update_vcf_backup_settings_from_ui": update_vcf_backup_settings_from_ui,
        },
    )
