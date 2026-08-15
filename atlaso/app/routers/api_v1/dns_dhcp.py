from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Response,
)
from fastapi import Path as ApiPath
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atlaso.app.adapters.system import SystemAdapter
from atlaso.app.audit import record_audit
from atlaso.app.database import get_db
from atlaso.app.models import (
    DhcpOption,
    DhcpReservation,
    DhcpScope,
    DnsRecord,
    PhysicalInterface,
    ServiceState,
    VlanInterface,
    utcnow,
)
from atlaso.app.openapi import DocumentedAPIRoute
from atlaso.app.schemas import (
    ConfigApplyResponse,
    ConfigValidationResponse,
    DhcpLeaseResponse,
    DhcpOptionCreate,
    DhcpOptionResponse,
    DhcpReservationCreate,
    DhcpReservationResponse,
    DhcpScopeCreate,
    DhcpScopeResponse,
    DhcpSettingsResponse,
    DhcpSettingsUpdate,
    DhcpStatusResponse,
    DnsHostsImportRequest,
    DnsHostsImportResponse,
    DnsRecordCreate,
    DnsRecordResponse,
    DnsSettingsResponse,
    DnsSettingsUpdate,
    DnsStatusResponse,
    ServiceStateResponse,
)
from atlaso.app.security import (
    Identity,
    require_scope,
)
from atlaso.app.services.dnsmasq import (
    DNS_CONDITIONAL_FORWARDERS_SETTING_KEY,
    dhcp_bind_target_families,
    dhcp_bind_target_names,
    dns_domain_warnings,
    dns_settings_to_dict,
    dnsmasq_test_command,
    dump_dns_record_data,
    join_conditional_forwarders,
    join_domains,
    join_servers,
    parse_dnsmasq_leases,
    parse_hosts_records,
    split_domains,
    validate_authoritative_dns_record,
    validate_dhcp_bind_targets,
    validate_dhcp_settings,
    validate_dns_listen_targets,
    validate_dns_record,
    validate_dns_settings,
)

Endpoint = Callable[..., Any]


@dataclass(frozen=True)
class DnsDhcpApiDependencies:
    ensure_dns_for_dhcp_reservation: Endpoint
    get_dhcp_settings_row: Endpoint
    get_dns_settings_row: Endpoint
    get_dnsmasq_state: Endpoint
    set_setting_value: Endpoint
    setting_value: Endpoint
    stage_api_dnsmasq_config: Endpoint


@dataclass(frozen=True)
class DnsDhcpApiRouter:
    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_router(dependencies: DnsDhcpApiDependencies) -> DnsDhcpApiRouter:
    """Build the DNS/DHCP API v1 router without importing its compatibility facade.

    Args:
        dependencies: Facade-owned helpers retained during structural extraction.

    Returns:
        Configured domain router and its stable endpoint callables.
    """
    router = APIRouter(prefix="/api/v1", route_class=DocumentedAPIRoute)

    ensure_dns_for_dhcp_reservation = dependencies.ensure_dns_for_dhcp_reservation
    get_dhcp_settings_row = dependencies.get_dhcp_settings_row
    get_dns_settings_row = dependencies.get_dns_settings_row
    get_dnsmasq_state = dependencies.get_dnsmasq_state
    set_setting_value = dependencies.set_setting_value
    setting_value = dependencies.setting_value
    stage_api_dnsmasq_config = dependencies.stage_api_dnsmasq_config

    @router.get(
        "/dns/status",
        response_model=DnsStatusResponse,
        tags=["DNS"],
        operation_id="getDnsStatus",
    )
    def get_dns_status(
        identity: Annotated[Identity, Depends(require_scope("read:dns"))],
        db: Session = Depends(get_db),
    ) -> DnsStatusResponse:
        """Get Dns Status.

        Requires the `read:dns` API scope. This read-only operation does not change saved desired state
        or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        settings = get_dns_settings_row(db)
        service = db.execute(
            select(ServiceState).where(ServiceState.service == "dns")
        ).scalar_one_or_none()
        record_count = db.scalar(
            select(func.count())
            .select_from(DnsRecord)
            .where(DnsRecord.enabled.is_(True))
        )
        return DnsStatusResponse(
            enabled=settings.enabled,
            service=ServiceStateResponse.model_validate(service) if service else None,
            listen_interface=settings.listen_interface,
            listen_address=settings.listen_address,
            domain=settings.domain,
            record_count=record_count or 0,
            config_path=settings.config_path,
            dry_run=SystemAdapter().dry_run,
        )

    @router.get(
        "/dns/settings",
        response_model=DnsSettingsResponse,
        tags=["DNS"],
        operation_id="getDnsSettings",
    )
    def get_dns_settings(
        identity: Annotated[Identity, Depends(require_scope("read:dns"))],
        db: Session = Depends(get_db),
    ) -> DnsSettingsResponse:
        """Get Dns Settings.

        Requires the `read:dns` API scope. This read-only operation does not change saved desired state
        or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return DnsSettingsResponse(
            **dns_settings_to_dict(
                get_dns_settings_row(db),
                setting_value(db, DNS_CONDITIONAL_FORWARDERS_SETTING_KEY),
            )
        )

    @router.patch(
        "/dns/settings",
        response_model=DnsSettingsResponse,
        tags=["DNS"],
        operation_id="updateDnsSettings",
    )
    def update_dns_settings(
        payload: DnsSettingsUpdate,
        identity: Annotated[Identity, Depends(require_scope("write:dns"))],
        db: Session = Depends(get_db),
    ) -> DnsSettingsResponse:
        """Update Dns Settings.

        Requires the `write:dns` API scope. The operation updates saved Atlaso state and does not bypass
        the documented global Appliance Apply or service lifecycle boundary.

        Args:
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        settings = get_dns_settings_row(db)
        for key, value in payload.model_dump().items():
            if key == "upstream_servers":
                value = join_servers(value)
            elif key == "conditional_forwarders":
                set_setting_value(
                    db,
                    DNS_CONDITIONAL_FORWARDERS_SETTING_KEY,
                    join_conditional_forwarders(value),
                )
                continue
            elif key == "domain":
                value = join_domains(split_domains(value))
            setattr(settings, key, value)
        settings.updated_at = utcnow()
        db.commit()
        db.refresh(settings)
        record_audit(
            db,
            actor=identity.username,
            action="update_dns_settings",
            resource_type="dns",
            resource_id=str(settings.id),
            detail=(
                f"authoritative={settings.authoritative}; primary={settings.authoritative_server}; "
                f"contact={settings.authoritative_contact}; ttl={settings.authoritative_ttl}; "
                f"serial={settings.authoritative_serial}; refresh={settings.authoritative_refresh}; "
                f"retry={settings.authoritative_retry}; expire={settings.authoritative_expire}"
            ),
        )
        return DnsSettingsResponse(
            **dns_settings_to_dict(
                settings,
                setting_value(db, DNS_CONDITIONAL_FORWARDERS_SETTING_KEY),
            )
        )

    @router.get(
        "/dns/records",
        response_model=list[DnsRecordResponse],
        tags=["DNS"],
        operation_id="listDnsRecords",
    )
    def list_dns_records(
        identity: Annotated[Identity, Depends(require_scope("read:dns"))],
        db: Session = Depends(get_db),
    ) -> list[DnsRecordResponse]:
        """List Dns Records.

        Requires the `read:dns` API scope. This read-only operation does not change saved desired state
        or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return [
            DnsRecordResponse.model_validate(row)
            for row in db.execute(select(DnsRecord).order_by(DnsRecord.hostname))
            .scalars()
            .all()
        ]

    @router.post(
        "/dns/records",
        response_model=DnsRecordResponse,
        status_code=201,
        tags=["DNS"],
        operation_id="createDnsRecord",
    )
    def create_dns_record(
        payload: DnsRecordCreate,
        identity: Annotated[Identity, Depends(require_scope("write:dns"))],
        db: Session = Depends(get_db),
    ) -> DnsRecordResponse:
        """Create Dns Record.

        Requires the `write:dns` API scope. The operation changes saved Atlaso application state; any
        appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        hostname = payload.hostname.strip().lower()
        record_type = payload.record_type.strip().upper()
        address = payload.address.strip()
        record_data_json = dump_dns_record_data(record_type, address)
        validation_errors = validate_dns_record(hostname, record_type, address)
        validation_errors.extend(
            validate_authoritative_dns_record(
                get_dns_settings_row(db), hostname, record_type, address
            )
        )
        if validation_errors:
            raise HTTPException(status_code=422, detail=" ".join(validation_errors))
        existing = db.execute(
            select(DnsRecord).where(
                func.lower(DnsRecord.hostname) == hostname,
                func.lower(DnsRecord.record_type) == record_type.lower(),
                DnsRecord.address == address,
            )
        ).scalar_one_or_none()
        if existing:
            raise HTTPException(
                status_code=409,
                detail=f"DNS {record_type} record already exists for {hostname}",
            )
        record = DnsRecord(
            hostname=hostname,
            record_type=record_type,
            address=address,
            record_data_json=record_data_json,
            description=payload.description,
            enabled=payload.enabled,
        )
        db.add(record)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail=f"DNS {record_type} record already exists for {hostname}",
            ) from exc
        db.refresh(record)
        record_audit(
            db,
            actor=identity.username,
            action="create_dns_record",
            resource_type="dns_record",
            resource_id=str(record.id),
        )
        return DnsRecordResponse.model_validate(record)

    @router.patch(
        "/dns/records/{record_id}",
        response_model=DnsRecordResponse,
        tags=["DNS"],
        operation_id="updateDnsRecord",
    )
    def update_dns_record(
        record_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the record record addressed by this operation."
            ),
        ],
        payload: DnsRecordCreate,
        identity: Annotated[Identity, Depends(require_scope("write:dns"))],
        db: Session = Depends(get_db),
    ) -> DnsRecordResponse:
        """Update Dns Record.

        Requires the `write:dns` API scope. The operation updates saved Atlaso state and does not bypass
        the documented global Appliance Apply or service lifecycle boundary.

        Args:
            record_id: Stable identifier of the associated record resource.
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        record = db.get(DnsRecord, record_id)
        if not record:
            raise HTTPException(status_code=404, detail="DNS record not found")
        hostname = payload.hostname.strip().lower()
        record_type = payload.record_type.strip().upper()
        address = payload.address.strip()
        record_data_json = dump_dns_record_data(record_type, address)
        validation_errors = validate_dns_record(hostname, record_type, address)
        validation_errors.extend(
            validate_authoritative_dns_record(
                get_dns_settings_row(db), hostname, record_type, address
            )
        )
        if validation_errors:
            raise HTTPException(status_code=422, detail=" ".join(validation_errors))
        existing = db.execute(
            select(DnsRecord).where(
                DnsRecord.id != record_id,
                func.lower(DnsRecord.hostname) == hostname,
                func.lower(DnsRecord.record_type) == record_type.lower(),
                DnsRecord.address == address,
            )
        ).scalar_one_or_none()
        if existing:
            raise HTTPException(
                status_code=409,
                detail=f"DNS {record_type} record already exists for {hostname}",
            )
        record.hostname = hostname
        record.record_type = record_type
        record.address = address
        record.record_data_json = record_data_json
        record.description = payload.description
        record.enabled = payload.enabled
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail=f"DNS {record_type} record already exists for {hostname}",
            ) from exc
        db.refresh(record)
        record_audit(
            db,
            actor=identity.username,
            action="update_dns_record",
            resource_type="dns_record",
            resource_id=str(record.id),
        )
        return DnsRecordResponse.model_validate(record)

    @router.post(
        "/dns/records/import",
        response_model=DnsHostsImportResponse,
        tags=["DNS"],
        operation_id="importDnsHostsFile",
    )
    def import_dns_hosts_file(
        payload: DnsHostsImportRequest,
        identity: Annotated[Identity, Depends(require_scope("write:dns"))],
        db: Session = Depends(get_db),
    ) -> DnsHostsImportResponse:
        """Import Dns Hosts File.

        Requires the `write:dns` API scope. The operation changes saved Atlaso application state; any
        appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        parsed_records, errors = parse_hosts_records(payload.hosts_text)
        dns_settings = get_dns_settings_row(db)
        for item in parsed_records:
            errors.extend(
                validate_authoritative_dns_record(
                    dns_settings,
                    str(item["hostname"]),
                    str(item["record_type"]),
                    str(item["address"]),
                )
            )
        if errors:
            raise HTTPException(status_code=422, detail="; ".join(errors))
        if payload.replace_existing:
            for record in db.execute(select(DnsRecord)).scalars().all():
                db.delete(record)
            db.flush()
        for item in parsed_records:
            existing = None
            if not payload.replace_existing:
                existing = db.execute(
                    select(DnsRecord).where(
                        DnsRecord.hostname == item["hostname"],
                        DnsRecord.record_type == item["record_type"],
                        DnsRecord.address == item["address"],
                    )
                ).scalar_one_or_none()
            if existing:
                existing.address = str(item["address"])
                existing.record_data_json = dump_dns_record_data(
                    str(item["record_type"]), str(item["address"])
                )
                existing.description = str(item["description"] or "")
                existing.enabled = bool(item["enabled"])
            else:
                item["record_data_json"] = dump_dns_record_data(
                    str(item["record_type"]), str(item["address"])
                )
                db.add(DnsRecord(**item))
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409, detail="Imported hosts contain duplicate DNS records"
            ) from exc
        rows = (
            db.execute(select(DnsRecord).order_by(DnsRecord.hostname)).scalars().all()
        )
        record_audit(
            db,
            actor=identity.username,
            action="import_dns_hosts_file",
            resource_type="dns_record",
            detail=f"Imported {len(parsed_records)} records; replace_existing={payload.replace_existing}",
        )
        return DnsHostsImportResponse(
            imported_count=len(parsed_records),
            replaced_existing=payload.replace_existing,
            records=[DnsRecordResponse.model_validate(row) for row in rows],
        )

    @router.delete(
        "/dns/records/{record_id}",
        status_code=204,
        tags=["DNS"],
        operation_id="deleteDnsRecord",
    )
    def delete_dns_record(
        record_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the record record addressed by this operation."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("write:dns"))],
        db: Session = Depends(get_db),
    ) -> Response:
        """Delete Dns Record.

        Requires the `write:dns` API scope. Removal or revocation takes effect in Atlaso application
        state; appliance host changes remain subject to the documented apply boundary for the resource.

        Args:
            record_id: Stable identifier of the associated record resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        record = db.get(DnsRecord, record_id)
        if not record:
            raise HTTPException(status_code=404, detail="DNS record not found")
        db.delete(record)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_dns_record",
            resource_type="dns_record",
            resource_id=str(record_id),
        )
        return Response(status_code=204)

    def dnsmasq_validation_response(db: Session) -> ConfigValidationResponse:
        """Return dnsmasq validation response.

        Args:
            db: Active database session.
        """
        (
            dns_settings,
            dns_records,
            dhcp_settings,
            dhcp_scopes,
            dhcp_options,
            dhcp_reservations,
            fallback_upstream_servers,
            require_dhcp_upstream,
            config_preview,
        ) = get_dnsmasq_state(db)
        conditional_forwarders = setting_value(
            db, DNS_CONDITIONAL_FORWARDERS_SETTING_KEY
        )
        physical_interfaces = (
            db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name))
            .scalars()
            .all()
        )
        vlan_interfaces = (
            db.execute(select(VlanInterface).order_by(VlanInterface.name))
            .scalars()
            .all()
        )
        bind_targets = dhcp_bind_target_names(physical_interfaces, vlan_interfaces)
        bind_target_families = dhcp_bind_target_families(
            physical_interfaces, vlan_interfaces
        )
        errors = (
            validate_dns_settings(
                dns_settings,
                dns_records,
                conditional_forwarders,
                fallback_upstream_servers=fallback_upstream_servers,
                require_dhcp_upstream=require_dhcp_upstream,
            )
            + validate_dns_listen_targets(dns_settings, bind_targets)
            + validate_dhcp_bind_targets(
                dhcp_settings, dhcp_scopes, bind_target_families
            )
            + validate_dhcp_settings(
                dhcp_settings,
                dhcp_reservations,
                dhcp_scopes,
                dhcp_options,
            )
        )
        warnings = dns_domain_warnings(split_domains(dns_settings.domain))
        adapter = SystemAdapter()
        config_path = dns_settings.config_path
        if not adapter.dry_run:
            config_path = stage_api_dnsmasq_config(config_preview)
        result = adapter.validate_dnsmasq_config(config_path)
        return ConfigValidationResponse(
            valid=not errors,
            dry_run=result.dry_run,
            command=result.command
            if result.command
            else dnsmasq_test_command(config_path),
            config_path=config_path,
            config_preview=config_preview,
            errors=errors,
            warnings=warnings,
        )

    @router.post(
        "/dns/validate",
        response_model=ConfigValidationResponse,
        tags=["DNS"],
        operation_id="validateDnsConfig",
    )
    def validate_dns_config(
        identity: Annotated[Identity, Depends(require_scope("read:dns"))],
        db: Session = Depends(get_db),
    ) -> ConfigValidationResponse:
        """Validate Dns Config.

        Requires the `read:dns` API scope. The request is evaluated without persisting desired state or
        mutating appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return dnsmasq_validation_response(db)

    @router.post(
        "/dns/apply",
        response_model=ConfigApplyResponse,
        tags=["DNS"],
        operation_id="applyDnsConfig",
        include_in_schema=False,
    )
    def apply_dns_config(
        identity: Annotated[Identity, Depends(require_scope("write:dns"))],
        db: Session = Depends(get_db),
    ) -> ConfigApplyResponse:
        """Apply Dns Config.

        Requires the `write:dns` API scope. The action runs through the endpoint's existing audited
        adapter or task boundary; inspect the returned state before treating the operation as complete.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        validation = dnsmasq_validation_response(db)
        if not validation.valid:
            return ConfigApplyResponse(**validation.model_dump(), reloaded=False)
        apply_result = SystemAdapter().apply_dnsmasq_config(validation.config_path)
        reload_result = SystemAdapter().reload_dnsmasq()
        record_audit(
            db,
            actor=identity.username,
            action="apply_dns_config_dry_run",
            resource_type="dns",
            detail=" ".join(apply_result.command + [";"] + reload_result.command),
        )
        payload = validation.model_dump()
        payload["command"] = apply_result.command
        return ConfigApplyResponse(**payload, reloaded=not apply_result.dry_run)

    @router.get(
        "/dns/logs", response_model=list[str], tags=["DNS"], operation_id="getDnsLogs"
    )
    def get_dns_logs(
        identity: Annotated[Identity, Depends(require_scope("read:dns"))],
    ) -> list[str]:
        """Get Dns Logs.

        Requires the `read:dns` API scope. This read-only operation does not change saved desired state
        or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
        """
        return [
            "dry-run log source for dnsmasq",
            "Host journal reading is reserved for the provisioned appliance.",
        ]

    @router.get(
        "/dhcp/status",
        response_model=DhcpStatusResponse,
        tags=["DHCP"],
        operation_id="getDhcpStatus",
    )
    def get_dhcp_status(
        identity: Annotated[Identity, Depends(require_scope("read:dhcp"))],
        db: Session = Depends(get_db),
    ) -> DhcpStatusResponse:
        """Get Dhcp Status.

        Requires the `read:dhcp` API scope. This read-only operation does not change saved desired state
        or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        settings = get_dhcp_settings_row(db)
        first_scope = (
            db.execute(select(DhcpScope).order_by(DhcpScope.name)).scalars().first()
        )
        service = db.execute(
            select(ServiceState).where(ServiceState.service == "dhcp")
        ).scalar_one_or_none()
        reservations = (
            db.execute(select(DhcpReservation).where(DhcpReservation.enabled.is_(True)))
            .scalars()
            .all()
        )
        return DhcpStatusResponse(
            enabled=settings.enabled,
            service=ServiceStateResponse.model_validate(service) if service else None,
            interface_name=first_scope.interface_name
            if first_scope
            else settings.interface_name,
            range_expression=first_scope.range_expression if first_scope else "",
            reservation_count=len(reservations),
            config_path=settings.config_path,
            dry_run=SystemAdapter().dry_run,
        )

    @router.get(
        "/dhcp/settings",
        response_model=DhcpSettingsResponse,
        tags=["DHCP"],
        operation_id="getDhcpSettings",
    )
    def get_dhcp_settings(
        identity: Annotated[Identity, Depends(require_scope("read:dhcp"))],
        db: Session = Depends(get_db),
    ) -> DhcpSettingsResponse:
        """Get Dhcp Settings.

        Requires the `read:dhcp` API scope. This read-only operation does not change saved desired state
        or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return DhcpSettingsResponse.model_validate(get_dhcp_settings_row(db))

    @router.patch(
        "/dhcp/settings",
        response_model=DhcpSettingsResponse,
        tags=["DHCP"],
        operation_id="updateDhcpSettings",
    )
    def update_dhcp_settings(
        payload: DhcpSettingsUpdate,
        identity: Annotated[Identity, Depends(require_scope("write:dhcp"))],
        db: Session = Depends(get_db),
    ) -> DhcpSettingsResponse:
        """Update Dhcp Settings.

        Requires the `write:dhcp` API scope. The operation updates saved Atlaso state and does not
        bypass the documented global Appliance Apply or service lifecycle boundary.

        Args:
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        settings = get_dhcp_settings_row(db)
        for key, value in payload.model_dump().items():
            setattr(settings, key, value)
        settings.updated_at = utcnow()
        db.commit()
        db.refresh(settings)
        record_audit(
            db,
            actor=identity.username,
            action="update_dhcp_settings",
            resource_type="dhcp",
            resource_id=str(settings.id),
        )
        return DhcpSettingsResponse.model_validate(settings)

    @router.get(
        "/dhcp/scopes",
        response_model=list[DhcpScopeResponse],
        tags=["DHCP"],
        operation_id="listDhcpScopes",
    )
    def list_dhcp_scopes(
        identity: Annotated[Identity, Depends(require_scope("read:dhcp"))],
        db: Session = Depends(get_db),
    ) -> list[DhcpScopeResponse]:
        """List Dhcp Scopes.

        Requires the `read:dhcp` API scope. This read-only operation does not change saved desired state
        or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return [
            DhcpScopeResponse.model_validate(row)
            for row in db.execute(select(DhcpScope).order_by(DhcpScope.name))
            .scalars()
            .all()
        ]

    @router.post(
        "/dhcp/scopes",
        response_model=DhcpScopeResponse,
        status_code=201,
        tags=["DHCP"],
        operation_id="createDhcpScope",
    )
    def create_dhcp_scope(
        payload: DhcpScopeCreate,
        identity: Annotated[Identity, Depends(require_scope("write:dhcp"))],
        db: Session = Depends(get_db),
    ) -> DhcpScopeResponse:
        """Create Dhcp Scope.

        Requires the `write:dhcp` API scope. The operation changes saved Atlaso application state; any
        appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        scope = DhcpScope(**payload.model_dump())
        db.add(scope)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409, detail="DHCP IP zone already exists"
            ) from exc
        db.refresh(scope)
        record_audit(
            db,
            actor=identity.username,
            action="create_dhcp_scope",
            resource_type="dhcp_scope",
            resource_id=str(scope.id),
        )
        return DhcpScopeResponse.model_validate(scope)

    @router.patch(
        "/dhcp/scopes/{scope_id}",
        response_model=DhcpScopeResponse,
        tags=["DHCP"],
        operation_id="updateDhcpScope",
    )
    def update_dhcp_scope(
        scope_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the scope record addressed by this operation."
            ),
        ],
        payload: DhcpScopeCreate,
        identity: Annotated[Identity, Depends(require_scope("write:dhcp"))],
        db: Session = Depends(get_db),
    ) -> DhcpScopeResponse:
        """Update Dhcp Scope.

        Requires the `write:dhcp` API scope. The operation updates saved Atlaso state and does not
        bypass the documented global Appliance Apply or service lifecycle boundary.

        Args:
            scope_id: Stable identifier of the associated scope resource.
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        scope = db.get(DhcpScope, scope_id)
        if not scope:
            raise HTTPException(status_code=404, detail="DHCP IP zone not found")
        if payload.address_family != scope.address_family:
            raise HTTPException(
                status_code=409,
                detail="DHCP IP zone family cannot be changed after it is created",
            )
        for key, value in payload.model_dump().items():
            setattr(scope, key, value)
        scope.updated_at = utcnow()
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409, detail="DHCP IP zone already exists"
            ) from exc
        db.refresh(scope)
        record_audit(
            db,
            actor=identity.username,
            action="update_dhcp_scope",
            resource_type="dhcp_scope",
            resource_id=str(scope.id),
        )
        return DhcpScopeResponse.model_validate(scope)

    @router.delete(
        "/dhcp/scopes/{scope_id}",
        status_code=204,
        tags=["DHCP"],
        operation_id="deleteDhcpScope",
    )
    def delete_dhcp_scope(
        scope_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the scope record addressed by this operation."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("write:dhcp"))],
        db: Session = Depends(get_db),
    ) -> Response:
        """Delete Dhcp Scope.

        Requires the `write:dhcp` API scope. Removal or revocation takes effect in Atlaso application
        state; appliance host changes remain subject to the documented apply boundary for the resource.

        Args:
            scope_id: Stable identifier of the associated scope resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        scope = db.get(DhcpScope, scope_id)
        if not scope:
            raise HTTPException(status_code=404, detail="DHCP IP zone not found")
        for option in (
            db.execute(select(DhcpOption).where(DhcpOption.scope_id == scope_id))
            .scalars()
            .all()
        ):
            db.delete(option)
        db.delete(scope)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_dhcp_scope",
            resource_type="dhcp_scope",
            resource_id=str(scope_id),
        )
        return Response(status_code=204)

    @router.get(
        "/dhcp/options",
        response_model=list[DhcpOptionResponse],
        tags=["DHCP"],
        operation_id="listDhcpOptions",
    )
    def list_dhcp_options(
        identity: Annotated[Identity, Depends(require_scope("read:dhcp"))],
        db: Session = Depends(get_db),
    ) -> list[DhcpOptionResponse]:
        """List Dhcp Options.

        Requires the `read:dhcp` API scope. This read-only operation does not change saved desired state
        or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return [
            DhcpOptionResponse.model_validate(row)
            for row in db.execute(
                select(DhcpOption).order_by(DhcpOption.scope_id, DhcpOption.option_code)
            )
            .scalars()
            .all()
        ]

    @router.post(
        "/dhcp/options",
        response_model=DhcpOptionResponse,
        status_code=201,
        tags=["DHCP"],
        operation_id="createDhcpOption",
    )
    def create_dhcp_option(
        payload: DhcpOptionCreate,
        identity: Annotated[Identity, Depends(require_scope("write:dhcp"))],
        db: Session = Depends(get_db),
    ) -> DhcpOptionResponse:
        """Create Dhcp Option.

        Requires the `write:dhcp` API scope. The operation changes saved Atlaso application state; any
        appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        if payload.scope_id is not None and not db.get(DhcpScope, payload.scope_id):
            raise HTTPException(status_code=404, detail="DHCP IP zone not found")
        option = DhcpOption(**payload.model_dump())
        db.add(option)
        db.commit()
        db.refresh(option)
        record_audit(
            db,
            actor=identity.username,
            action="create_dhcp_option",
            resource_type="dhcp_option",
            resource_id=str(option.id),
        )
        return DhcpOptionResponse.model_validate(option)

    @router.patch(
        "/dhcp/options/{option_id}",
        response_model=DhcpOptionResponse,
        tags=["DHCP"],
        operation_id="updateDhcpOption",
    )
    def update_dhcp_option(
        option_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the option record addressed by this operation."
            ),
        ],
        payload: DhcpOptionCreate,
        identity: Annotated[Identity, Depends(require_scope("write:dhcp"))],
        db: Session = Depends(get_db),
    ) -> DhcpOptionResponse:
        """Update Dhcp Option.

        Requires the `write:dhcp` API scope. The operation updates saved Atlaso state and does not
        bypass the documented global Appliance Apply or service lifecycle boundary.

        Args:
            option_id: Stable identifier of the associated option resource.
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        option = db.get(DhcpOption, option_id)
        if not option:
            raise HTTPException(status_code=404, detail="DHCP option not found")
        if payload.scope_id is not None and not db.get(DhcpScope, payload.scope_id):
            raise HTTPException(status_code=404, detail="DHCP IP zone not found")
        for key, value in payload.model_dump().items():
            setattr(option, key, value)
        option.updated_at = utcnow()
        db.commit()
        db.refresh(option)
        record_audit(
            db,
            actor=identity.username,
            action="update_dhcp_option",
            resource_type="dhcp_option",
            resource_id=str(option.id),
        )
        return DhcpOptionResponse.model_validate(option)

    @router.delete(
        "/dhcp/options/{option_id}",
        status_code=204,
        tags=["DHCP"],
        operation_id="deleteDhcpOption",
    )
    def delete_dhcp_option(
        option_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the option record addressed by this operation."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("write:dhcp"))],
        db: Session = Depends(get_db),
    ) -> Response:
        """Delete Dhcp Option.

        Requires the `write:dhcp` API scope. Removal or revocation takes effect in Atlaso application
        state; appliance host changes remain subject to the documented apply boundary for the resource.

        Args:
            option_id: Stable identifier of the associated option resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        option = db.get(DhcpOption, option_id)
        if not option:
            raise HTTPException(status_code=404, detail="DHCP option not found")
        db.delete(option)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_dhcp_option",
            resource_type="dhcp_option",
            resource_id=str(option_id),
        )
        return Response(status_code=204)

    @router.get(
        "/dhcp/reservations",
        response_model=list[DhcpReservationResponse],
        tags=["DHCP"],
        operation_id="listDhcpReservations",
    )
    def list_dhcp_reservations(
        identity: Annotated[Identity, Depends(require_scope("read:dhcp"))],
        db: Session = Depends(get_db),
    ) -> list[DhcpReservationResponse]:
        """List Dhcp Reservations.

        Requires the `read:dhcp` API scope. This read-only operation does not change saved desired state
        or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return [
            DhcpReservationResponse.model_validate(row)
            for row in db.execute(
                select(DhcpReservation).order_by(DhcpReservation.hostname)
            )
            .scalars()
            .all()
        ]

    @router.get(
        "/dhcp/leases",
        response_model=list[DhcpLeaseResponse],
        tags=["DHCP"],
        operation_id="listDhcpLeases",
    )
    def list_dhcp_leases(
        identity: Annotated[Identity, Depends(require_scope("read:dhcp"))],
    ) -> list[DhcpLeaseResponse]:
        """List Dhcp Leases.

        Requires the `read:dhcp` API scope. This read-only operation does not change saved desired state
        or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
        """
        result = SystemAdapter().read_dhcp_leases()
        if result.returncode != 0:
            raise HTTPException(
                status_code=502,
                detail=result.stderr.strip() or "Unable to read dnsmasq DHCP leases.",
            )
        return [
            DhcpLeaseResponse(**lease) for lease in parse_dnsmasq_leases(result.stdout)
        ]

    @router.post(
        "/dhcp/reservations",
        response_model=DhcpReservationResponse,
        status_code=201,
        tags=["DHCP"],
        operation_id="createDhcpReservation",
    )
    def create_dhcp_reservation(
        payload: DhcpReservationCreate,
        identity: Annotated[Identity, Depends(require_scope("write:dhcp"))],
        db: Session = Depends(get_db),
    ) -> DhcpReservationResponse:
        """Create Dhcp Reservation.

        Requires the `write:dhcp` API scope. The operation changes saved Atlaso application state; any
        appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        reservation = DhcpReservation(**payload.model_dump())
        db.add(reservation)
        db.flush()
        ensure_dns_for_dhcp_reservation(db, reservation, identity.username)
        db.commit()
        db.refresh(reservation)
        record_audit(
            db,
            actor=identity.username,
            action="create_dhcp_reservation",
            resource_type="dhcp_reservation",
            resource_id=str(reservation.id),
        )
        return DhcpReservationResponse.model_validate(reservation)

    @router.delete(
        "/dhcp/reservations/{reservation_id}",
        status_code=204,
        tags=["DHCP"],
        operation_id="deleteDhcpReservation",
    )
    def delete_dhcp_reservation(
        reservation_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the reservation record addressed by this operation."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("write:dhcp"))],
        db: Session = Depends(get_db),
    ) -> Response:
        """Delete Dhcp Reservation.

        Requires the `write:dhcp` API scope. Removal or revocation takes effect in Atlaso application
        state; appliance host changes remain subject to the documented apply boundary for the resource.

        Args:
            reservation_id: Stable identifier of the associated reservation resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        reservation = db.get(DhcpReservation, reservation_id)
        if not reservation:
            raise HTTPException(status_code=404, detail="DHCP reservation not found")
        db.delete(reservation)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_dhcp_reservation",
            resource_type="dhcp_reservation",
            resource_id=str(reservation_id),
        )
        return Response(status_code=204)

    @router.post(
        "/dhcp/validate",
        response_model=ConfigValidationResponse,
        tags=["DHCP"],
        operation_id="validateDhcpConfig",
    )
    def validate_dhcp_config(
        identity: Annotated[Identity, Depends(require_scope("read:dhcp"))],
        db: Session = Depends(get_db),
    ) -> ConfigValidationResponse:
        """Validate Dhcp Config.

        Requires the `read:dhcp` API scope. The request is evaluated without persisting desired state or
        mutating appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return dnsmasq_validation_response(db)

    @router.post(
        "/dhcp/apply",
        response_model=ConfigApplyResponse,
        tags=["DHCP"],
        operation_id="applyDhcpConfig",
        include_in_schema=False,
    )
    def apply_dhcp_config(
        identity: Annotated[Identity, Depends(require_scope("write:dhcp"))],
        db: Session = Depends(get_db),
    ) -> ConfigApplyResponse:
        """Apply Dhcp Config.

        Requires the `write:dhcp` API scope. The action runs through the endpoint's existing audited
        adapter or task boundary; inspect the returned state before treating the operation as complete.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        validation = dnsmasq_validation_response(db)
        if not validation.valid:
            return ConfigApplyResponse(**validation.model_dump(), reloaded=False)
        apply_result = SystemAdapter().apply_dnsmasq_config(validation.config_path)
        reload_result = SystemAdapter().reload_dnsmasq()
        record_audit(
            db,
            actor=identity.username,
            action="apply_dhcp_config_dry_run",
            resource_type="dhcp",
            detail=" ".join(apply_result.command + [";"] + reload_result.command),
        )
        payload = validation.model_dump()
        payload["command"] = apply_result.command
        return ConfigApplyResponse(**payload, reloaded=not apply_result.dry_run)

    @router.get(
        "/dhcp/logs",
        response_model=list[str],
        tags=["DHCP"],
        operation_id="getDhcpLogs",
    )
    def get_dhcp_logs(
        identity: Annotated[Identity, Depends(require_scope("read:dhcp"))],
    ) -> list[str]:
        """Get Dhcp Logs.

        Requires the `read:dhcp` API scope. This read-only operation does not change saved desired state
        or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
        """
        return [
            "dry-run log source for dnsmasq DHCP leases",
            "Host lease files are read only on provisioned appliances.",
        ]

    endpoints: dict[str, Endpoint] = {
        "get_dns_status": get_dns_status,
        "get_dns_settings": get_dns_settings,
        "update_dns_settings": update_dns_settings,
        "list_dns_records": list_dns_records,
        "create_dns_record": create_dns_record,
        "update_dns_record": update_dns_record,
        "import_dns_hosts_file": import_dns_hosts_file,
        "delete_dns_record": delete_dns_record,
        "validate_dns_config": validate_dns_config,
        "apply_dns_config": apply_dns_config,
        "get_dns_logs": get_dns_logs,
        "get_dhcp_status": get_dhcp_status,
        "get_dhcp_settings": get_dhcp_settings,
        "update_dhcp_settings": update_dhcp_settings,
        "list_dhcp_scopes": list_dhcp_scopes,
        "create_dhcp_scope": create_dhcp_scope,
        "update_dhcp_scope": update_dhcp_scope,
        "delete_dhcp_scope": delete_dhcp_scope,
        "list_dhcp_options": list_dhcp_options,
        "create_dhcp_option": create_dhcp_option,
        "update_dhcp_option": update_dhcp_option,
        "delete_dhcp_option": delete_dhcp_option,
        "list_dhcp_reservations": list_dhcp_reservations,
        "list_dhcp_leases": list_dhcp_leases,
        "create_dhcp_reservation": create_dhcp_reservation,
        "delete_dhcp_reservation": delete_dhcp_reservation,
        "validate_dhcp_config": validate_dhcp_config,
        "apply_dhcp_config": apply_dhcp_config,
        "get_dhcp_logs": get_dhcp_logs,
        "dnsmasq_validation_response": dnsmasq_validation_response,
    }
    return DnsDhcpApiRouter(router=router, endpoints=endpoints)
