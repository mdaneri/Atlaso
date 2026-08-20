from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from secrets import token_urlsafe
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    Form,
    HTTPException,
    Request,
)
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atlaso.app.audit import record_audit
from atlaso.app.database import get_db
from atlaso.app.models import (
    DhcpOption,
    DhcpReservation,
    DhcpScope,
    DnsRecord,
    EsxiPxeHost,
    utcnow,
)
from atlaso.app.security import (
    Identity,
    require_session_identity,
)
from atlaso.app.services.dnsmasq import (
    DHCP_DENY_RESERVATION_DESCRIPTION_PREFIX,
    DNS_CONDITIONAL_FORWARDERS_SETTING_KEY,
    dhcp_option_to_dict,
    dhcp_scope_to_dict,
    dump_dns_record_data,
    join_conditional_forwarders,
    join_domains,
    join_servers,
    parse_hosts_records,
    parse_zone_records,
    split_addresses,
    split_conditional_forwarders,
    split_domains,
    split_interfaces,
    split_servers,
    validate_authoritative_dns_record,
    validate_dns_record,
)
from atlaso.app.services.esxi_pxe import (
    esxi_pxe_boot_settings,
    esxi_pxe_default_host_settings,
    normalize_installer_iso_path,
    normalize_pxe_mac,
    sync_esxi_pxe_host_network_records,
)
from atlaso.app.services.network_boot import lock_esxi_host_reference_lifecycle
from atlaso.app.ui_routes import (
    MANAGEMENT_UI_ROOT,
)

Endpoint = Callable[..., Any]


@dataclass(frozen=True)
class DnsDhcpUiDependencies:
    require_management_ui_request: Endpoint
    dns_domains_for_settings: Endpoint
    dnsmasq_apply_status: Endpoint
    dnsmasq_context: Endpoint
    ensure_dns_for_dhcp_reservation: Endpoint
    get_dhcp_settings_row: Endpoint
    get_dns_settings_row: Endpoint
    grid_error_response: Endpoint
    grid_request: Endpoint
    grid_saved_response: Endpoint
    normalize_dns_hostname: Endpoint
    parse_dhcp_option_scope_id: Endpoint
    parse_optional_esxi_kickstart_id: Endpoint
    records_for_domain: Endpoint
    render: Endpoint
    require_esxi_pxe_write: Endpoint
    resolve_service_bind_targets: Endpoint
    save_disabled_dns_domains: Endpoint
    save_dns_domain_description: Endpoint
    save_dns_domains: Endpoint
    service_bind_options: Endpoint
    set_setting_value: Endpoint
    verify_csrf: Endpoint


@dataclass(frozen=True)
class DnsDhcpUiRouter:
    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_router(dependencies: DnsDhcpUiDependencies) -> DnsDhcpUiRouter:
    """Build the DNS/DHCP UI router without importing its compatibility facade.

    Args:
        dependencies: Facade-owned helpers retained during structural extraction.

    Returns:
        Configured domain router and its stable endpoint callables.
    """
    router = APIRouter(
        prefix=MANAGEMENT_UI_ROOT,
        dependencies=[Depends(dependencies.require_management_ui_request)],
    )

    dns_domains_for_settings = dependencies.dns_domains_for_settings
    dnsmasq_apply_status = dependencies.dnsmasq_apply_status
    dnsmasq_context = dependencies.dnsmasq_context
    ensure_dns_for_dhcp_reservation = dependencies.ensure_dns_for_dhcp_reservation
    get_dhcp_settings_row = dependencies.get_dhcp_settings_row
    get_dns_settings_row = dependencies.get_dns_settings_row
    grid_error_response = dependencies.grid_error_response
    grid_request = dependencies.grid_request
    grid_saved_response = dependencies.grid_saved_response
    normalize_dns_hostname = dependencies.normalize_dns_hostname
    parse_dhcp_option_scope_id = dependencies.parse_dhcp_option_scope_id
    parse_optional_esxi_kickstart_id = dependencies.parse_optional_esxi_kickstart_id
    records_for_domain = dependencies.records_for_domain
    render = dependencies.render
    require_esxi_pxe_write = dependencies.require_esxi_pxe_write
    resolve_service_bind_targets = dependencies.resolve_service_bind_targets
    save_disabled_dns_domains = dependencies.save_disabled_dns_domains
    save_dns_domain_description = dependencies.save_dns_domain_description
    save_dns_domains = dependencies.save_dns_domains
    service_bind_options = dependencies.service_bind_options
    set_setting_value = dependencies.set_setting_value
    verify_csrf = dependencies.verify_csrf

    @router.get("/dns", response_class=HTMLResponse, response_model=None)
    def dns_page(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the dns page endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        context = dnsmasq_context(db)
        return render(
            request,
            "dns.html",
            {
                "identity": identity,
                **context,
                "appliance_apply_status": dnsmasq_apply_status(db, context),
            },
        )

    @router.post("/dns/settings", response_model=None)
    def update_dns_from_ui(
        request: Request,
        enabled: str | None = Form(None),
        listen_interfaces: list[str] = Form(default_factory=list),
        listen_addresses: list[str] = Form(default_factory=list),
        listen_interfaces_present: str | None = Form(None),
        listen_addresses_present: str | None = Form(None),
        domains: str | None = Form(None),
        upstream_servers: str = Form(""),
        conditional_forwarders: str = Form(""),
        cache_size: int = Form(1000),
        expand_hosts: str | None = Form(None),
        authoritative: str | None = Form(None),
        authoritative_server: str = Form(""),
        authoritative_contact: str = Form(""),
        authoritative_ttl: int = Form(3600),
        authoritative_refresh: int = Form(1200),
        authoritative_retry: int = Form(180),
        authoritative_expire: int = Form(1209600),
        dnssec_enabled: str | None = Form(None),
        rebind_protection_enabled: str | None = Form(None),
        rebind_domain_exemptions: str = Form(""),
        query_logging_mode: str = Form("off"),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the update dns from ui endpoint.

        Args:
            request: Incoming HTTP request.
            enabled: Whether the requested behavior is enabled.
            listen_interfaces: Interfaces on which the service should listen.
            listen_addresses: Addresses on which the service should listen.
            listen_interfaces_present: Whether the caller supplied listen interfaces.
            listen_addresses_present: Whether the caller supplied listen addresses.
            domains: Domains supplied by the caller.
            upstream_servers: Upstream servers supplied by the caller.
            conditional_forwarders: Conditional forwarders supplied by the caller.
            cache_size: Cache size supplied by the caller.
            expand_hosts: Expand hosts supplied by the caller.
            authoritative: Authoritative supplied by the caller.
            authoritative_server: Authoritative server supplied by the caller.
            authoritative_contact: Authoritative contact supplied by the caller.
            authoritative_ttl: Authoritative ttl supplied by the caller.
            authoritative_refresh: Authoritative refresh supplied by the caller.
            authoritative_retry: Authoritative retry supplied by the caller.
            authoritative_expire: Authoritative expire supplied by the caller.
            dnssec_enabled: Dnssec enabled supplied by the caller.
            rebind_protection_enabled: Rebind protection enabled supplied by the caller.
            rebind_domain_exemptions: Rebind domain exemptions supplied by the caller.
            query_logging_mode: Query logging mode supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        settings = get_dns_settings_row(db)
        available_options = service_bind_options(db)
        available_names = {item["name"] for item in available_options}
        selected_interfaces, selected_addresses = resolve_service_bind_targets(
            db,
            listen_interfaces,
            listen_addresses,
            current_interface=settings.listen_interface,
            current_address=settings.listen_address,
            listen_interfaces_present=listen_interfaces_present,
            listen_addresses_present=listen_addresses_present,
        )
        if available_names and not split_interfaces(selected_interfaces):
            selected_interfaces, selected_addresses = resolve_service_bind_targets(
                db,
                [available_options[0]["name"]],
                [],
                current_interface=settings.listen_interface,
                current_address=settings.listen_address,
                listen_interfaces_present="1",
                listen_addresses_present=None,
            )
        settings.enabled = enabled == "on"
        settings.listen_interface = selected_interfaces
        settings.listen_address = selected_addresses or None
        if domains is not None:
            settings.domain = join_domains(split_domains(domains))
        settings.upstream_servers = join_servers(split_servers(upstream_servers))
        set_setting_value(
            db,
            DNS_CONDITIONAL_FORWARDERS_SETTING_KEY,
            join_conditional_forwarders(
                split_conditional_forwarders(conditional_forwarders)
            ),
        )
        settings.cache_size = cache_size
        settings.expand_hosts = expand_hosts == "on"
        settings.authoritative = authoritative == "on"
        settings.authoritative_server = authoritative_server.strip().strip(".").lower()
        settings.authoritative_contact = (
            authoritative_contact.strip().strip(".").lower()
        )
        settings.authoritative_ttl = authoritative_ttl
        settings.authoritative_refresh = authoritative_refresh
        settings.authoritative_retry = authoritative_retry
        settings.authoritative_expire = authoritative_expire
        settings.dnssec_enabled = dnssec_enabled == "on"
        settings.rebind_protection_enabled = rebind_protection_enabled == "on"
        settings.rebind_domain_exemptions = join_domains(
            split_domains(rebind_domain_exemptions)
        )
        settings.query_logging_mode = (
            query_logging_mode
            if query_logging_mode in {"off", "queries-extra"}
            else "off"
        )
        settings.updated_at = utcnow()
        db.commit()
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
        if request.headers.get("X-Atlaso-Autosave") == "1":
            context = dnsmasq_context(db)
            return JSONResponse(
                {
                    "status": "saved",
                    "updated_at": settings.updated_at.isoformat(),
                    "listen_interfaces": split_interfaces(settings.listen_interface),
                    "listen_addresses": split_addresses(settings.listen_address),
                    "valid": not context["validation_errors"],
                    "validation_errors": context["validation_errors"],
                    "validation_warnings": context["dns_warnings"],
                    "config_path": context["dns_settings"].config_path,
                    "config_preview": context["config_preview"],
                    "observed_dhcp_upstream_servers": context[
                        "observed_dhcp_upstream_servers"
                    ],
                    "effective_upstream_servers": context["effective_upstream_servers"],
                    "dnssec_enabled": context["dns_settings"].dnssec_enabled,
                    "rebind_protection_enabled": context[
                        "dns_settings"
                    ].rebind_protection_enabled,
                    "query_logging_mode": context["dns_settings"].query_logging_mode,
                    "authoritative_serial": context[
                        "dns_settings"
                    ].authoritative_serial,
                }
            )
        return RedirectResponse("/dns", status_code=303)

    @router.post("/dns/zones", response_model=None)
    def create_dns_zone_from_ui(
        request: Request,
        domain: str = Form(...),
        description: str = Form(""),
        enabled: str | None = Form(None),
        enabled_present: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse:
        """Handle the create dns zone from ui endpoint.

        Args:
            request: Incoming HTTP request.
            domain: Managed DNS domain affected by the operation.
            description: Human-readable description of the resource.
            enabled: Whether the requested behavior is enabled.
            enabled_present: Enabled present supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        settings = get_dns_settings_row(db)
        existing_domains = dns_domains_for_settings(settings)
        new_domains = split_domains(domain)
        if len(new_domains) != 1:
            return render(
                request,
                "dns.html",
                {
                    "identity": identity,
                    **dnsmasq_context(db),
                    "form_error": "Enter one valid domain name.",
                },
                status_code=422,
            )
        new_domain = new_domains[0]
        if new_domain in existing_domains:
            return render(
                request,
                "dns.html",
                {
                    "identity": identity,
                    **dnsmasq_context(db),
                    "form_error": f"DNS domain {new_domain} already exists.",
                },
                status_code=409,
            )
        active_domains = split_domains(settings.domain) or ["atlaso.internal"]
        disabled_domains = split_domains(settings.disabled_domains)
        next_enabled = enabled == "on" if enabled_present is not None else True
        if next_enabled:
            save_dns_domains(settings, [*active_domains, new_domain])
            save_disabled_dns_domains(
                settings, [item for item in disabled_domains if item != new_domain]
            )
        else:
            save_disabled_dns_domains(settings, [*disabled_domains, new_domain])
        save_dns_domain_description(settings, new_domain, description)
        settings.updated_at = utcnow()
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="create_dns_zone",
            resource_type="dns_zone",
            resource_id=new_domain,
        )
        return grid_saved_response(
            request,
            redirect_url="/dns",
            resource_name="domain",
            resource={
                "name": new_domain,
                "description": description.strip(),
                "enabled": next_enabled,
            },
        )

    @router.post("/dns/zones/enabled", response_model=None)
    def set_dns_zone_enabled_from_ui(
        request: Request,
        domain: str = Form(...),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the set dns zone enabled from ui endpoint.

        Args:
            request: Incoming HTTP request.
            domain: Managed DNS domain affected by the operation.
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
        settings = get_dns_settings_row(db)
        normalized_domain = split_domains(domain)
        existing_domains = dns_domains_for_settings(settings)
        if len(normalized_domain) != 1 or normalized_domain[0] not in existing_domains:
            raise HTTPException(status_code=404, detail="DNS domain was not found.")
        selected_domain = normalized_domain[0]
        active_domains = split_domains(settings.domain) or ["atlaso.internal"]
        disabled_domains = split_domains(settings.disabled_domains)
        next_enabled = enabled == "on"
        if (
            not next_enabled
            and selected_domain in active_domains
            and len(active_domains) == 1
        ):
            raise HTTPException(
                status_code=422, detail="At least one DNS domain must remain enabled."
            )
        if next_enabled:
            save_dns_domains(settings, [*active_domains, selected_domain])
            save_disabled_dns_domains(
                settings, [item for item in disabled_domains if item != selected_domain]
            )
        else:
            save_dns_domains(
                settings, [item for item in active_domains if item != selected_domain]
            )
            save_disabled_dns_domains(settings, [*disabled_domains, selected_domain])
        settings.updated_at = utcnow()
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="enable_dns_zone" if next_enabled else "disable_dns_zone",
            resource_type="dns_zone",
            resource_id=selected_domain,
        )
        if grid_request(request):
            return JSONResponse(
                {"domain": {"name": selected_domain, "enabled": next_enabled}}
            )
        return RedirectResponse("/dns", status_code=303)

    @router.post("/dns/zones/delete", response_model=None)
    def delete_dns_zone_from_ui(
        request: Request,
        domain: str = Form(...),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse:
        """Handle the delete dns zone from ui endpoint.

        Args:
            request: Incoming HTTP request.
            domain: Managed DNS domain affected by the operation.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        settings = get_dns_settings_row(db)
        existing_domains = dns_domains_for_settings(settings)
        normalized_domain = split_domains(domain)
        if len(normalized_domain) != 1 or normalized_domain[0] not in existing_domains:
            return render(
                request,
                "dns.html",
                {
                    "identity": identity,
                    **dnsmasq_context(db),
                    "form_error": "DNS domain was not found.",
                },
                status_code=404,
            )
        deleted_domain = normalized_domain[0]
        if len(existing_domains) == 1:
            return render(
                request,
                "dns.html",
                {
                    "identity": identity,
                    **dnsmasq_context(db),
                    "form_error": "At least one DNS domain must remain managed.",
                },
                status_code=422,
            )
        deleted_records = records_for_domain(db, deleted_domain)
        for record in deleted_records:
            db.delete(record)
        save_dns_domains(
            settings,
            [item for item in split_domains(settings.domain) if item != deleted_domain],
        )
        save_disabled_dns_domains(
            settings,
            [
                item
                for item in split_domains(settings.disabled_domains)
                if item != deleted_domain
            ],
        )
        save_dns_domain_description(settings, deleted_domain, "")
        settings.updated_at = utcnow()
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_dns_zone",
            resource_type="dns_zone",
            resource_id=deleted_domain,
            detail=f"Deleted {len(deleted_records)} scoped DNS records.",
        )
        return RedirectResponse("/dns", status_code=303)

    @router.post("/dns/records", response_model=None)
    def create_dns_record_from_ui(
        request: Request,
        hostname: str = Form(...),
        domain: str = Form(""),
        record_type: str = Form("A"),
        address: str = Form(...),
        description: str = Form(""),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Handle the create dns record from ui endpoint.

        Args:
            request: Incoming HTTP request.
            hostname: DNS hostname of the target resource.
            domain: Managed DNS domain affected by the operation.
            record_type: Record type supplied by the caller.
            address: Network address of the target service or interface.
            description: Human-readable description of the resource.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        hostname = normalize_dns_hostname(hostname, domain)
        record_type = record_type.strip().upper()
        address = address.strip()
        record_data_json = dump_dns_record_data(record_type, address)
        validation_errors = validate_dns_record(hostname, record_type, address)
        validation_errors.extend(
            validate_authoritative_dns_record(
                get_dns_settings_row(db), hostname, record_type, address
            )
        )
        if validation_errors:
            return render(
                request,
                "dns.html",
                {
                    "identity": identity,
                    **dnsmasq_context(db),
                    "form_error": " ".join(validation_errors),
                },
                status_code=422,
            )
        existing = db.execute(
            select(DnsRecord).where(
                func.lower(DnsRecord.hostname) == hostname.lower(),
                func.lower(DnsRecord.record_type) == record_type.lower(),
                DnsRecord.address == address,
            )
        ).scalar_one_or_none()
        if existing:
            return render(
                request,
                "dns.html",
                {
                    "identity": identity,
                    **dnsmasq_context(db),
                    "form_error": f"DNS {record_type} record already exists for {hostname}.",
                },
                status_code=409,
            )
        record = DnsRecord(
            hostname=hostname,
            record_type=record_type,
            address=address,
            record_data_json=record_data_json,
            description=description or None,
            enabled=enabled == "on",
        )
        db.add(record)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return render(
                request,
                "dns.html",
                {
                    "identity": identity,
                    **dnsmasq_context(db),
                    "form_error": f"DNS {record_type} record already exists for {hostname}.",
                },
                status_code=409,
            )
        record_audit(
            db,
            actor=identity.username,
            action="create_dns_record",
            resource_type="dns_record",
            resource_id=str(record.id),
        )
        return RedirectResponse("/dns", status_code=303)

    @router.post("/dns/records/{record_id}/delete", response_model=None)
    def delete_dns_record_from_ui(
        request: Request,
        record_id: int,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Handle the delete dns record from ui endpoint.

        Args:
            request: Incoming HTTP request.
            record_id: Identifier of the record.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
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
        return RedirectResponse("/dns", status_code=303)

    @router.post("/dns/records/{record_id}/edit", response_model=None)
    def edit_dns_record_from_ui(
        request: Request,
        record_id: int,
        hostname: str = Form(...),
        domain: str = Form(""),
        record_type: str = Form("A"),
        address: str = Form(...),
        description: str = Form(""),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse:
        """Handle the edit dns record from ui endpoint.

        Args:
            request: Incoming HTTP request.
            record_id: Identifier of the record.
            hostname: DNS hostname of the target resource.
            domain: Managed DNS domain affected by the operation.
            record_type: Record type supplied by the caller.
            address: Network address of the target service or interface.
            description: Human-readable description of the resource.
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
        record = db.get(DnsRecord, record_id)
        if not record:
            raise HTTPException(status_code=404, detail="DNS record not found")
        hostname = normalize_dns_hostname(hostname, domain)
        record_type = record_type.strip().upper()
        address = address.strip()
        record_data_json = dump_dns_record_data(record_type, address)
        validation_errors = validate_dns_record(hostname, record_type, address)
        validation_errors.extend(
            validate_authoritative_dns_record(
                get_dns_settings_row(db), hostname, record_type, address
            )
        )
        if validation_errors:
            return render(
                request,
                "dns.html",
                {
                    "identity": identity,
                    **dnsmasq_context(db),
                    "form_error": " ".join(validation_errors),
                },
                status_code=422,
            )
        existing = db.execute(
            select(DnsRecord).where(
                DnsRecord.id != record_id,
                func.lower(DnsRecord.hostname) == hostname.lower(),
                func.lower(DnsRecord.record_type) == record_type.lower(),
                DnsRecord.address == address,
            )
        ).scalar_one_or_none()
        if existing:
            return render(
                request,
                "dns.html",
                {
                    "identity": identity,
                    **dnsmasq_context(db),
                    "form_error": f"DNS {record_type} record already exists for {hostname}.",
                },
                status_code=409,
            )
        record.hostname = hostname
        record.record_type = record_type
        record.address = address
        record.record_data_json = record_data_json
        record.description = description or None
        record.enabled = enabled == "on"
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return render(
                request,
                "dns.html",
                {
                    "identity": identity,
                    **dnsmasq_context(db),
                    "form_error": f"DNS {record_type} record already exists for {hostname}.",
                },
                status_code=409,
            )
        record_audit(
            db,
            actor=identity.username,
            action="update_dns_record",
            resource_type="dns_record",
            resource_id=str(record.id),
        )
        return RedirectResponse("/dns", status_code=303)

    @router.post("/dns/records/import", response_model=None)
    def import_dns_hosts_from_ui(
        request: Request,
        hosts_text: str = Form(...),
        domain: str = Form(""),
        replace_existing: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse:
        """Handle the import dns hosts from ui endpoint.

        Args:
            request: Incoming HTTP request.
            hosts_text: Hosts text supplied by the caller.
            domain: Managed DNS domain affected by the operation.
            replace_existing: Replace existing supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        parsed_records, errors = parse_hosts_records(hosts_text)
        if errors:
            return render(
                request,
                "dns.html",
                {
                    "identity": identity,
                    **dnsmasq_context(db),
                    "bulk_error": " ".join(errors),
                    "hosts_editor_text": hosts_text,
                },
                status_code=422,
            )
        scoped_domain = domain.strip().strip(".").lower()
        dns_settings = get_dns_settings_row(db)
        for item in parsed_records:
            if scoped_domain:
                item["hostname"] = normalize_dns_hostname(
                    str(item["hostname"]), scoped_domain
                )
            errors.extend(
                validate_authoritative_dns_record(
                    dns_settings,
                    str(item["hostname"]),
                    str(item["record_type"]),
                    str(item["address"]),
                )
            )
        if errors:
            return render(
                request,
                "dns.html",
                {
                    "identity": identity,
                    **dnsmasq_context(db),
                    "bulk_error": " ".join(errors),
                    "hosts_editor_text": hosts_text,
                },
                status_code=422,
            )
        replace = replace_existing == "on"
        if replace:
            records_to_delete = (
                records_for_domain(db, scoped_domain)
                if scoped_domain
                else db.execute(select(DnsRecord)).scalars().all()
            )
            for record in records_to_delete:
                db.delete(record)
            db.flush()
        for item in parsed_records:
            existing = None
            if not replace:
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
        except IntegrityError:
            db.rollback()
            return render(
                request,
                "dns.html",
                {
                    "identity": identity,
                    **dnsmasq_context(db),
                    "bulk_error": "Imported hosts contain duplicate DNS records.",
                    "hosts_editor_text": hosts_text,
                },
                status_code=409,
            )
        record_audit(
            db,
            actor=identity.username,
            action="import_dns_hosts_file",
            resource_type="dns_record",
            detail=f"Imported {len(parsed_records)} records; replace_existing={replace}",
        )
        return RedirectResponse("/dns", status_code=303)

    @router.post("/dns/zones/import", response_model=None)
    def import_dns_zone_from_ui(
        request: Request,
        domain: str = Form(...),
        zone_text: str = Form(...),
        replace_existing: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse:
        """Handle the import dns zone from ui endpoint.

        Args:
            request: Incoming HTTP request.
            domain: Managed DNS domain affected by the operation.
            zone_text: Zone text supplied by the caller.
            replace_existing: Replace existing supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        scoped_domain = domain.strip().strip(".").lower()
        parsed_records, errors = parse_zone_records(
            zone_text, scoped_domain, get_dns_settings_row(db)
        )
        if errors:
            return render(
                request,
                "dns.html",
                {
                    "identity": identity,
                    **dnsmasq_context(db),
                    "bulk_error": " ".join(errors),
                    "active_zone_import_domain": scoped_domain,
                    "zone_editor_text": zone_text,
                },
                status_code=422,
            )
        replace = replace_existing == "on"
        if replace:
            for record in records_for_domain(db, scoped_domain):
                db.delete(record)
            db.flush()
        for item in parsed_records:
            existing = None
            if not replace:
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
        except IntegrityError:
            db.rollback()
            return render(
                request,
                "dns.html",
                {
                    "identity": identity,
                    **dnsmasq_context(db),
                    "bulk_error": "Zone file contains duplicate DNS records.",
                    "active_zone_import_domain": scoped_domain,
                    "zone_editor_text": zone_text,
                },
                status_code=409,
            )
        record_audit(
            db,
            actor=identity.username,
            action="import_dns_zone_file",
            resource_type="dns_zone",
            resource_id=scoped_domain,
            detail=f"Imported {len(parsed_records)} records; replace_existing={replace}",
        )
        return RedirectResponse("/dns", status_code=303)

    @router.get("/dhcp", response_class=HTMLResponse, response_model=None)
    def dhcp_page(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the dhcp page endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        context = dnsmasq_context(db)
        return render(
            request,
            "dhcp.html",
            {
                "identity": identity,
                **context,
                "appliance_apply_status": dnsmasq_apply_status(db, context),
            },
        )

    @router.post("/dhcp/settings", response_model=None)
    def update_dhcp_from_ui(
        request: Request,
        enabled: str | None = Form(None),
        interface_name: str | None = Form(None),
        site_address: str | None = Form(None),
        prefix_length: str | None = Form(None),
        lease_time: str | None = Form(None),
        domain_name: str | None = Form(None),
        dns_server: str | None = Form(None),
        authoritative: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the update dhcp from ui endpoint.

        Args:
            request: Incoming HTTP request.
            enabled: Whether the requested behavior is enabled.
            interface_name: Linux interface name of the network target.
            site_address: Site address supplied by the caller.
            prefix_length: Prefix length supplied by the caller.
            lease_time: Lease time supplied by the caller.
            domain_name: Domain name supplied by the caller.
            dns_server: Dns server supplied by the caller.
            authoritative: Authoritative supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        settings = get_dhcp_settings_row(db)
        settings.enabled = enabled == "on"
        if interface_name is not None:
            settings.interface_name = interface_name.strip()
        if site_address is not None:
            settings.site_address = site_address.strip()
        prefix_text = (prefix_length or "").strip()
        if prefix_text:
            try:
                settings.prefix_length = int(prefix_text)
            except ValueError:
                return JSONResponse(
                    {
                        "status": "error",
                        "error": "DHCP prefix length must be an integer.",
                    },
                    status_code=422,
                )
        if lease_time is not None:
            settings.lease_time = lease_time.strip() or settings.lease_time
        if domain_name is not None:
            settings.domain_name = domain_name.strip() or settings.domain_name
        if dns_server is not None:
            settings.dns_server = dns_server.strip()
        settings.authoritative = authoritative == "on"
        settings.updated_at = utcnow()
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="update_dhcp_settings",
            resource_type="dhcp",
            resource_id=str(settings.id),
        )
        if request.headers.get("X-Atlaso-Autosave") == "1":
            return JSONResponse(
                {
                    "status": "saved",
                    "updated_at": settings.updated_at.isoformat(),
                }
            )
        return RedirectResponse("/dhcp", status_code=303)

    @router.post("/dhcp/scopes", response_model=None)
    def create_dhcp_scope_from_ui(
        request: Request,
        name: str = Form(...),
        address_family: str = Form("ipv4"),
        interface_name: str = Form(...),
        site_address: str = Form(...),
        prefix_length: int = Form(...),
        range_expression: str = Form(...),
        lease_time: str = Form(...),
        domain_name: str = Form(...),
        dns_server: str = Form(""),
        ntp_server: str = Form(""),
        description: str = Form(""),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse | JSONResponse:
        """Handle the create dhcp scope from ui endpoint.

        Args:
            request: Incoming HTTP request.
            name: Name of the target object.
            address_family: Address family supplied by the caller.
            interface_name: Linux interface name of the network target.
            site_address: Site address supplied by the caller.
            prefix_length: Prefix length supplied by the caller.
            range_expression: Range expression supplied by the caller.
            lease_time: Lease time supplied by the caller.
            domain_name: Domain name supplied by the caller.
            dns_server: Dns server supplied by the caller.
            ntp_server: Ntp server supplied by the caller.
            description: Human-readable description of the resource.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        scope = DhcpScope(
            name=name.strip(),
            address_family=address_family.strip().lower()
            if address_family.strip().lower() in {"ipv4", "ipv6"}
            else "ipv4",
            interface_name=interface_name.strip(),
            site_address=site_address.strip(),
            prefix_length=prefix_length,
            range_expression=range_expression.strip(),
            lease_time=lease_time.strip(),
            domain_name=domain_name.strip(),
            dns_server=dns_server.strip(),
            ntp_server=ntp_server.strip(),
            description=description or None,
            enabled=enabled == "on",
        )
        db.add(scope)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return grid_error_response(
                request,
                detail=f"DHCP IP zone {name} already exists.",
                status_code=409,
                template_name="dhcp.html",
                context={
                    "identity": identity,
                    **dnsmasq_context(db),
                    "form_error": f"DHCP IP zone {name} already exists.",
                },
            )
        record_audit(
            db,
            actor=identity.username,
            action="create_dhcp_scope",
            resource_type="dhcp_scope",
            resource_id=str(scope.id),
        )
        db.refresh(scope)
        return grid_saved_response(
            request,
            redirect_url="/dhcp",
            resource_name="scope",
            resource=dhcp_scope_to_dict(scope),
        )

    @router.post("/dhcp/scopes/{scope_id}/edit", response_model=None)
    def edit_dhcp_scope_from_ui(
        request: Request,
        scope_id: int,
        name: str = Form(...),
        address_family: str = Form("ipv4"),
        interface_name: str = Form(...),
        site_address: str = Form(...),
        prefix_length: int = Form(...),
        range_expression: str = Form(...),
        lease_time: str = Form(...),
        domain_name: str = Form(...),
        dns_server: str = Form(""),
        ntp_server: str = Form(""),
        description: str = Form(""),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse | JSONResponse:
        """Handle the edit dhcp scope from ui endpoint.

        Args:
            request: Incoming HTTP request.
            scope_id: Identifier of the scope.
            name: Name of the target object.
            address_family: Address family supplied by the caller.
            interface_name: Linux interface name of the network target.
            site_address: Site address supplied by the caller.
            prefix_length: Prefix length supplied by the caller.
            range_expression: Range expression supplied by the caller.
            lease_time: Lease time supplied by the caller.
            domain_name: Domain name supplied by the caller.
            dns_server: Dns server supplied by the caller.
            ntp_server: Ntp server supplied by the caller.
            description: Human-readable description of the resource.
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
        scope = db.get(DhcpScope, scope_id)
        if not scope:
            raise HTTPException(status_code=404, detail="DHCP IP zone not found")
        normalized_family = (
            address_family.strip().lower()
            if address_family.strip().lower() in {"ipv4", "ipv6"}
            else "ipv4"
        )
        if normalized_family != scope.address_family:
            return grid_error_response(
                request,
                detail="DHCP IP zone family cannot be changed after it is created.",
                status_code=409,
                template_name="dhcp.html",
                context={
                    "identity": identity,
                    **dnsmasq_context(db),
                    "form_error": "DHCP IP zone family cannot be changed after it is created.",
                },
            )
        scope.name = name.strip()
        scope.address_family = normalized_family
        scope.interface_name = interface_name.strip()
        scope.site_address = site_address.strip()
        scope.prefix_length = prefix_length
        scope.range_expression = range_expression.strip()
        scope.lease_time = lease_time.strip()
        scope.domain_name = domain_name.strip()
        scope.dns_server = dns_server.strip()
        scope.ntp_server = ntp_server.strip()
        scope.description = description or None
        scope.enabled = enabled == "on"
        scope.updated_at = utcnow()
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return grid_error_response(
                request,
                detail=f"DHCP IP zone {name} already exists.",
                status_code=409,
                template_name="dhcp.html",
                context={
                    "identity": identity,
                    **dnsmasq_context(db),
                    "form_error": f"DHCP IP zone {name} already exists.",
                },
            )
        record_audit(
            db,
            actor=identity.username,
            action="update_dhcp_scope",
            resource_type="dhcp_scope",
            resource_id=str(scope.id),
        )
        db.refresh(scope)
        return grid_saved_response(
            request,
            redirect_url="/dhcp",
            resource_name="scope",
            resource=dhcp_scope_to_dict(scope),
        )

    @router.post("/dhcp/scopes/{scope_id}/delete", response_model=None)
    def delete_dhcp_scope_from_ui(
        request: Request,
        scope_id: int,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | Response:
        """Handle the delete dhcp scope from ui endpoint.

        Args:
            request: Incoming HTTP request.
            scope_id: Identifier of the scope.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
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
        if grid_request(request):
            return Response(status_code=204)
        return RedirectResponse("/dhcp", status_code=303)

    @router.post("/dhcp/options", response_model=None)
    def create_dhcp_option_from_ui(
        request: Request,
        scope_id: str = Form("__global__"),
        option_code: str = Form(...),
        value: str = Form(...),
        description: str = Form(""),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Handle the create dhcp option from ui endpoint.

        Args:
            request: Incoming HTTP request.
            scope_id: Identifier of the scope.
            option_code: Option code supplied by the caller.
            value: Value to process.
            description: Human-readable description of the resource.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        option = DhcpOption(
            scope_id=parse_dhcp_option_scope_id(scope_id),
            option_code=option_code.strip(),
            value=value.strip(),
            description=description or None,
            enabled=enabled == "on",
        )
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
        return grid_saved_response(
            request,
            redirect_url="/dhcp",
            resource_name="option",
            resource=dhcp_option_to_dict(option),
        )

    @router.post("/dhcp/options/{option_id}/edit", response_model=None)
    def edit_dhcp_option_from_ui(
        request: Request,
        option_id: int,
        scope_id: str = Form("__global__"),
        option_code: str = Form(...),
        value: str = Form(...),
        description: str = Form(""),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the edit dhcp option from ui endpoint.

        Args:
            request: Incoming HTTP request.
            option_id: Identifier of the option.
            scope_id: Identifier of the scope.
            option_code: Option code supplied by the caller.
            value: Value to process.
            description: Human-readable description of the resource.
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
        option = db.get(DhcpOption, option_id)
        if not option:
            raise HTTPException(status_code=404, detail="DHCP option not found")
        option.scope_id = parse_dhcp_option_scope_id(scope_id)
        option.option_code = option_code.strip()
        option.value = value.strip()
        option.description = description or None
        option.enabled = enabled == "on"
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
        return grid_saved_response(
            request,
            redirect_url="/dhcp",
            resource_name="option",
            resource=dhcp_option_to_dict(option),
        )

    @router.post("/dhcp/options/{option_id}/delete", response_model=None)
    def delete_dhcp_option_from_ui(
        request: Request,
        option_id: int,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | Response:
        """Handle the delete dhcp option from ui endpoint.

        Args:
            request: Incoming HTTP request.
            option_id: Identifier of the option.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
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
        if grid_request(request):
            return Response(status_code=204)
        return RedirectResponse("/dhcp", status_code=303)

    @router.post("/dhcp/reservations", response_model=None)
    def create_dhcp_reservation_from_ui(
        request: Request,
        hostname: str = Form(...),
        mac_address: str = Form(...),
        ip_address: str = Form(...),
        description: str = Form(""),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse:
        """Handle the create dhcp reservation from ui endpoint.

        Args:
            request: Incoming HTTP request.
            hostname: DNS hostname of the target resource.
            mac_address: MAC address identifying the host or interface.
            ip_address: Ip address supplied by the caller.
            description: Human-readable description of the resource.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        reservation = DhcpReservation(
            hostname=hostname.strip(),
            mac_address=mac_address.strip(),
            ip_address=ip_address.strip(),
            description=description or None,
            enabled=enabled == "on",
        )
        db.add(reservation)
        try:
            db.flush()
            ensure_dns_for_dhcp_reservation(db, reservation, identity.username)
            db.commit()
        except IntegrityError:
            db.rollback()
            return render(
                request,
                "dhcp.html",
                {
                    "identity": identity,
                    **dnsmasq_context(db),
                    "form_error": f"DHCP reservation already exists for MAC address {mac_address}.",
                },
                status_code=409,
            )
        record_audit(
            db,
            actor=identity.username,
            action="create_dhcp_reservation",
            resource_type="dhcp_reservation",
            resource_id=str(reservation.id),
        )
        return RedirectResponse("/dhcp", status_code=303)

    def _lease_hostname_or_default(
        hostname: str, mac_address: str, *, prefix: str = "lease"
    ) -> str:
        """Return lease hostname or default.

        Args:
            hostname: DNS hostname contacted, validated, or configured by the operation.
            mac_address: Mac address consumed by lease hostname or default.
            prefix: Prefix consumed by lease hostname or default.
        """
        normalized = hostname.strip().strip(".").lower()
        if normalized and normalized != "-":
            return normalized
        mac_suffix = (
            re.sub(r"[^0-9a-f]", "", mac_address.strip().lower())[-6:]
            or token_urlsafe(3).lower()
        )
        return f"{prefix}-{mac_suffix}.atlaso.internal"

    @router.post("/dhcp/leases/pxe-host", response_model=None)
    def create_esxi_pxe_host_from_dhcp_lease(
        request: Request,
        hostname: str = Form(""),
        mac_address: str = Form(...),
        ip_address: str = Form(...),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Handle the create esxi pxe host from dhcp lease endpoint.

        Args:
            request: Incoming HTTP request.
            hostname: DNS hostname of the target resource.
            mac_address: MAC address identifying the host or interface.
            ip_address: Ip address supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        require_esxi_pxe_write(identity)
        verify_csrf(request, csrf)
        normalized_mac = mac_address.strip().lower()
        if not normalize_pxe_mac(normalized_mac):
            raise HTTPException(
                status_code=400, detail="Lease MAC address is not valid for ESXi PXE."
            )
        lock_esxi_host_reference_lifecycle(db)
        default_host = esxi_pxe_default_host_settings(db)
        normalized_iso_path = normalize_installer_iso_path(
            str(default_host.get("installer_iso_path") or "")
        )
        normalized_kickstart_id = parse_optional_esxi_kickstart_id(
            db, str(default_host.get("kickstart_id") or "")
        )
        host = db.execute(
            select(EsxiPxeHost).where(EsxiPxeHost.mac_address == normalized_mac)
        ).scalar_one_or_none()
        if host is None:
            host = EsxiPxeHost(mac_address=normalized_mac)
        host.hostname = _lease_hostname_or_default(
            hostname, normalized_mac, prefix="esxi"
        )
        host.ip_address = ip_address.strip()
        host.kickstart_id = normalized_kickstart_id
        host.installer_iso_path = normalized_iso_path
        host.enabled = True
        host.updated_at = utcnow()
        db.add(host)
        try:
            db.flush()
            sync_esxi_pxe_host_network_records(db, host, esxi_pxe_boot_settings(db))
            db.commit()
        except ValueError as exc:
            db.rollback()
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail=f"ESXi PXE host for {mac_address} already exists.",
            ) from exc
        record_audit(
            db,
            actor=identity.username,
            action="create_esxi_pxe_host_from_dhcp_lease",
            resource_type="esxi_pxe_host",
            resource_id=str(host.id),
            detail=f"mac={host.mac_address} ip={host.ip_address}",
            request_id=request.state.request_id,
        )
        return RedirectResponse("/esxi-pxe#esxi-pxe-hosts", status_code=303)

    @router.post("/dhcp/leases/deny", response_model=None)
    def deny_dhcp_lease_mac_from_ui(
        request: Request,
        hostname: str = Form(""),
        mac_address: str = Form(...),
        ip_address: str = Form(...),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Handle the deny dhcp lease mac from ui endpoint.

        Args:
            request: Incoming HTTP request.
            hostname: DNS hostname of the target resource.
            mac_address: MAC address identifying the host or interface.
            ip_address: Ip address supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        normalized_mac = mac_address.strip().lower()
        reservation = db.execute(
            select(DhcpReservation).where(DhcpReservation.mac_address == normalized_mac)
        ).scalar_one_or_none()
        if reservation is None:
            reservation = DhcpReservation(mac_address=normalized_mac)
        reservation.hostname = _lease_hostname_or_default(
            hostname, normalized_mac, prefix="deny"
        )
        reservation.ip_address = ip_address.strip()
        reservation.enabled = False
        reservation.description = (
            f"{DHCP_DENY_RESERVATION_DESCRIPTION_PREFIX}{normalized_mac}."
        )
        db.add(reservation)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail=f"DHCP reservation already exists for MAC address {mac_address}.",
            ) from exc
        record_audit(
            db,
            actor=identity.username,
            action="deny_dhcp_lease_mac",
            resource_type="dhcp_reservation",
            resource_id=str(reservation.id),
            detail=f"mac={normalized_mac}",
            request_id=request.state.request_id,
        )
        return RedirectResponse("/dhcp#dhcp-actual-leases", status_code=303)

    @router.post("/dhcp/reservations/{reservation_id}/edit", response_model=None)
    def edit_dhcp_reservation_from_ui(
        request: Request,
        reservation_id: int,
        hostname: str = Form(...),
        mac_address: str = Form(...),
        ip_address: str = Form(...),
        description: str = Form(""),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse:
        """Handle the edit dhcp reservation from ui endpoint.

        Args:
            request: Incoming HTTP request.
            reservation_id: Identifier of the reservation.
            hostname: DNS hostname of the target resource.
            mac_address: MAC address identifying the host or interface.
            ip_address: Ip address supplied by the caller.
            description: Human-readable description of the resource.
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
        reservation = db.get(DhcpReservation, reservation_id)
        if not reservation:
            raise HTTPException(status_code=404, detail="DHCP reservation not found")
        reservation.hostname = hostname.strip()
        reservation.mac_address = mac_address.strip()
        reservation.ip_address = ip_address.strip()
        reservation.description = description or None
        reservation.enabled = enabled == "on"
        try:
            ensure_dns_for_dhcp_reservation(db, reservation, identity.username)
            db.commit()
        except IntegrityError:
            db.rollback()
            return render(
                request,
                "dhcp.html",
                {
                    "identity": identity,
                    **dnsmasq_context(db),
                    "form_error": f"DHCP reservation already exists for MAC address {mac_address}.",
                },
                status_code=409,
            )
        record_audit(
            db,
            actor=identity.username,
            action="update_dhcp_reservation",
            resource_type="dhcp_reservation",
            resource_id=str(reservation.id),
        )
        return RedirectResponse("/dhcp", status_code=303)

    @router.post("/dhcp/reservations/{reservation_id}/delete", response_model=None)
    def delete_dhcp_reservation_from_ui(
        request: Request,
        reservation_id: int,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Handle the delete dhcp reservation from ui endpoint.

        Args:
            request: Incoming HTTP request.
            reservation_id: Identifier of the reservation.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
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
        return RedirectResponse("/dhcp", status_code=303)

    endpoints: dict[str, Endpoint] = {
        "dns_page": dns_page,
        "update_dns_from_ui": update_dns_from_ui,
        "create_dns_zone_from_ui": create_dns_zone_from_ui,
        "set_dns_zone_enabled_from_ui": set_dns_zone_enabled_from_ui,
        "delete_dns_zone_from_ui": delete_dns_zone_from_ui,
        "create_dns_record_from_ui": create_dns_record_from_ui,
        "delete_dns_record_from_ui": delete_dns_record_from_ui,
        "edit_dns_record_from_ui": edit_dns_record_from_ui,
        "import_dns_hosts_from_ui": import_dns_hosts_from_ui,
        "import_dns_zone_from_ui": import_dns_zone_from_ui,
        "dhcp_page": dhcp_page,
        "update_dhcp_from_ui": update_dhcp_from_ui,
        "create_dhcp_scope_from_ui": create_dhcp_scope_from_ui,
        "edit_dhcp_scope_from_ui": edit_dhcp_scope_from_ui,
        "delete_dhcp_scope_from_ui": delete_dhcp_scope_from_ui,
        "create_dhcp_option_from_ui": create_dhcp_option_from_ui,
        "edit_dhcp_option_from_ui": edit_dhcp_option_from_ui,
        "delete_dhcp_option_from_ui": delete_dhcp_option_from_ui,
        "create_dhcp_reservation_from_ui": create_dhcp_reservation_from_ui,
        "create_esxi_pxe_host_from_dhcp_lease": create_esxi_pxe_host_from_dhcp_lease,
        "deny_dhcp_lease_mac_from_ui": deny_dhcp_lease_mac_from_ui,
        "edit_dhcp_reservation_from_ui": edit_dhcp_reservation_from_ui,
        "delete_dhcp_reservation_from_ui": delete_dhcp_reservation_from_ui,
        "_lease_hostname_or_default": _lease_hostname_or_default,
    }
    return DnsDhcpUiRouter(router=router, endpoints=endpoints)
