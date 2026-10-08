"""Test managed reverse-proxy validation and atomic desired-state writes."""

import json

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from atlaso.app.models import (
    ApplianceSettings,
    AuditEvent,
    Base,
    CaSettings,
    PhysicalInterface,
    PortForward,
    ReverseProxy,
    ReverseProxyRoute,
    Setting,
)
from atlaso.app.reverse_proxy_schemas import ReverseProxyCreate
from atlaso.app.services.port_forwarding import ListenerClaim, listener_claims
from atlaso.app.services.reverse_proxies import (
    delete_proxy,
    desired_rows,
    listener_options,
    runtime_snapshot,
    save_proxy,
    set_enabled,
    validate_proxy,
    validate_service_listener_sockets,
    validate_service_proxy_dependencies,
    validation_context,
)


@pytest.mark.parametrize(("model_name", "scheme", "conflicts"), [
    ("KmsSettings", "https", True),
    ("LdapSettings", "https", True),
    ("VcfBackupSettings", "https", True),
    ("VcfPrivateRegistrySettings", "https", True),
    ("OidcProviderSettings", "http", True),
    ("OidcProviderSettings", "https", False),
    ("VcfOfflineDepotSettings", "http", True),
    ("VcfOfflineDepotSettings", "https", False),
    ("NtpSettings", "http", False),
])
def test_service_socket_guard_retains_exclusive_and_shared_protocol_ownership(model_name, scheme, conflicts):
    """Validate service-first and proxy-first ownership with shared nginx exceptions.

    Args:
        model_name: Canonical service settings model owning the requested socket.
        scheme: Existing proxy protocol on the shared TCP port.
        conflicts: Whether the service must reject the enabled proxy socket.
    """
    from atlaso.app import models
    from atlaso.app.services.network_objects import acquire_network_objects_write_lock

    engine, db = create_db()
    try:
        proxy = save_proxy(db, payload(enabled=True, scheme=scheme, port=9443, redirect_http=False), actor="test")
        acquire_network_objects_write_lock(db)
        service = getattr(models, model_name)(enabled=True, port=9443, listen_interface="eth1", listen_address="192.168.1.10")
        if model_name == "LdapSettings":
            service.ldaps_enabled = True
        db.add(service)
        db.flush()
        if conflicts:
            with pytest.raises(ValueError, match="Service listener conflicts"):
                validate_service_listener_sockets(db)
            assert "exclusive Atlaso service" in " ".join(validate_proxy(proxy, validation_context(db), [proxy], exclude_id=proxy.id))
            proxy.enabled = False
        validate_service_listener_sockets(db)
    finally:
        db.rollback()
        db.close()
        engine.dispose()


@pytest.mark.parametrize("model_name", ["CaSettings", "KmsSettings", "LdapSettings", "EsxStorageSettings",
                                       "OidcProviderSettings", "NtpSettings", "VcfBackupSettings",
                                       "VcfOfflineDepotSettings", "VcfPrivateRegistrySettings"])
def test_service_hostname_edits_preserve_disabled_proxy_ownership(model_name):
    """Reserve proxy names even before enabling their listener.

    Args:
        model_name: Service settings owner whose candidate hostname is changed.
    """
    from atlaso.app import models

    engine, db = create_db()
    try:
        proxy = save_proxy(db, payload(), actor="test")
        before = runtime_snapshot(db)
        model = getattr(models, model_name)
        service = db.scalar(select(model))
        if service is None:
            service = model()
            db.add(service)
        field = "portal_hostname" if model_name == "CaSettings" else "hostname"
        setattr(service, field, proxy.hostname.upper() + ".")
        with pytest.raises(ValueError, match="Service hostname conflicts"):
            validate_service_proxy_dependencies(db)
        db.rollback()
        assert runtime_snapshot(db) == before
    finally:
        db.close()
        engine.dispose()


@pytest.mark.parametrize(("scheme", "enabled"), [("https", False), ("http", True)])
def test_ca_disable_retains_disabled_https_and_enabled_http(scheme, enabled):
    """Permit CA retirement when no saved proxy requires an active HTTPS leaf.

    Args:
        scheme: Client-facing protocol of the saved proxy.
        enabled: Desired proxy availability.
    """
    engine, db = create_db()
    try:
        save_proxy(db, payload(scheme=scheme, enabled=enabled, port=9443, redirect_http=False), actor="test")
        db.scalar(select(CaSettings)).enabled = False
        validate_service_proxy_dependencies(db)
        db.commit()
        assert not db.scalar(select(CaSettings)).enabled
    finally:
        db.close()
        engine.dispose()


def payload(**overrides):
    """Return one safe HTTPS virtual-host request for a lab target.

    Args:
        **overrides: Input used by payload.
    """
    value = {
        "name": "Application",
        "description": "Internal application",
        "hostname": "application.example.test",
        "scheme": "https",
        "port": 443,
        "redirect_http": True,
        "redirect_port": 80,
        "enabled": False,
        "public_listing": True,
        "managed_dns": False,
        "listeners": [{"interface": "eth1", "address": "192.168.1.10"}],
        "connect_timeout": 5,
        "read_timeout": 60,
        "send_timeout": 60,
        "body_limit": 16777216,
        "routes": [
            {
                "path_prefix": "/",
                "upstream_scheme": "http",
                "upstream_host": "10.10.20.30",
                "upstream_port": 8080,
                "path_behavior": "preserve",
                "trust_mode": "trusted_ca",
            }
        ],
    }
    value.update(overrides)
    return value


@pytest.mark.parametrize(("scheme", "conflicts"), [("http", False), ("https", True)])
def test_network_boot_save_preserves_proxy_protocol_ownership(scheme, conflicts):
    """Allow shared HTTP and roll back a Network Boot edit taking an HTTPS socket.

    Args:
        scheme: Enabled proxy protocol on the candidate Network Boot port.
        conflicts: Whether the requested HTTP publication must be rejected.
    """
    from atlaso.app.services.esxi_pxe import (
        esxi_pxe_boot_settings,
        save_esxi_pxe_boot_settings,
    )

    engine, db = create_db()
    try:
        save_proxy(db, payload(enabled=True, scheme=scheme, port=9443, redirect_http=False), actor="test")
        before = esxi_pxe_boot_settings(db)
        values = {"enabled": True, "hostname": "pxe.example.test", "listen_interface": "eth1",
                  "listen_address": "192.168.1.10", "http_port": 9443,
                  "tftp_root": before["tftp_root"], "bios_bootfile": before["bios_bootfile"],
                  "uefi_bootfile": before["uefi_bootfile"]}
        if conflicts:
            with pytest.raises(ValueError, match="Service listener conflicts"):
                save_esxi_pxe_boot_settings(db, **values)
            db.rollback()
            assert esxi_pxe_boot_settings(db) == before
        else:
            assert save_esxi_pxe_boot_settings(db, **values)["http_port"] == 9443
    finally:
        db.rollback()
        db.close()
        engine.dispose()


def create_db() -> tuple[object, Session]:
    """Create an isolated in-memory database with one eligible public listener."""
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    db = Session(engine)
    db.add_all(
        [
            PhysicalInterface(
                name="eth1",
                mac_address="02:00:00:00:00:01",
                admin_state="up",
                oper_state="up",
                role="access",
                mode="access",
                ip_cidr="192.168.1.10/24",
            ),
            PhysicalInterface(
                name="eth0",
                mac_address="02:00:00:00:00:02",
                admin_state="up",
                oper_state="up",
                role="management",
                mode="access",
                ip_cidr="192.168.2.10/24",
            ),
            ApplianceSettings(fqdn="core.atlaso.internal"),
            CaSettings(enabled=True),
        ]
    )
    db.commit()
    return engine, db


def test_managed_dns_hostname_bound_prevents_invalid_owned_record():
    """Reject a DNS-owned name beyond the record response contract before save."""
    engine, db = create_db()
    try:
        hostname = ".".join(["a" * 60, "b" * 60, "test"])
        with pytest.raises(ValueError, match="at most 120 characters"):
            save_proxy(db, payload(hostname=hostname, managed_dns=True), actor="operator")
        assert list(db.scalars(select(ReverseProxy))) == []
    finally:
        db.close()
        engine.dispose()


def test_live_https_requires_ca_for_save_enable_and_publication_readiness():
    """Preserve disabled HTTPS intent and reject enabled publication without a CA."""
    from atlaso.app.services.reverse_proxy_publication import context

    engine, db = create_db()
    try:
        db.scalar(select(CaSettings)).enabled = False
        db.commit()
        saved = save_proxy(db, payload(), actor="test")
        before = runtime_snapshot(db)
        with pytest.raises(ValueError, match="require an enabled CA"):
            set_enabled(db, saved.id, enabled=True, actor="test")
        assert runtime_snapshot(db) == before
        with pytest.raises(ValueError, match="require an enabled CA"):
            save_proxy(db, payload(name="Other", hostname="other.example.test", enabled=True), actor="test")
        assert runtime_snapshot(db) == before
        save_proxy(db, payload(name="HTTP", hostname="http.example.test", scheme="http", port=8080,
                               redirect_http=False, enabled=True), actor="test")
        saved.enabled = True
        db.flush()
        assert any("enabled CA" in error for error in context(db)["reverse_proxy_validation_errors"])
    finally:
        db.rollback()
        db.close()
        engine.dispose()


@pytest.mark.parametrize(("configured", "target"), [("Ns1.Example.Test.", "served"), ("Ns1.Example.Test.", "upstream"),
                                                       ("", "served"), ("", "upstream")])
def test_authoritative_dns_primary_hostname_is_reserved(configured, target):
    """Reserve explicit and default nameserver identities in both proxy positions.

    Args:
        configured: Canonicalizable configured primary hostname or empty default.
        target: Served proxy hostname or upstream route target.
    """
    from atlaso.app.models import DnsSettings

    engine, db = create_db()
    try:
        db.add(DnsSettings(enabled=True, authoritative=True, domain="example.test", authoritative_server=configured))
        db.commit()
        request = payload()
        if target == "served":
            request["hostname"] = "ns1.example.test"
        else:
            request["routes"][0]["upstream_host"] = "ns1.example.test"
        with pytest.raises(ValueError, match="Atlaso.*service"):
            save_proxy(db, request, actor="test")
        assert list(db.scalars(select(ReverseProxy))) == []
    finally:
        db.close()
        engine.dispose()


@pytest.mark.parametrize("upstream", ["application.example.test", "peer.example.test"])
def test_reverse_proxy_hostnames_are_reserved_as_upstreams(upstream):
    """Prevent self and peer proxy targets that resolve onto appliance listeners.

    Args:
        upstream: Input used by test reverse proxy hostnames are reserved as upstreams.
    """
    engine, db = create_db()
    try:
        save_proxy(db, payload(name="Peer", hostname="peer.example.test"), actor="operator")
        candidate = payload()
        candidate["routes"][0]["upstream_host"] = upstream
        with pytest.raises(ValueError, match="managed reverse-proxy hostname"):
            save_proxy(db, candidate, actor="operator")
        assert len(list(db.scalars(select(ReverseProxy)))) == 1
    finally:
        db.close()
        engine.dispose()


@pytest.mark.parametrize(
    ("setting_value", "reserved_hostname"),
    [
        (None, "esxi-pxe.atlaso.internal"),
        ("", "esxi-pxe.atlaso.internal"),
        ("boot.example.test", "boot.example.test"),
    ],
)
@pytest.mark.parametrize("target", ["served", "upstream"])
def test_network_boot_hostname_is_reserved_for_serving_and_upstreams(
    setting_value, reserved_hostname, target
):
    """Reserve the configured PXE name or canonical default, even while disabled.

    Args:
        setting_value: Input used by test network boot hostname is reserved for serving and upstreams.
        reserved_hostname: Input used by test network boot hostname is reserved for serving and upstreams.
        target: Served or upstream hostname relationship under test.
    """
    engine, db = create_db()
    try:
        if setting_value is not None:
            db.add(Setting(key="esxi_pxe.boot.hostname", value=setting_value))
            db.add(Setting(key="esxi_pxe.boot.enabled", value="false"))
            db.commit()

        request = payload(hostname=reserved_hostname)
        if target == "upstream":
            request["hostname"] = "application.example.test"
            request["routes"] = [
                {**payload()["routes"][0], "upstream_host": reserved_hostname}
            ]
            message = "Atlaso-owned service hostname"
        else:
            message = "owned by an Atlaso service"

        with pytest.raises(ValueError, match=message):
            save_proxy(db, request, actor="operator")
        assert desired_rows(db) == []
    finally:
        db.close()
        engine.dispose()


def test_proxy_rename_can_target_its_released_old_hostname():
    """Exclude the replaced row from peer reservations while keeping its new name protected."""
    engine, db = create_db()
    try:
        original = save_proxy(db, payload(), actor="operator")
        old_hostname = original.hostname
        replacement = payload(
            hostname="renamed.example.test",
            routes=[
                {**payload()["routes"][0], "upstream_host": old_hostname}
            ],
        )

        updated = save_proxy(db, replacement, actor="operator", proxy_id=original.id)

        assert updated.hostname == "renamed.example.test"
        assert updated.routes[0].upstream_host == old_hostname
    finally:
        db.close()
        engine.dispose()


def test_schema_canonicalizes_hostnames_and_fingerprints():
    """Normalize harmless DNS/fingerprint formatting before saving."""
    request = ReverseProxyCreate.model_validate(
        payload(
            hostname="Application.Example.Test.",
            routes=[
                {
                    "path_prefix": "/secure",
                    "upstream_scheme": "https",
                    "upstream_host": "Backend.Example.Test.",
                    "upstream_port": 8443,
                    "trust_mode": "fingerprint",
                    "fingerprint": ":".join(["AA"] + ["BB"] * 30 + ["CC"]),
                }
            ],
        )
    )
    assert request.hostname == "application.example.test"
    assert request.routes[0].upstream_host == "backend.example.test"
    assert request.routes[0].fingerprint == "aa" + "bb" * 30 + "cc"


@pytest.mark.parametrize(
    "route,match",
    [
        ({"path_prefix": "/%2e%2e/private"}, "encoded"),
        ({"path_prefix": "/safe; include /etc/passwd"}, "path prefix"),
        ({"path_prefix": "/safe$var"}, "path prefix"),
        ({"upstream_host": "https://user:pass@example.test"}, "upstream DNS"),
        ({"upstream_host": "[fe80::1%eth0]"}, "upstream DNS"),
        ({"trust_mode": "insecure"}, "Acknowledge"),
        ({"trust_mode": "insecure", "insecure_acknowledged": True, "upstream_scheme": "http"}, "HTTP upstreams"),
    ],
)
def test_schema_rejects_ambiguous_paths_hosts_and_unreviewed_trust(route, match):
    """Reject nginx syntax ambiguity, special destinations and missing acknowledgements.

    Args:
        route: Input used by test schema rejects ambiguous paths hosts and unreviewed trust.
        match: Expected validation error text.
    """
    candidate = payload(routes=[{**payload()["routes"][0], **route}])
    with pytest.raises(ValidationError, match=match):
        ReverseProxyCreate.model_validate(candidate)


def test_acknowledged_insecure_upstream_emits_bounded_operational_warning(caplog):
    """Warn on a persisted trust exception using only proxy identity and route count.

    Args:
        caplog: Captured bounded operational events.
    """
    engine, db = create_db()
    try:
        caplog.set_level("WARNING", logger="atlaso.operational")
        with pytest.raises(ValidationError, match="Acknowledge"):
            save_proxy(
                db,
                payload(routes=[{**payload()["routes"][0], "trust_mode": "insecure"}]),
                actor="operator",
            )
        assert not [record for record in caplog.records if record.name == "atlaso.operational"]

        save_proxy(
            db,
            payload(routes=[{
                **payload()["routes"][0],
                "upstream_scheme": "https",
                "trust_mode": "insecure",
                "insecure_acknowledged": True,
            }]),
            actor="operator",
        )
        warnings = [record for record in caplog.records if record.name == "atlaso.operational"]
        assert len(warnings) == 1
        assert warnings[0].getMessage() == (
            "Reverse proxy desired state saved with acknowledged insecure upstream verification: "
            "proxy_id=1 routes=1"
        )
        assert "10.10.20.30" not in warnings[0].getMessage()
        assert "application.example.test" not in warnings[0].getMessage()
    finally:
        db.close()
        engine.dispose()


@pytest.mark.parametrize(
    "overrides,match",
    [
        ({"connect_timeout": 31}, "less than or equal to 30"),
        ({"read_timeout": 301}, "less than or equal to 300"),
        ({"send_timeout": 301}, "less than or equal to 300"),
        ({"body_limit": 0}, "greater than or equal to 1"),
        ({"body_limit": 1073741825}, "less than or equal to 1073741824"),
        ({"routes": [{**payload()["routes"][0], "path_prefix": "/api"}, {**payload()["routes"][0], "path_prefix": "/api/v1"}]}, "overlap"),
    ],
)
def test_schema_and_service_enforce_bounded_runtime_and_unambiguous_routes(overrides, match):
    """Reject out-of-policy timeouts/body sizes and overlapping route prefixes.

    Args:
        overrides: Desired-state fields replaced by the fixture.
        match: Expected validation error text.
    """
    engine, db = create_db()
    try:
        try:
            request = ReverseProxyCreate.model_validate(payload(**overrides))
        except ValidationError as exc:
            assert match in str(exc).lower()
            return
        candidate = ReverseProxy(**request.model_dump(exclude={"routes"}), routes=[])
        candidate.listeners = [listener.model_dump() for listener in request.listeners]
        candidate.routes = [
            ReverseProxyRoute(**route.model_dump(exclude={"id", "insecure_acknowledged"}), position=index)
            for index, route in enumerate(request.routes)
        ]
        errors = validate_proxy(candidate, validation_context(db), [])
        assert any(match in error.lower() for error in errors)
    finally:
        db.close()
        engine.dispose()


def test_listener_options_exclude_management_and_require_exact_saved_addresses():
    """Offer only configured non-management interface addresses."""
    engine, db = create_db()
    try:
        assert listener_options(db) == [{"interface": "eth1", "address": "192.168.1.10"}]
        request = ReverseProxyCreate.model_validate(
            payload(listeners=[{"interface": "eth0", "address": "192.168.2.10"}])
        )
        candidate = ReverseProxy(**request.model_dump(exclude={"routes"}), routes=[])
        candidate.listeners = [listener.model_dump() for listener in request.listeners]
        candidate.routes = [
            ReverseProxyRoute(**route.model_dump(exclude={"id", "insecure_acknowledged"}), position=index)
            for index, route in enumerate(request.routes)
        ]
        assert any("non-management" in error for error in validate_proxy(candidate, validation_context(db), []))
    finally:
        db.close()
        engine.dispose()


def test_validation_rejects_special_listener_addresses_reserved_paths_and_empty_routes():
    """Protect Atlaso routes and fail closed for manually built empty candidates."""
    engine, db = create_db()
    try:
        special_listener = ReverseProxyCreate.model_validate(
            payload(listeners=[{"interface": "eth1", "address": "127.0.0.1"}])
        )
        special_candidate = ReverseProxy(
            **special_listener.model_dump(exclude={"routes"}),
            routes=[
                ReverseProxyRoute(
                    **special_listener.routes[0].model_dump(exclude={"id", "insecure_acknowledged"}),
                    position=0,
                )
            ],
        )
        special_candidate.listeners = [listener.model_dump() for listener in special_listener.listeners]
        assert any("non-management interface" in error for error in validate_proxy(
            special_candidate, validation_context(db), []
        ))

        reserved = ReverseProxyCreate.model_validate(
            payload(routes=[{**payload()["routes"][0], "path_prefix": "/API/v1"}])
        )
        reserved_candidate = ReverseProxy(
            **reserved.model_dump(exclude={"routes"}),
            routes=[
                ReverseProxyRoute(
                    **reserved.routes[0].model_dump(exclude={"id", "insecure_acknowledged"}),
                    position=0,
                )
            ],
        )
        reserved_candidate.listeners = [listener.model_dump() for listener in reserved.listeners]
        assert any("reserved Atlaso" in error for error in validate_proxy(
            reserved_candidate, validation_context(db), []
        ))

        empty_candidate = ReverseProxy(**reserved.model_dump(exclude={"routes"}), routes=[])
        empty_candidate.listeners = [listener.model_dump() for listener in reserved.listeners]
        assert any("at least one path route" in error for error in validate_proxy(
            empty_candidate, validation_context(db), []
        ))
    finally:
        db.close()
        engine.dispose()


def test_named_nginx_front_doors_share_sockets_but_exclusive_claims_block():
    """Allow distinct names on standard nginx ports and reject other socket owners."""
    engine, db = create_db()
    try:
        first = save_proxy(db, ReverseProxyCreate.model_validate(payload(enabled=True)), actor="operator")
        second = ReverseProxyCreate.model_validate(
            payload(name="Second", hostname="second.example.test", enabled=True)
        )
        assert not validate_candidate(db, second, existing=desired_rows(db))
        duplicate_hostname = ReverseProxyCreate.model_validate(
            payload(name="Duplicate hostname", enabled=True)
        )
        assert any("hostname already exists" in error for error in validate_candidate(
            db, duplicate_hostname, existing=desired_rows(db)
        ))

        context = validation_context(db)
        context["claims"] = [ListenerClaim("eth1", "192.168.1.10", "tcp", 9443, 9443)]
        blocked = ReverseProxyCreate.model_validate(
            payload(name="Custom", hostname="custom.example.test", port=9443, redirect_http=False)
        )
        assert any("exclusive Atlaso" in error for error in validate_candidate(db, blocked, context=context))

        assert first.hostname == "application.example.test"
    finally:
        db.close()
        engine.dispose()


def validate_candidate(db: Session, request: ReverseProxyCreate, *, context=None, existing=None) -> list[str]:
    """Build a complete model candidate for service-level validation.

    Args:
        db: Caller-owned database session for proxy desired state.
        request: Incoming browser request carrying the payload and CSRF token.
        context: Validated listener, address, service, and socket inventory.
        existing: Current proxy collection used for replacement and conflict checks.
    """
    values = request.model_dump(exclude={"routes"})
    values["listeners"] = [listener.model_dump() for listener in request.listeners]
    candidate = ReverseProxy(**values)
    candidate.routes = [
        ReverseProxyRoute(**route.model_dump(exclude={"id", "insecure_acknowledged"}), position=index)
        for index, route in enumerate(request.routes)
    ]
    return validate_proxy(candidate, context or validation_context(db), existing or [])


def test_enabled_port_forward_claims_are_exclusive_for_shared_listener():
    """Keep destination NAT mappings exclusive even on shareable nginx ports."""
    engine, db = create_db()
    try:
        db.add(
            PortForward(
                name="Existing forward",
                enabled=True,
                ip_family=4,
                ingress_interface="eth1",
                listener_address="192.168.1.10",
                protocol="tcp",
                external_port_start=443,
                external_port_end=443,
                target_address="10.10.20.40",
                target_port_start=443,
                target_port_end=443,
            )
        )
        db.commit()
        errors = validate_candidate(db, ReverseProxyCreate.model_validate(payload()))
        assert any("exclusive port-forward" in error for error in errors)
    finally:
        db.close()
        engine.dispose()


def test_enabled_reverse_proxy_claims_exact_sockets_for_port_forwarding():
    """Reserve the proxy's exact TCP listen and redirect sockets from DNAT."""
    engine, db = create_db()
    try:
        proxy = save_proxy(db, payload(enabled=True), actor="operator")
        claims = listener_claims(db)
        assert ListenerClaim("eth1", "192.168.1.10", "tcp", 443, 443) in claims
        assert ListenerClaim("eth1", "192.168.1.10", "tcp", 80, 80) in claims
        base_claims = listener_claims(db, include_reverse_proxies=False)
        assert not any(claim.interface == "eth1" and claim.address == "192.168.1.10" for claim in base_claims)
        proxy.enabled = False
        db.commit()
        assert ListenerClaim("eth1", "192.168.1.10", "tcp", 443, 443) not in listener_claims(db)
    finally:
        db.close()
        engine.dispose()


def test_service_rejects_appliance_addresses_and_service_hostnames_as_upstreams():
    """Prevent upstream loops to appliance addresses and Atlaso service identities."""
    engine, db = create_db()
    try:
        request = payload(
            routes=[{**payload()["routes"][0], "upstream_host": "192.168.1.10"}]
        )
        with pytest.raises(ValueError, match="assigned to this Atlaso appliance"):
            save_proxy(db, request, actor="operator")

        request = payload(
            routes=[{**payload()["routes"][0], "upstream_host": "core.atlaso.internal"}]
        )
        with pytest.raises(ValueError, match="Atlaso-owned service hostname"):
            save_proxy(db, request, actor="operator")

        request = payload(
            routes=[{**payload()["routes"][0], "upstream_host": "127.0.0.1"}]
        )
        with pytest.raises(ValueError, match="ordinary unicast"):
            save_proxy(db, request, actor="operator")
    finally:
        db.close()
        engine.dispose()


def test_esx_storage_hostname_is_reserved_for_serving_and_upstreams():
    """Preserve the canonical ESX hostname even when its service is disabled."""
    from atlaso.app.models import EsxStorageSettings

    engine, db = create_db()
    try:
        db.add(EsxStorageSettings(hostname="nfs.atlaso.internal"))
        db.commit()
        with pytest.raises(ValueError, match="owned by an Atlaso service"):
            save_proxy(db, payload(hostname="nfs.atlaso.internal"), actor="operator")
        with pytest.raises(ValueError, match="Atlaso-owned"):
            save_proxy(db, payload(routes=[{**payload()["routes"][0], "upstream_host": "nfs.atlaso.internal"}]), actor="operator")
        assert desired_rows(db) == []
    finally:
        db.close()
        engine.dispose()


def test_listener_fanout_is_bounded_before_saved_state_or_audit():
    """Count selected listeners across disabled proxies before later enablement."""
    engine, db = create_db()
    try:
        listeners = [{"interface": "eth1", "address": "192.168.1.10"}]
        for index in range(2, 17):
            address = f"192.168.1.{index + 9}"
            db.add(PhysicalInterface(name=f"eth{index}", mac_address=f"02:00:00:00:01:{index:02x}",
                                     admin_state="up", oper_state="up", role="access", mode="access", ip_cidr=address + "/24"))
            listeners.append({"interface": f"eth{index}", "address": address})
        db.commit()
        for index in range(16):
            save_proxy(db, payload(name=f"Application {index}", hostname=f"app{index}.example.test", listeners=listeners), actor="operator")
        before_audits = list(db.scalars(select(AuditEvent)))
        with pytest.raises(ValueError, match="listener/route combinations"):
            save_proxy(db, payload(name="Excess", hostname="excess.example.test", listeners=listeners), actor="operator")
        assert len(desired_rows(db)) == 16
        assert list(db.scalars(select(AuditEvent))) == before_audits
    finally:
        db.close()
        engine.dispose()


def test_save_replaces_routes_atomically_preserves_owned_ids_and_audits(monkeypatch):
    """Preserve submitted child identities and roll back when audit commit fails.

    Args:
        monkeypatch: Scoped dependency replacements supplied by pytest.
    """
    engine, db = create_db()
    try:
        created = save_proxy(db, payload(), actor="operator")
        original_route_id = created.routes[0].id
        replacement = payload(
            routes=[
                {**payload()["routes"][0], "id": original_route_id, "path_prefix": "/app"},
                {**payload()["routes"][0], "path_prefix": "/health"},
            ]
        )
        updated = save_proxy(db, replacement, actor="operator", proxy_id=created.id)
        assert updated.routes[0].id == original_route_id
        assert updated.routes[1].id != original_route_id
        assert [route.position for route in updated.routes] == [0, 1]
        assert [route.path_prefix for route in updated.routes] == ["/app", "/health"]
        assert len(list(db.scalars(select(AuditEvent)))) == 2
        assert runtime_snapshot(db)[0]["routes"][0]["position"] == 0
        replaced_route_ids = {route.id for route in updated.routes}
        retained_route_id = updated.routes[1].id

        replaced = save_proxy(
            db,
            payload(
                routes=[
                    {**payload()["routes"][0], "path_prefix": "/replacement"},
                    {**payload()["routes"][0], "id": retained_route_id, "path_prefix": "/health"},
                ]
            ),
            actor="operator",
            proxy_id=created.id,
        )
        replacement_route_id = replaced.routes[0].id
        assert replacement_route_id not in replaced_route_ids
        assert [(route.id, route.position) for route in replaced.routes] == [
            (replacement_route_id, 0),
            (retained_route_id, 1),
        ]

        reordered = save_proxy(
            db,
            payload(
                routes=[
                    {**payload()["routes"][0], "id": replacement_route_id, "path_prefix": "/replacement"},
                    {**payload()["routes"][0], "path_prefix": "/health"},
                ]
            ),
            actor="operator",
            proxy_id=created.id,
        )
        retained_route_id = reordered.routes[1].id
        swapped = save_proxy(
            db,
            payload(
                routes=[
                    {**payload()["routes"][0], "id": retained_route_id, "path_prefix": "/health"},
                    {**payload()["routes"][0], "id": replacement_route_id, "path_prefix": "/replacement"},
                ]
            ),
            actor="operator",
            proxy_id=created.id,
        )
        assert [(route.id, route.position) for route in swapped.routes] == [
            (retained_route_id, 0),
            (replacement_route_id, 1),
        ]

        foreign = save_proxy(
            db,
            payload(name="Other", hostname="other.example.test", listeners=payload()["listeners"]),
            actor="operator",
        )
        foreign_route_id = foreign.routes[0].id
        with pytest.raises(ValueError, match="must belong to the reverse proxy"):
            save_proxy(
                db,
                payload(routes=[{**payload()["routes"][0], "id": foreign_route_id}]),
                actor="operator",
                proxy_id=created.id,
            )

        original_commit = db.commit

        def fail_commit():
            raise RuntimeError("audit commit failed")

        monkeypatch.setattr(db, "commit", fail_commit)
        with pytest.raises(RuntimeError, match="audit commit failed"):
            save_proxy(db, payload(description="not saved"), actor="operator", proxy_id=created.id)
        monkeypatch.setattr(db, "commit", original_commit)
        refreshed = db.get(ReverseProxy, created.id)
        assert refreshed is not None and refreshed.description == "Internal application"
    finally:
        db.close()
        engine.dispose()


def test_enable_and_delete_use_complete_audited_operations():
    """Enable through complete replacement and delete the proxy with its routes."""
    engine, db = create_db()
    try:
        proxy = save_proxy(db, payload(), actor="operator")
        enabled = set_enabled(db, proxy.id, enabled=True, actor="operator")
        assert enabled.enabled is True
        assert enabled.routes[0].id == proxy.routes[0].id
        delete_proxy(db, proxy.id, actor="operator")
        assert db.get(ReverseProxy, proxy.id) is None
        assert list(db.scalars(select(ReverseProxyRoute))) == []
        actions = [row.action for row in db.scalars(select(AuditEvent)).all()]
        assert actions == ["create_reverse_proxy", "update_reverse_proxy", "delete_reverse_proxy"]
    finally:
        db.close()
        engine.dispose()


@pytest.mark.parametrize("operation", ["save", "delete"])
def test_proxy_mutations_capture_legacy_applied_service_dns_before_reconcile(monkeypatch, operation):
    """Keep DNS rows from an older apply baseline before proxy reconciliation changes desired state.

    Args:
        monkeypatch: Scoped dependency replacements supplied by pytest.
        operation: Proxy mutation selected by the fixture.
    """
    from atlaso.app import ui
    from atlaso.app.services import applied_service_dns

    engine, db = create_db()
    try:
        proxy = save_proxy(db, payload(), actor="operator") if operation == "delete" else None
        legacy_record = {
            "hostname": "legacy-service.example.test",
            "record_type": "A",
            "address": "192.168.1.10",
            "description": "Atlaso service record",
            "generated_ptr": "false",
            "source_interface": "eth1",
        }
        db.add(Setting(
            key=ui.APPLIANCE_APPLY_BASELINES_KEY,
            value=json.dumps({"dnsmasq": {"config_preview": "previous applied dns preview"}}),
        ))
        db.commit()

        observations = []

        def capture_legacy_rows(session, _preview):
            """Run capture legacy rows for the bounded proxy operation.

            Args:
                session: Caller-owned database session used by the fixture.
                _preview: Rendered DNS snapshot passed to the ownership capture fixture.
            """
            observations.append(len(list(session.scalars(select(ReverseProxy)))))
            return [legacy_record]

        monkeypatch.setattr(applied_service_dns, "owned_service_dns_records", capture_legacy_rows)
        if operation == "save":
            save_proxy(db, payload(), actor="operator")
            assert observations == [0]
        else:
            assert proxy is not None
            delete_proxy(db, proxy.id, actor="operator")
            assert observations == [1]

        baseline = ui.load_appliance_apply_baselines(db)["dnsmasq"]
        assert baseline["service_dns_records"] == [legacy_record]
    finally:
        db.close()
        engine.dispose()


@pytest.mark.parametrize("change", [
    {"ip_cidr": "192.168.1.11/24"}, {"role": "unused"}, {"admin_state": "down"},
    {"mode": "trunk"}, {"ipv6_cidr": "2001:db8:1::11/64"},
])
def test_physical_interface_edit_preserves_enabled_proxy_and_dns(change):
    """Roll back real physical mutations before an exact proxy tuple becomes stale.

    Args:
        change: Candidate interface field changes that remove a reviewed listener.
    """
    from atlaso.app.models import DnsRecord, DnsSettings
    from atlaso.app.services.interface_updates import (
        PhysicalInterfaceUpdateError,
        update_physical_interface_desired_state,
    )

    engine, db = create_db()
    try:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth1"))
        interface.ipv6_enabled = True
        interface.ipv6_cidr = "2001:db8:1::10/64"
        db.add(DnsSettings(enabled=True, authoritative=True, domain="example.test"))
        db.commit()
        address = "2001:db8:1::10" if "ipv6_cidr" in change else "192.168.1.10"
        save_proxy(db, payload(enabled=True, scheme="http", port=9443, redirect_http=False,
                               managed_dns=True, listeners=[{"interface": "eth1", "address": address}]), actor="test")
        before = runtime_snapshot(db)
        dns_before = [(row.id, row.hostname, row.record_type, row.address, row.description, row.enabled) for row in db.scalars(select(DnsRecord))]
        with pytest.raises(PhysicalInterfaceUpdateError, match="Enabled reverse proxy"):
            update_physical_interface_desired_state(db, interface, change)
        assert runtime_snapshot(db) == before
        assert [(row.id, row.hostname, row.record_type, row.address, row.description, row.enabled) for row in db.scalars(select(DnsRecord))] == dns_before
        assert interface.ip_cidr == "192.168.1.10/24"
        assert interface.ipv6_cidr == "2001:db8:1::10/64"
        assert interface.role == "access" and interface.mode == "access" and interface.admin_state == "up"
    finally:
        db.close()
        engine.dispose()


@pytest.mark.parametrize("change", ["address", "rename", "delete", "disable", "parent"])
def test_vlan_interface_edit_rejects_enabled_proxy_binding_loss(change):
    """Cover VLAN edits and transitive physical-parent eligibility in the shared transaction.

    Args:
        change: Candidate VLAN or parent mutation.
    """
    from atlaso.app.models import VlanInterface
    from atlaso.app.services.interface_updates import (
        PhysicalInterfaceUpdateError,
        refresh_interface_dependent_addresses,
    )
    from atlaso.app.services.network_objects import acquire_network_objects_write_lock

    engine, db = create_db()
    try:
        parent = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth1"))
        parent.mode = "trunk"
        vlan = VlanInterface(name="eth1.20", parent_interface="eth1", vlan_id=20,
                             ip_cidr="192.168.20.10/24", role="access", enabled=True)
        db.add(vlan)
        db.commit()
        save_proxy(db, payload(enabled=True, scheme="http", port=9443, redirect_http=False,
                               listeners=[{"interface": "eth1.20", "address": "192.168.20.10"}]), actor="test")
        before = runtime_snapshot(db)
        acquire_network_objects_write_lock(db)
        old_name = "eth1" if change == "parent" else vlan.name
        new_name = old_name
        if change == "address":
            vlan.ip_cidr = "192.168.20.11/24"
        elif change == "rename":
            vlan.name = new_name = "eth1.21"
            vlan.vlan_id = 21
        elif change == "delete":
            db.delete(vlan)
            new_name = ""
        elif change == "disable":
            vlan.enabled = False
        else:
            parent.mode = "access"
        db.flush()
        with pytest.raises(PhysicalInterfaceUpdateError, match="Enabled reverse proxy"):
            refresh_interface_dependent_addresses(db, old_name=old_name, new_name=new_name,
                                                 old_ip_cidr="192.168.20.10/24", old_ipv6_cidr=None)
        db.rollback()
        assert runtime_snapshot(db) == before
        assert db.scalar(select(VlanInterface)).name == "eth1.20"
        assert db.scalar(select(VlanInterface)).enabled
    finally:
        db.close()
        engine.dispose()


def test_disabled_proxy_does_not_block_interface_address_edit():
    """Keep disabled saved intent portable while unrelated edits remain available."""
    from atlaso.app.services.interface_updates import (
        update_physical_interface_desired_state,
    )

    engine, db = create_db()
    try:
        save_proxy(db, payload(), actor="test")
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth1"))
        result = update_physical_interface_desired_state(db, interface, {"ip_cidr": "192.168.1.11/24"})
        assert result.interface.ip_cidr == "192.168.1.11/24"
        assert not db.scalar(select(ReverseProxy)).enabled
    finally:
        db.close()
        engine.dispose()


def test_enabled_proxy_allows_interface_mtu_edit():
    """Permit an unrelated interface edit that preserves every exact proxy listener."""
    from atlaso.app.services.interface_updates import (
        update_physical_interface_desired_state,
    )

    engine, db = create_db()
    try:
        save_proxy(db, payload(enabled=True, scheme="http", port=9443, redirect_http=False), actor="test")
        before = runtime_snapshot(db)
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth1"))
        result = update_physical_interface_desired_state(db, interface, {"mtu": 1400})
        assert result.interface.mtu == 1400
        assert runtime_snapshot(db) == before
    finally:
        db.close()
        engine.dispose()
