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
@pytest.mark.parametrize("listen_interface", ["eth1", "eth2"])
@pytest.mark.parametrize("address", ["192.168.1.10", "2001:db8:1::10"])
def test_service_socket_guard_retains_exclusive_and_shared_protocol_ownership(model_name, scheme, conflicts, listen_interface, address):
    """Validate service-first and proxy-first ownership with shared nginx exceptions.

    Args:
        model_name: Canonical service settings model owning the requested socket.
        scheme: Existing proxy protocol on the shared TCP port.
        conflicts: Whether the service must reject the enabled proxy socket.
        listen_interface: Same or different interface sharing the proxy address.
        address: Exact shared IPv4 or IPv6 socket address.
    """
    from atlaso.app import models
    from atlaso.app.services.network_objects import acquire_network_objects_write_lock

    engine, db = create_db()
    try:
        first_interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth1"))
        if ":" in address:
            first_interface.ipv6_enabled = True
            first_interface.ipv6_cidr = address + "/64"
        if listen_interface == "eth2":
            db.add(PhysicalInterface(
                name="eth2", mac_address="02:00:00:00:00:03", admin_state="up", oper_state="up",
                role="access", mode="access", ip_cidr="192.168.1.10/24",
                ipv6_enabled=":" in address, ipv6_cidr=address + "/64" if ":" in address else None,
            ))
        db.commit()
        proxy = save_proxy(db, payload(enabled=True, scheme=scheme, port=9443, redirect_http=False,
                                      listeners=[{"interface": "eth1", "address": address}]), actor="test")
        acquire_network_objects_write_lock(db)
        service = getattr(models, model_name)(enabled=True, port=9443, listen_interface=listen_interface,
                                             listen_address=address)
        if model_name == "LdapSettings":
            service.ldaps_enabled = True
        db.add(service)
        db.flush()
        if conflicts or (listen_interface != "eth1" and model_name in {"OidcProviderSettings", "VcfOfflineDepotSettings"}):
            with pytest.raises(ValueError, match="Service listener conflicts"):
                validate_service_listener_sockets(db)
            assert "exclusive Atlaso service" in " ".join(validate_proxy(proxy, validation_context(db), [proxy], exclude_id=proxy.id))
            proxy.enabled = False
        validate_service_listener_sockets(db)
    finally:
        db.rollback()
        db.close()
        engine.dispose()


@pytest.mark.parametrize("address", ["192.168.1.10", "2001:db8:1::10"])
@pytest.mark.parametrize("matching", [False, True])
def test_shared_service_ingress_set_matches_complete_proxy_binding_set(address, matching):
    """Reject partial ingress and preserve unordered matching multi-interface sets.

    Args:
        address: Exact IPv4 or IPv6 listener shared by both eligible interfaces.
        matching: Select both service interfaces or only one for the proxy.
    """
    from atlaso.app.models import OidcProviderSettings

    engine, db = create_db()
    try:
        first = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth1"))
        first.ipv6_enabled = ":" in address
        first.ipv6_cidr = address + "/64" if ":" in address else None
        db.add(PhysicalInterface(name="eth2", mac_address="02:00:00:00:00:03", role="access", mode="access",
                                 admin_state="up", oper_state="up", ip_cidr="192.168.1.10/24",
                                 ipv6_enabled=":" in address, ipv6_cidr=first.ipv6_cidr))
        db.add(OidcProviderSettings(enabled=True, port=9443, listen_interface="eth1 eth2", listen_address=address))
        db.commit()
        before_audits = list(db.scalars(select(AuditEvent.id)))
        bindings = [{"interface": name, "address": address} for name in (["eth2", "eth1"] if matching else ["eth1"])]
        request = payload(enabled=True, port=9443, redirect_http=False, listeners=bindings)
        if matching:
            proxy = save_proxy(db, request, actor="operator")
            assert proxy.listeners == bindings
            validate_service_listener_sockets(db)
        else:
            with pytest.raises(ValueError, match="exclusive Atlaso service"):
                save_proxy(db, request, actor="operator")
            assert not list(db.scalars(select(ReverseProxy)))
            assert list(db.scalars(select(AuditEvent.id))) == before_audits
    finally:
        db.close()
        engine.dispose()


@pytest.mark.parametrize("model_name", ["CaSettings", "KmsSettings", "LdapSettings", "EsxStorageSettings",
                                       "OidcProviderSettings", "NtpSettings",
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


@pytest.mark.parametrize("editing", [False, True])
@pytest.mark.parametrize("peer_enabled", [False, True])
@pytest.mark.parametrize("hostname", ["backend.example.test", "BACKEND.EXAMPLE.TEST."])
def test_peer_upstream_hostname_cannot_be_claimed_atomically(editing, peer_enabled, hostname):
    """Keep peer backend resolution private when another served name is saved.

    Args:
        editing: Replace a saved row instead of adding a new virtual host.
        peer_enabled: Include disabled peer intent in the ownership inventory.
        hostname: Canonical or case/root-dot alias of the peer backend.
    """
    from atlaso.app.services.settings_archive import export_settings_archive

    engine, db = create_db()
    try:
        peer = payload(name="Peer", hostname="peer.example.test", enabled=peer_enabled)
        peer["routes"][0]["upstream_host"] = "backend.example.test"
        save_proxy(db, peer, actor="test")
        current = save_proxy(db, payload(), actor="test") if editing else None
        before = export_settings_archive(db, actor="test")["data"]
        audit_ids = list(db.scalars(select(AuditEvent.id)))
        with pytest.raises(ValueError, match="peer reverse-proxy upstream"):
            save_proxy(db, payload(hostname=hostname, managed_dns=True), actor="test",
                       proxy_id=current.id if current else None)
        assert export_settings_archive(db, actor="test")["data"] == before
        assert list(db.scalars(select(AuditEvent.id))) == audit_ids
        save_proxy(db, payload(hostname="distinct.example.test", name="Distinct"), actor="test")
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
@pytest.mark.parametrize("enabled,authoritative", [(True, True), (True, False), (False, False)])
def test_authoritative_dns_primary_hostname_is_reserved(configured, target, enabled, authoritative):
    """Reserve explicit and default nameserver identities in both proxy positions.

    Args:
        configured: Canonicalizable configured primary hostname or empty default.
        target: Served proxy hostname or upstream route target.
        enabled: Whether the DNS service is enabled.
        authoritative: Whether authoritative mode is active or dormant.
    """
    from atlaso.app.models import DnsSettings

    engine, db = create_db()
    try:
        db.add(DnsSettings(enabled=enabled, authoritative=authoritative, domain="example.test", authoritative_server=configured))
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


@pytest.mark.parametrize("target", ["served", "upstream"])
@pytest.mark.parametrize("host", ["127.1", "0177.0.0.1", "0x7f.0.0.1", "127.0.1", "2130706433", "0x7f000001", "0300.0.2.1"])
def test_legacy_numeric_addresses_reject_without_changing_saved_proxy(target, host):
    """Reject resolver-dependent numeric spellings atomically at shared save validation.

    Args:
        target: Served hostname or upstream field being replaced.
        host: Legacy numeric address spelling.
    """
    engine, db = create_db()
    try:
        proxy = save_proxy(db, payload(), actor="operator")
        before = runtime_snapshot(db)
        audit_ids = [row.id for row in db.scalars(select(AuditEvent))]
        candidate = payload()
        if target == "served":
            candidate["hostname"] = host
        else:
            candidate["routes"][0]["upstream_host"] = host
        with pytest.raises(ValueError):
            save_proxy(db, candidate, actor="operator", proxy_id=proxy.id)
        db.rollback()
        assert runtime_snapshot(db) == before
        assert [row.id for row in db.scalars(select(AuditEvent))] == audit_ids
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


@pytest.mark.parametrize("inventory_source", ["host", "seed"])
@pytest.mark.parametrize("missing", [False, True])
def test_inventory_refresh_suspends_physical_and_vlan_proxies_without_rebinding(monkeypatch, missing, inventory_source):
    """Inventory identity changes suspend publication atomically and retain reviewed tuples.

    Args:
        monkeypatch: Native inventory discovery replacement.
        missing: Remove the selected NIC instead of renaming the same MAC.
        inventory_source: Native observed identity or disposable seed-only inventory.
    """
    from copy import deepcopy

    from atlaso.app.models import DnsRecord, DnsSettings, VlanInterface
    from atlaso.app.services import networking

    engine, db = create_db()
    try:
        db.add(DnsSettings(enabled=True, authoritative=True, domain="example.test"))
        db.commit()
        physical = save_proxy(db, payload(enabled=True, managed_dns=True), actor="test")
        operator = DnsRecord(hostname="operator.example.test", record_type="A", address="192.168.1.20",
                             description="operator", enabled=True)
        db.add(operator)
        db.commit()
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth1"))
        interface.mode = "trunk"
        interface.inventory_source = inventory_source
        interface.desired_state_source = "seed" if inventory_source == "seed" else "user"
        vlan = VlanInterface(name="eth1.20", parent_interface="eth1", vlan_id=20,
                             role="access", enabled=True, ip_cidr="192.168.20.10/24")
        child = ReverseProxy(name="VLAN application", hostname="vlan.example.test", enabled=True,
                             listeners=[{"interface": "eth1.20", "address": "192.168.20.10"}])
        unrelated = ReverseProxy(name="Unrelated", hostname="other.example.test", enabled=True,
                                 listeners=[{"interface": "eth0", "address": "192.168.0.10"}])
        db.add_all([vlan, child, unrelated])
        db.commit()
        before = deepcopy([physical.listeners, child.listeners])
        observations = [networking.HostPhysicalInterface(
            name="eth0", mac_address="02:00:00:00:00:02", driver=None, speed=None,
            host_ip_cidr="192.168.0.10/24", host_mtu=1500, host_admin_state="up", oper_state="up",
        )]
        if not missing:
            observations.append(networking.HostPhysicalInterface(
                name="eth9", mac_address="02:00:00:00:00:01", driver=None, speed=None,
                host_ip_cidr="192.168.1.10/24", host_mtu=1500, host_admin_state="up", oper_state="up",
            ))
        monkeypatch.setattr(networking, "discover_host_physical_interfaces", lambda **_kwargs: observations)
        networking.sync_host_physical_interfaces(db)
        db.expire_all()
        assert not physical.enabled and not child.enabled
        assert [physical.listeners, child.listeners] == before
        assert unrelated.enabled
        assert list(db.scalars(select(DnsRecord))) == [operator]
        events = list(db.scalars(select(AuditEvent).where(
            AuditEvent.action == "suspend_inventory_reverse_proxy_bindings")))
        assert len(events) == 1 and "review exact listeners" in events[0].detail
        networking.sync_host_physical_interfaces(db)
        assert len(list(db.scalars(select(AuditEvent).where(
            AuditEvent.action == "suspend_inventory_reverse_proxy_bindings")))) == 1
    finally:
        db.close()
        engine.dispose()


def test_inventory_proxy_suspension_rolls_back_with_parent_transaction():
    """A failed inventory transaction restores enablement, listeners and its audit."""
    from atlaso.app.services.network_objects import acquire_network_objects_write_lock
    from atlaso.app.services.networking import _retarget_interface_references

    engine, db = create_db()
    try:
        proxy = save_proxy(db, payload(enabled=True), actor="test")
        original = list(proxy.listeners)
        acquire_network_objects_write_lock(db)
        _retarget_interface_references(db, {"eth1": "eth9"})
        assert not proxy.enabled
        db.rollback()
        assert proxy.enabled and proxy.listeners == original
        assert list(db.scalars(select(AuditEvent).where(
            AuditEvent.action == "suspend_inventory_reverse_proxy_bindings"))) == []
    finally:
        db.close()
        engine.dispose()


@pytest.mark.parametrize("address", ["192.168.1.10", "2001:db8:1::10"])
@pytest.mark.parametrize(("scheme", "port", "conflicts"), [
    ("http", 443, True), ("https", 80, True), ("https", 443, True), ("http", 8080, False),
])
def test_proxy_socket_protocol_ownership_ignores_duplicate_interface_addresses(address, scheme, port, conflicts):
    """Keep nginx protocol ownership address-scoped while retaining interface bindings.

    Args:
        address: Exact duplicate saved IPv4 or IPv6 listener address.
        scheme: Candidate client-facing protocol.
        port: Candidate TCP port, including the existing HTTP redirect socket.
        conflicts: Whether save must reject protocol or ingress-scope overlap without mutation.
    """
    engine, db = create_db()
    try:
        first_interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth1"))
        if ":" in address:
            first_interface.ipv6_enabled = True
            first_interface.ipv6_cidr = address + "/64"
        second_interface = PhysicalInterface(
            name="eth2", mac_address="02:00:00:00:00:03", admin_state="up", oper_state="up",
            role="access", mode="access", ip_cidr="192.168.1.10/24",
            ipv6_enabled=":" in address, ipv6_cidr=address + "/64" if ":" in address else None,
        )
        db.add(second_interface)
        db.commit()
        first = save_proxy(db, payload(enabled=True, listeners=[{"interface": "eth1", "address": address}]),
                           actor="operator")
        candidate = payload(name="Second", hostname="second.example.test", enabled=True, scheme=scheme,
                            port=port, redirect_http=False, listeners=[{"interface": "eth2", "address": address}])
        if conflicts:
            message = "identical interface scopes" if (scheme, port) == ("https", 443) else "HTTP and HTTPS virtual hosts cannot share"
            with pytest.raises(ValueError, match=message):
                save_proxy(db, candidate, actor="operator")
            assert list(db.scalars(select(ReverseProxy))) == [first]
        else:
            second = save_proxy(db, candidate, actor="operator")
            assert second.listeners == [{"interface": "eth2", "address": address}]
        assert first.listeners == [{"interface": "eth1", "address": address}]
    finally:
        db.close()
        engine.dispose()


@pytest.mark.parametrize("address", ["192.168.1.10", "2001:db8:1::10"])
@pytest.mark.parametrize(("scheme", "port"), [("https", 443), ("http", 80)])
@pytest.mark.parametrize(("first_scopes", "second_scopes", "conflicts"), [
    (("eth1",), ("eth1",), False),
    (("eth1", "eth2"), ("eth2", "eth1"), False),
    (("eth1",), ("eth2",), True),
    (("eth1", "eth2"), ("eth1",), True),
    (("eth1",), ("eth1", "eth2"), True),
])
def test_shared_proxy_sockets_require_identical_ingress_scopes(address, scheme, port, first_scopes, second_scopes, conflicts):
    """Protect primary and redirect hosts while admitting identical unordered scopes.

    Args:
        address: Exact duplicate saved IPv4 or IPv6 address.
        scheme: Candidate protocol sharing the primary or redirect socket.
        port: Existing primary or redirect listener port.
        first_scopes: Interfaces selected by the existing enabled proxy.
        second_scopes: Interfaces selected by the candidate proxy.
        conflicts: Whether differing ingress scopes must reject the write atomically.
    """
    engine, db = create_db()
    try:
        first_interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth1"))
        first_interface.ipv6_enabled = ":" in address
        first_interface.ipv6_cidr = address + "/64" if ":" in address else None
        db.add(PhysicalInterface(
            name="eth2", mac_address="02:00:00:00:00:03", admin_state="up", oper_state="up",
            role="access", mode="access", ip_cidr="192.168.1.10/24",
            ipv6_enabled=":" in address, ipv6_cidr=address + "/64" if ":" in address else None,
        ))
        db.commit()
        first = save_proxy(db, payload(enabled=True, listeners=[
            {"interface": interface, "address": address} for interface in first_scopes
        ]), actor="operator")
        before_audits = list(db.scalars(select(AuditEvent.id)))
        candidate = payload(name="Second", hostname="second.example.test", enabled=True, scheme=scheme,
                            port=port, redirect_http=False, listeners=[
                                {"interface": interface, "address": address} for interface in second_scopes
                            ])
        if conflicts:
            with pytest.raises(ValueError, match="identical interface scopes"):
                save_proxy(db, candidate, actor="operator")
            assert list(db.scalars(select(ReverseProxy))) == [first]
            assert list(db.scalars(select(AuditEvent.id))) == before_audits
        else:
            second = save_proxy(db, candidate, actor="operator")
            assert {binding["interface"] for binding in second.listeners} == set(second_scopes)
        assert {binding["interface"] for binding in first.listeners} == set(first_scopes)
    finally:
        db.close()
        engine.dispose()


def test_shared_proxy_scope_is_per_address_and_rejected_edit_preserves_state():
    """Admit unrelated bindings and reject a changed shared-socket scope atomically."""
    engine, db = create_db()
    try:
        db.add(PhysicalInterface(
            name="eth2", mac_address="02:00:00:00:00:03", admin_state="up", oper_state="up",
            role="access", mode="access", ip_cidr="192.168.1.11/24",
        ))
        db.add(PhysicalInterface(
            name="eth3", mac_address="02:00:00:00:00:04", admin_state="up", oper_state="up",
            role="access", mode="access", ip_cidr="192.168.1.10/24",
        ))
        db.commit()
        first = save_proxy(db, payload(enabled=True, listeners=[
            {"interface": "eth1", "address": "192.168.1.10"},
            {"interface": "eth2", "address": "192.168.1.11"},
        ]), actor="operator")
        second_payload = payload(name="Second", hostname="second.example.test", enabled=True)
        second = save_proxy(db, second_payload, actor="operator")
        assert second.listeners == [{"interface": "eth1", "address": "192.168.1.10"}]
        before_audits = list(db.scalars(select(AuditEvent.id)))
        second_payload["listeners"] = [{"interface": "eth3", "address": "192.168.1.10"}]
        with pytest.raises(ValueError, match="identical interface scopes"):
            save_proxy(db, second_payload, actor="operator", proxy_id=second.id)
        assert second.listeners == [{"interface": "eth1", "address": "192.168.1.10"}]
        assert first.listeners[0] == second.listeners[0]
        assert list(db.scalars(select(AuditEvent.id))) == before_audits
    finally:
        db.close()
        engine.dispose()


@pytest.mark.parametrize("model_name", ["CaSettings", "KmsSettings", "LdapSettings", "OidcProviderSettings",
                                       "NtpSettings", "VcfOfflineDepotSettings", "VcfPrivateRegistrySettings"])
@pytest.mark.parametrize("naming", ["ip", "interface"])
@pytest.mark.parametrize("address", ["192.168.1.10", "2001:db8::10"])
def test_generated_service_aliases_rejected_before_save(model_name, naming, address):
    """Reserve actual DNS publication targets without committing proxy or audit rows.

    Args:
        model_name: Canonical service settings owner.
        naming: Appliance service target naming strategy.
        address: Selected IPv4 or IPv6 listener address.
    """
    from atlaso.app import models, ui

    engine, db = create_db()
    try:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth1"))
        interface.ipv6_enabled = True
        interface.ipv6_cidr = "2001:db8::10/64"
        db.scalar(select(ApplianceSettings)).service_dns_target_naming = naming
        model = getattr(models, model_name)
        service = db.scalar(select(model))
        if service is None:
            service = model()
            db.add(service)
        field = "portal_hostname" if model_name == "CaSettings" else "hostname"
        setattr(service, field, "a" * 63 + ".example.test")
        service.listen_interface = "eth1"
        service.listen_address = address
        db.commit()
        target = ui.service_interface_dns_targets(
            db, hostname=getattr(service, field), listen_interface="eth1", listen_address=address,
            shared_target_token="service" if model_name == "NtpSettings" else None,
        )[0]["hostname"]
        before = desired_rows(db)
        audits = list(db.scalars(select(AuditEvent.id)))
        request = payload()
        request["routes"][0]["upstream_host"] = target.upper() + "."
        with pytest.raises(ValueError, match="Atlaso.*service"):
            save_proxy(db, request, actor="test")
        assert desired_rows(db) == before
        assert list(db.scalars(select(AuditEvent.id))) == audits
        request["routes"][0]["upstream_host"] = "remote-" + target.split(".", 1)[1]
        save_proxy(db, request, actor="test")
    finally:
        db.close()
        engine.dispose()


@pytest.mark.parametrize("target", ["served", "upstream"])
def test_owned_service_dns_aliases_reserved_but_operator_dns_allowed(target):
    """Reserve retained generated records without treating operator DNS as service ownership.

    Args:
        target: Proxy hostname or upstream route claiming the generated alias.
    """
    from atlaso.app.models import DnsRecord
    from atlaso.app.services.service_dns_defaults import NTP_DNS_DESCRIPTION

    engine, db = create_db()
    try:
        db.add(DnsRecord(hostname="ntp-192-168-1-10.example.test", record_type="A", address="192.168.1.10",
                         description=NTP_DNS_DESCRIPTION))
        db.add(DnsRecord(hostname="remote-192-168-1-10.example.test", record_type="A", address="10.10.20.30",
                         description="Operator-owned record"))
        db.commit()
        request = payload()
        if target == "served":
            request["hostname"] = "ntp-192-168-1-10.example.test"
        else:
            request["routes"][0]["upstream_host"] = "ntp-192-168-1-10.example.test"
        with pytest.raises(ValueError, match="Atlaso.*service"):
            save_proxy(db, request, actor="test")
        request = payload()
        request["routes"][0]["upstream_host"] = "remote-192-168-1-10.example.test"
        save_proxy(db, request, actor="test")
    finally:
        db.close()
        engine.dispose()


@pytest.mark.parametrize("naming", ["ip", "interface"])
def test_storage_and_network_boot_generated_aliases_reserved(naming):
    """Use each publisher's target naming rules for selected local addresses.

    Args:
        naming: Appliance service target naming strategy.
    """
    from atlaso.app.models import EsxNfsShare, EsxStorageSettings, EsxStorageVolume
    from atlaso.app.services.esx_storage import target_hostname, target_token
    from atlaso.app.services.esxi_pxe import (
        ESXI_PXE_LISTEN_ADDRESS_KEY,
        ESXI_PXE_LISTEN_INTERFACE_KEY,
    )
    from atlaso.app.services.service_dns_names import (
        service_dns_target_token,
        service_target_hostname,
    )

    engine, db = create_db()
    try:
        db.scalar(select(ApplianceSettings)).service_dns_target_naming = naming
        db.add(EsxStorageSettings(hostname="nfs.example.test"))
        volume = EsxStorageVolume(name="reserved-volume", stable_device_id="test-device")
        db.add(volume)
        db.flush()
        db.add(EsxNfsShare(datastore_name="reserved", volume_id=volume.id, interface_name="eth1", address_families="ipv4"))
        db.add(Setting(key=ESXI_PXE_LISTEN_INTERFACE_KEY, value="eth1"))
        db.add(Setting(key=ESXI_PXE_LISTEN_ADDRESS_KEY, value="192.168.1.10"))
        db.commit()
        names = validation_context(db)["service_hostnames"]
        assert target_hostname("nfs.example.test", target_token("192.168.1.10", naming, "eth1")) in names
        assert service_target_hostname("esxi-pxe.atlaso.internal",
                                       service_dns_target_token(naming, "eth1", "192.168.1.10")) in names
    finally:
        db.close()
        engine.dispose()


@pytest.mark.parametrize("enabled", [False, True])
def test_interface_guard_uses_secondary_observed_ipv6_and_preserves_rollback(enabled):
    """The shared candidate inventory sees every native address on unrelated interfaces.

    Args:
        enabled: Whether the saved proxy is active and must block a conflicting interface.
    """
    from atlaso.app.services.reverse_proxies import validate_interface_proxy_bindings

    engine, db = create_db()
    try:
        route = {**payload()["routes"][0], "upstream_host": "2001:db8:2::10"}
        save_proxy(db, payload(enabled=enabled, routes=[route]), actor="test")
        before = runtime_snapshot(db)
        audits = list(db.scalars(select(AuditEvent.id)))
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        interface.host_ipv6_cidr = "2001:db8:1::10/64"
        interface.host_ipv6_cidrs = ["invalid", "2001:db8:1::10/64", "2001:0db8:0002::0010/64"]
        if enabled:
            with pytest.raises(ValueError, match="still uses upstream address"):
                validate_interface_proxy_bindings(db, {"eth0"})
        else:
            validate_interface_proxy_bindings(db, {"eth0"})
        db.rollback()
        assert runtime_snapshot(db) == before
        assert list(db.scalars(select(AuditEvent.id))) == audits
        assert interface.host_ipv6_cidrs == []
    finally:
        db.close()
        engine.dispose()


@pytest.mark.parametrize("observed", [None, [], ["bad-cidr"], ["2001:db8:1::10/64", "2001:db8:1::10/64"]])
def test_observed_ipv6_inventory_retains_distinct_external_upstream(observed):
    """Empty, malformed or duplicate observations do not block a distinct ordinary address.

    Args:
        observed: Legacy-empty or repeated native IPv6 observation metadata.
    """
    engine, db = create_db()
    try:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        interface.host_ipv6_cidr = "2001:db8:1::10/64"
        interface.host_ipv6_cidrs = observed
        db.commit()
        route = {**payload()["routes"][0], "upstream_host": "2001:db8:2::11"}
        proxy = save_proxy(db, payload(routes=[route]), actor="test")
        assert proxy.routes[0].upstream_host == "2001:db8:2::11"
    finally:
        db.close()
        engine.dispose()


@pytest.mark.parametrize("ipv6", [False, True])
@pytest.mark.parametrize("scenario", ["distinct", "same_http", "same_https", "same_other_interface"])
def test_pxe_exact_listener_claim_preserves_proxy_address_and_protocol_boundaries(ipv6, scenario):
    """Save distinct-address proxies without relaxing real PXE socket ownership.

    Args:
        ipv6: Whether the configured listener belongs to IPv6.
        scenario: Distinct binding or same-socket ownership scenario.
    """
    from atlaso.app.services.esxi_pxe import (
        esxi_pxe_boot_settings,
        save_esxi_pxe_boot_settings,
    )
    from atlaso.app.services.public_services import _esxi_pxe_http_server_lines

    engine, db = create_db()
    try:
        pxe_address = "2001:db8:1::10" if ipv6 else "192.168.1.10"
        proxy_address = ("2001:db8:1::20" if ipv6 else "192.168.1.20") if scenario == "distinct" else pxe_address
        first = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth1"))
        first.ipv6_enabled = ipv6
        first.ipv6_cidr = "2001:db8:1::10/64" if ipv6 else ""
        db.add(PhysicalInterface(name="eth2", mac_address="02:00:00:00:00:03", role="access", mode="access",
                                 admin_state="up", oper_state="up", ip_cidr=proxy_address + "/24" if not ipv6 else "192.168.1.20/24",
                                 ipv6_enabled=ipv6, ipv6_cidr=proxy_address + "/64" if ipv6 else ""))
        db.commit()
        boot = esxi_pxe_boot_settings(db)
        save_esxi_pxe_boot_settings(db, enabled=True, hostname="pxe.example.test", listen_interface="eth1",
                                   listen_address=pxe_address, http_port=9443, tftp_root=boot["tftp_root"],
                                   bios_bootfile=boot["bios_bootfile"], uefi_bootfile=boot["uefi_bootfile"])
        db.commit()
        before = esxi_pxe_boot_settings(db)
        claims = [claim for claim in listener_claims(db, include_reverse_proxies=False) if claim.start == 9443]
        assert claims == [ListenerClaim("eth1", pxe_address, "tcp", 9443, 9443, "nginx", "http")]
        rendered = _esxi_pxe_http_server_lines(pxe_address, "127.0.0.1", 8000, 9443, "/var/lib/atlaso/pxe/http/esxi")
        endpoint = f"[{pxe_address}]:9443" if ipv6 else f"{pxe_address}:9443"
        assert f"  listen {endpoint};" in rendered
        values = payload(enabled=True, scheme="https" if scenario == "same_https" else "http", port=9443,
                         redirect_http=False, listeners=[{"interface": "eth2" if scenario in {"distinct", "same_other_interface"} else "eth1",
                                                         "address": proxy_address}])
        audit_ids = list(db.scalars(select(AuditEvent.id)))
        if scenario in {"same_https", "same_other_interface"}:
            with pytest.raises(ValueError, match="collid|conflict"):
                save_proxy(db, values, actor="test")
            db.rollback()
            assert desired_rows(db) == []
            assert list(db.scalars(select(AuditEvent.id))) == audit_ids
            assert esxi_pxe_boot_settings(db) == before
        else:
            assert save_proxy(db, values, actor="test").enabled
            validate_service_listener_sockets(db)
    finally:
        db.rollback()
        db.close()
        engine.dispose()


@pytest.mark.parametrize("kind", ["dedicated", "access", "vlan"])
@pytest.mark.parametrize("address", ["192.168.1.10", "2001:db8:1::10"])
@pytest.mark.parametrize(("scheme", "port", "redirect"), [("http", 80, False), ("https", 443, False), ("https", 9443, True)])
def test_management_scopes_guard_proxy_and_service_writes(kind, address, scheme, port, redirect):
    """Reject cross-interface management sharing on primary and redirect sockets atomically.

    Args:
        kind: Dedicated, flagged physical or flagged VLAN management listener.
        address: Shared IPv4 or IPv6 destination.
        scheme: Candidate proxy protocol.
        port: Candidate primary listener port.
        redirect: Whether the conflicting socket is the HTTP redirect.
    """
    from atlaso.app.models import VlanInterface
    from atlaso.app.services.network_objects import acquire_network_objects_write_lock

    engine, db = create_db()
    try:
        access = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth1"))
        access.ipv6_enabled = True
        access.ipv6_cidr = "2001:db8:1::10/64"
        existing = save_proxy(db, payload(enabled=True, port=9444, redirect_http=False,
                                         listeners=[{"interface": "eth1", "address": address}]), actor="test")
        if kind == "dedicated":
            management = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        else:
            management = PhysicalInterface(name="eth2", mac_address="02:00:00:00:00:03", admin_state="up",
                                           oper_state="up", role="access", mode="access",
                                           access_management_ui_enabled=True)
            db.add(management)
            if kind == "vlan":
                management.mode = "trunk"
                management.access_management_ui_enabled = False
                management = VlanInterface(name="eth2.77", parent_interface="eth2", vlan_id=77,
                                           role="access", enabled=True, access_management_ui_enabled=True)
                db.add(management)
        access.check_duplicate_ip_addresses = False
        management.check_duplicate_ip_addresses = False
        management.ip_cidr = "192.168.1.10/24"
        management.ipv6_cidr = "2001:db8:1::10/64"
        if isinstance(management, PhysicalInterface):
            management.ipv6_enabled = True
        db.commit()
        before_audits = list(db.scalars(select(AuditEvent.id)))
        candidate = payload(enabled=True, scheme=scheme, port=port, redirect_http=redirect,
                            listeners=[{"interface": "eth1", "address": address}])
        with pytest.raises(ValueError, match="exclusive Atlaso service socket"):
            save_proxy(db, candidate, actor="test", proxy_id=existing.id)
        assert existing.port == 9444 and not existing.redirect_http
        assert list(db.scalars(select(AuditEvent.id))) == before_audits
        acquire_network_objects_write_lock(db)
        existing.scheme, existing.port, existing.redirect_http = scheme, port, redirect
        db.flush()
        with pytest.raises(ValueError, match="Service listener conflicts"):
            validate_service_listener_sockets(db)
        db.rollback()
        assert existing.port == 9444 and not existing.redirect_http
        assert list(db.scalars(select(AuditEvent.id))) == before_audits
    finally:
        db.close()
        engine.dispose()


@pytest.mark.parametrize("address", ["192.168.1.10", "2001:db8:1::10"])
@pytest.mark.parametrize(("scheme", "port"), [("http", 80), ("https", 443)])
def test_management_access_socket_allows_identical_proxy_scope(address, scheme, port):
    """Retain ordinary cohosting on the same management-enabled access interface.

    Args:
        address: Shared IPv4 or IPv6 destination.
        scheme: Shared front-door protocol.
        port: Shared front-door port.
    """
    engine, db = create_db()
    try:
        access = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth1"))
        access.access_management_ui_enabled = True
        access.ipv6_enabled = True
        access.ipv6_cidr = "2001:db8:1::10/64"
        db.commit()
        proxy = save_proxy(db, payload(enabled=True, scheme=scheme, port=port, redirect_http=False,
                                       listeners=[{"interface": "eth1", "address": address}]), actor="test")
        validate_service_listener_sockets(db)
        assert proxy.enabled
    finally:
        db.close()
        engine.dispose()


@pytest.mark.parametrize("address", ["192.168.1.10", "2001:db8:1::10"])
def test_management_scope_includes_observed_dynamic_addresses(address):
    """Reserve DHCP and automatic IPv6 front doors before a proxy can share them.

    Args:
        address: Observed management destination reused by a public interface.
    """
    engine, db = create_db()
    try:
        management = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        management.ip_cidr = None
        management.ipv4_method = "dhcp"
        management.host_ip_cidr = "192.168.1.10/24"
        management.ipv6_enabled = True
        management.ipv6_cidr = None
        management.host_ipv6_cidrs = ["2001:db8:2::10/64", "2001:db8:1::10/64"]
        access = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth1"))
        access.ipv6_enabled = True
        access.ipv6_cidr = "2001:db8:1::10/64"
        db.commit()
        with pytest.raises(ValueError, match="exclusive Atlaso service socket"):
            save_proxy(db, payload(enabled=True, listeners=[{"interface": "eth1", "address": address}]), actor="test")
        assert not desired_rows(db)
    finally:
        db.close()
        engine.dispose()


@pytest.mark.parametrize("address", ["192.168.1.10", "2001:db8:1::10"])
@pytest.mark.parametrize("matching", [False, True])
@pytest.mark.parametrize("vlan", [False, True])
def test_terminal_https_scope_guards_both_write_orders(address, matching, vlan):
    """Reserve independently admitted terminal scopes for both write orders.

    Args:
        address: Duplicate IPv4 or IPv6 destination.
        matching: Whether terminal and proxy select the same interface.
        vlan: Whether the independent terminal scope is a VLAN.
    """
    from atlaso.app.models import VlanInterface

    engine, db = create_db()
    try:
        access = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth1"))
        access.ipv6_enabled = True
        access.ipv6_cidr = "2001:db8:1::10/64"
        other = PhysicalInterface(name="eth2", mac_address="02:00:00:00:00:03", role="access",
                                  mode="trunk" if vlan else "access", admin_state="up", oper_state="up",
                                  ip_cidr="192.168.1.10/24", ipv6_enabled=True, ipv6_cidr="2001:db8:1::10/64")
        db.add(other)
        name = "eth2"
        if vlan:
            name = "eth2.77"
            db.add(VlanInterface(name=name, parent_interface="eth2", vlan_id=77, role="access", enabled=True,
                                 ip_cidr="192.168.1.10/24", ipv6_cidr="2001:db8:1::10/64"))
        appliance = db.scalar(select(ApplianceSettings))
        appliance.web_terminal_enabled = False
        db.commit()
        proxy = save_proxy(db, payload(enabled=True, port=443, redirect_http=False,
                                      listeners=[{"interface": "eth1", "address": address}]), actor="test")
        appliance.web_terminal_enabled = True
        appliance.web_terminal_interfaces_json = json.dumps(["eth1" if matching else name])
        db.flush()
        if matching:
            validate_service_listener_sockets(db)
        else:
            with pytest.raises(ValueError, match="Service listener conflicts"):
                validate_service_listener_sockets(db)
            with pytest.raises(ValueError, match="exclusive Atlaso service socket"):
                save_proxy(db, payload(enabled=True, port=443, redirect_http=False,
                                       listeners=[{"interface": "eth1", "address": address}]), actor="test", proxy_id=proxy.id)
    finally:
        db.rollback()
        db.close()
        engine.dispose()


@pytest.mark.parametrize(("model_name", "scheme", "port"), [("CaSettings", "http", 80), ("CaSettings", "https", 443),
                                                           ("VcfOfflineDepotSettings", "http", 80),
                                                           ("VcfPrivateRegistrySettings", "http", 80), ("pxe", "http", 80)])
@pytest.mark.parametrize("address", ["192.168.1.10", "2001:db8:1::10"])
@pytest.mark.parametrize("matching", [False, True])
def test_service_directory_standard_http_scope_with_custom_protocol_port(model_name, scheme, port, address, matching):
    """Protect directory ingress independently of custom service ports.

    Args:
        model_name: Service exposing standard browser ingress.
        scheme: Browser transport protocol.
        port: Standard browser port.
        address: Duplicate IPv4 or IPv6 destination.
        matching: Whether the proxy shares the complete service scope.
    """
    from atlaso.app import models
    from atlaso.app.services.esxi_pxe import (
        esxi_pxe_boot_settings,
        save_esxi_pxe_boot_settings,
    )

    engine, db = create_db()
    try:
        access = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth1"))
        access.ipv6_enabled = True
        access.ipv6_cidr = "2001:db8:1::10/64"
        db.add(PhysicalInterface(name="eth2", mac_address="02:00:00:00:00:03", role="access", mode="access",
                                 admin_state="up", oper_state="up", ip_cidr="192.168.1.10/24",
                                 ipv6_enabled=True, ipv6_cidr="2001:db8:1::10/64"))
        db.commit()
        proxy = save_proxy(db, payload(enabled=True, scheme=scheme, port=port, redirect_http=False,
                                      listeners=[{"interface": "eth1", "address": address}]), actor="test")
        name = "eth1" if matching else "eth2"
        if model_name == "pxe":
            boot = esxi_pxe_boot_settings(db)
            if not matching:
                with pytest.raises(ValueError, match="Service listener conflicts"):
                    save_esxi_pxe_boot_settings(db, enabled=True, hostname="pxe.example.test", listen_interface=name,
                                               listen_address=address, http_port=9443, tftp_root=boot["tftp_root"],
                                               bios_bootfile=boot["bios_bootfile"], uefi_bootfile=boot["uefi_bootfile"])
                return
            save_esxi_pxe_boot_settings(db, enabled=True, hostname="pxe.example.test", listen_interface=name,
                                       listen_address=address, http_port=9443, tftp_root=boot["tftp_root"],
                                       bios_bootfile=boot["bios_bootfile"], uefi_bootfile=boot["uefi_bootfile"])
        else:
            model = getattr(models, model_name)
            service = db.scalar(select(model))
            if service is None:
                service = model()
                db.add(service)
            service.enabled, service.listen_interface, service.listen_address = True, name, address
            if model_name != "CaSettings":
                service.port = 9443
        db.flush()
        if matching:
            validate_service_listener_sockets(db)
        else:
            with pytest.raises(ValueError, match="Service listener conflicts"):
                validate_service_listener_sockets(db)
            assert "exclusive Atlaso service" in " ".join(validate_proxy(proxy, validation_context(db), [proxy], exclude_id=proxy.id))
    finally:
        db.rollback()
        db.close()
        engine.dispose()
