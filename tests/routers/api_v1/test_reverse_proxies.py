"""Exercise Firewall-scoped reverse-proxy desired-state API contracts."""

import pytest
from sqlalchemy import select

from tests.routers.api_v1.helpers import create_token


def test_service_enable_rejects_proxy_socket_and_preserves_settings(client):
    """Reject the reverse-order KMIP collision through its real settings API.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import KmsSettings
    from atlaso.app.services.reverse_proxies import save_proxy

    _enable_test_listener()
    with SessionLocal() as db:
        settings = db.scalar(select(KmsSettings))
        settings.enabled = False
        db.commit()
        before = (settings.enabled, settings.port, settings.hostname, settings.listen_interface, settings.listen_address)
        save_proxy(db, _payload(enabled=True, scheme="http", port=5696, redirect_http=False), actor="test")
    token, _ = create_token(client, scopes=["write:kms"])
    response = client.patch("/api/v1/vsphere-key-providers/settings", headers={"Authorization": f"Bearer {token}"}, json={
        "enabled": True, "listen_interfaces": ["eth1"], "listen_addresses": ["192.0.2.10"],
        "hostname": "kms.example.test", "port": 5696,
    })
    assert response.status_code == 409, response.text
    assert "enabled reverse proxy" in response.json()["detail"]
    with SessionLocal() as db:
        settings = db.scalar(select(KmsSettings))
        assert (settings.enabled, settings.port, settings.hostname, settings.listen_interface, settings.listen_address) == before


def _payload(**overrides):
    """Return one complete proxy request for an eligible exact listener.

    Args:
        **overrides: Input used by  payload.
    """
    value = {
        "name": "Application",
        "description": "Internal application",
        "hostname": "application.example.test",
        "scheme": "https",
        "port": 8443,
        "redirect_http": True,
        "redirect_port": 8080,
        "enabled": False,
        "public_listing": True,
        "managed_dns": False,
        "listeners": [{"interface": "eth1", "address": "192.0.2.10"}],
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


def _enable_test_listener():
    """Prepare one exact access listener in the isolated application database."""
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaSettings, PhysicalInterface

    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth1"))
        assert interface is not None
        interface.role = "access"
        interface.mode = "access"
        interface.admin_state = "up"
        interface.oper_state = "up"
        interface.ip_cidr = "192.0.2.10/24"
        db.scalar(select(CaSettings)).enabled = True
        db.commit()


def test_reverse_proxy_api_rejects_enabled_https_without_ca(client):
    """Reject an unpublishable TLS listener while preserving disabled desired state.

    Args:
        client: Isolated appliance API test client.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaSettings, ReverseProxy

    _enable_test_listener()
    with SessionLocal() as db:
        db.scalar(select(CaSettings)).enabled = False
        db.commit()
    token, _ = create_token(client, scopes=["read:firewall", "write:firewall"])
    headers = {"Authorization": f"Bearer {token}"}
    collection = "/api/v1/traffic-publishing/reverse-proxies"
    rejected = client.post(collection, headers=headers, json=_payload(enabled=True))
    assert rejected.status_code == 422
    assert "enabled CA" in rejected.json()["detail"]
    created = client.post(collection, headers=headers, json=_payload())
    assert created.status_code == 201
    enabled = client.put(f"{collection}/{created.json()['id']}", headers=headers, json=_payload(enabled=True))
    assert enabled.status_code == 422
    with SessionLocal() as db:
        rows = list(db.scalars(select(ReverseProxy)))
        assert len(rows) == 1 and not rows[0].enabled


@pytest.mark.parametrize(("endpoint", "field", "scope", "model_name"), [
    ("/api/v1/settings", "appliance_fqdn", "admin:all", "ApplianceSettings"),
    ("/api/v1/esx-storage/status", "hostname", "write:esx-storage", "EsxStorageSettings"),
])
def test_service_hostname_api_rejects_takeover_of_saved_proxy(client, endpoint, field, scope, model_name):
    """Reject direct and derived service ownership changes without committing edits.

    Args:
        client: Isolated appliance client.
        endpoint: Canonical service settings mutation route.
        field: Hostname field in that route's request.
        scope: Scope required for the settings writer.
        model_name: Saved settings model whose state must be retained.
    """
    from atlaso.app import models
    from atlaso.app.database import SessionLocal
    from atlaso.app.services.reverse_proxies import runtime_snapshot, save_proxy

    _enable_test_listener()
    with SessionLocal() as db:
        proxy = save_proxy(db, _payload(), actor="test")
        hostname = proxy.hostname
        row = db.scalar(select(getattr(models, model_name)))
        before = getattr(row, "fqdn", getattr(row, "hostname", ""))
        proxies_before = runtime_snapshot(db)
    token, _ = create_token(client, scopes=[scope])
    payload = {field: hostname}
    if field == "hostname":
        payload["enabled"] = False
    response = client.patch(endpoint, headers={"Authorization": f"Bearer {token}"}, json=payload)
    assert response.status_code == 409, response.text
    with SessionLocal() as db:
        row = db.scalar(select(getattr(models, model_name)))
        assert getattr(row, "fqdn", getattr(row, "hostname", "")) == before
        assert runtime_snapshot(db) == proxies_before


def test_reverse_proxy_api_requires_firewall_scopes(client):
    """Require Firewall scopes for list, health, create and update operations.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    read_wan, _ = create_token(client, scopes=["read:wan", "write:wan"])
    read_firewall, _ = create_token(client, scopes=["read:firewall"])
    headers = {"Authorization": f"Bearer {read_wan}"}
    assert client.get("/api/v1/traffic-publishing/reverse-proxies", headers=headers).status_code == 403
    assert client.get("/api/v1/traffic-publishing/reverse-proxies/health", headers=headers).status_code == 403
    assert client.post("/api/v1/traffic-publishing/reverse-proxies", headers=headers, json=_payload()).status_code == 403
    assert client.post(
        "/api/v1/traffic-publishing/reverse-proxies",
        headers={"Authorization": f"Bearer {read_firewall}"},
        json=_payload(),
    ).status_code == 403


def test_reverse_proxy_api_crud_nested_replacement_and_unavailable_health(client, monkeypatch):
    """Persist complete nested intent without probing or mutating appliance runtime.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Replaces helper access with a failure to prove CRUD is desired-state only.
    """
    from atlaso.app.adapters.system import AdapterResult, SystemAdapter
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent

    def forbidden(*args, **kwargs):
        """Fail any unexpected appliance-helper call during desired-state CRUD.

        Args:
            *args: Unexpected helper arguments.
            **kwargs: Unexpected helper options.
        """
        raise AssertionError("Reverse-proxy desired-state API invoked the appliance helper")

    _enable_test_listener()
    monkeypatch.setattr(SystemAdapter, "_helper_result", forbidden)
    monkeypatch.setattr(
        SystemAdapter,
        "reverse_proxy_status",
        lambda _self: AdapterResult(command=["atlaso-helper"], dry_run=True, stdout="{}"),
    )
    reader, _ = create_token(client, scopes=["read:firewall"])
    writer, _ = create_token(client, scopes=["read:firewall", "write:firewall"])
    read_headers = {"Authorization": f"Bearer {reader}"}
    headers = {"Authorization": f"Bearer {writer}"}
    collection = "/api/v1/traffic-publishing/reverse-proxies"

    created = client.post(collection, headers=headers, json=_payload())
    assert created.status_code == 201, created.text
    saved = created.json()
    proxy_id = saved["id"]
    assert saved["apply_required"] is True
    assert saved["routes"][0]["path_prefix"] == "/"
    assert client.get(collection, headers=read_headers).json()[0]["id"] == proxy_id
    assert client.get(f"{collection}/{proxy_id}", headers=read_headers).json()["id"] == proxy_id
    nested = client.get(f"{collection}/{proxy_id}/routes", headers=read_headers)
    assert nested.status_code == 200
    assert nested.json()[0]["id"] == saved["routes"][0]["id"]

    health = client.get(f"{collection}/health", headers=read_headers)
    assert health.status_code == 200
    assert health.json()["items"] == [
        {
            "proxy_id": proxy_id,
            "route_id": saved["routes"][0]["id"],
            "proxy_name": "Application",
            "path_prefix": "/",
            "status": "unavailable",
            "last_success": None,
            "failure_class": "runtime_observer_unavailable",
            "http_status": None,
            "tls_status": "not_probed",
            "pending": True,
            "applied": False,
            "warning": "Runtime observation is unavailable or stale; no request-time probe was performed.",
        }
    ]

    route_id = saved["routes"][0]["id"]
    replacement = {
        "routes": [
            {
                "id": route_id,
                "path_prefix": "/application",
                "upstream_scheme": "https",
                "upstream_host": "backend.example.test",
                "upstream_port": 9443,
                "path_behavior": "strip",
                "trust_mode": "fingerprint",
                "fingerprint": "ab" * 32,
            }
        ]
    }
    routes = client.put(f"{collection}/{proxy_id}/routes", headers=headers, json=replacement)
    assert routes.status_code == 200, routes.text
    assert routes.json()[0]["id"] == route_id
    assert routes.json()[0]["upstream_host"] == "backend.example.test"

    invalid = client.put(
        f"{collection}/{proxy_id}/routes",
        headers=headers,
        json={"routes": [{**replacement["routes"][0], "path_prefix": "/api/../private"}]},
    )
    assert invalid.status_code == 422
    assert invalid.json()["error_code"] == "VALIDATION_ERROR"
    unchanged = client.get(f"{collection}/{proxy_id}/routes", headers=read_headers)
    assert unchanged.json()[0]["path_prefix"] == "/application"

    complete_replacement = _payload(name="Updated application")
    complete_replacement["routes"][0]["id"] = route_id
    updated = client.put(f"{collection}/{proxy_id}", headers=headers, json=complete_replacement)
    assert updated.status_code == 200, updated.text
    assert updated.json()["name"] == "Updated application"
    assert client.delete(f"{collection}/{proxy_id}", headers=headers).status_code == 204
    missing = client.get(f"{collection}/{proxy_id}", headers=read_headers)
    assert missing.status_code == 404
    assert missing.json()["status"] == 404

    with SessionLocal() as db:
        actions = list(
            db.scalars(
                select(AuditEvent.action)
                .where(AuditEvent.resource_type == "reverse_proxy")
                .order_by(AuditEvent.id)
            )
        )
    assert actions == ["create_reverse_proxy", "update_reverse_proxy", "update_reverse_proxy", "delete_reverse_proxy"]


def test_reverse_proxy_api_rejects_invalid_create_without_saving(client):
    """Map malformed nested route input to ProblemDetails before any persistence.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import func

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ReverseProxy

    writer, _ = create_token(client, scopes=["read:firewall", "write:firewall"])
    response = client.post(
        "/api/v1/traffic-publishing/reverse-proxies",
        headers={"Authorization": f"Bearer {writer}"},
        json=_payload(routes=[{**_payload()["routes"][0], "upstream_host": "https://user@example.test"}]),
    )
    assert response.status_code == 422
    assert response.json()["error_code"] == "VALIDATION_ERROR"
    with SessionLocal() as db:
        assert db.scalar(select(func.count(ReverseProxy.id))) == 0


def test_reverse_proxy_health_returns_one_cached_applied_observation(client, monkeypatch):
    """Read one helper snapshot and report applied cached health without probing.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Replaces the bounded helper adapter response.
    """
    import json
    from datetime import datetime, timezone

    from atlaso.app.adapters.system import AdapterResult, SystemAdapter
    from atlaso.app.database import SessionLocal
    from atlaso.app.services.reverse_proxies import runtime_snapshot

    _enable_test_listener()
    reader, _ = create_token(client, scopes=["read:firewall"])
    writer, _ = create_token(client, scopes=["read:firewall", "write:firewall"])
    headers = {"Authorization": f"Bearer {writer}"}
    created = client.post(
        "/api/v1/traffic-publishing/reverse-proxies",
        headers=headers,
        json=_payload(enabled=True),
    )
    assert created.status_code == 201, created.text
    with SessionLocal() as db:
        proxies = runtime_snapshot(db)
    proxy_id = proxies[0]["id"]
    route_id = proxies[0]["routes"][0]["id"]
    called = []
    status = {
        "schema": 1,
        "proxies": proxies,
        "generation": "a" * 64,
        "health": {
            f"{proxy_id}-{route_id}": {
                "status": "healthy",
                "last_success": datetime.now(timezone.utc).isoformat(),
                "failure_class": None,
                "http_status": 204,
                "tls_status": "not_applicable",
            }
        },
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }

    def reverse_proxy_status(self):
        """Return the fixed cached observation once."""
        called.append(True)
        return AdapterResult(command=["atlaso-helper"], dry_run=False, stdout=json.dumps(status))

    monkeypatch.setattr(SystemAdapter, "reverse_proxy_status", reverse_proxy_status)
    health = client.get(
        "/api/v1/traffic-publishing/reverse-proxies/health",
        headers={"Authorization": f"Bearer {reader}"},
    )

    assert health.status_code == 200, health.text
    item = health.json()["items"][0]
    assert item["proxy_id"] == proxy_id
    assert item["route_id"] == route_id
    assert item["status"] == "healthy"
    assert item["applied"] is True
    assert item["pending"] is False
    assert item["http_status"] == 204
    assert called == [True]


def test_reverse_proxy_delete_conflict_returns_problem_details_and_retains_intent(client, monkeypatch):
    """Project a failed DNS ownership transaction through the documented delete boundary.

    Args:
        client: Initialized authenticated appliance test client.
        monkeypatch: Scoped dependency replacements supplied by pytest.
    """
    from atlaso.app.schemas import ProblemDetails
    from atlaso.app.services import reverse_proxies

    _enable_test_listener()
    token, _ = create_token(client, scopes=["read:firewall", "write:firewall"])
    headers = {"Authorization": f"Bearer {token}"}
    collection = "/api/v1/traffic-publishing/reverse-proxies"
    created = client.post(collection, headers=headers, json=_payload())
    assert created.status_code == 201
    proxy_id = created.json()["id"]

    def conflict(*_args, **_kwargs):
        """Run conflict for the bounded proxy operation.

        Args:
            *_args: Input used by conflict.
            **_kwargs: Input used by conflict.
        """
        raise ValueError("Managed reverse-proxy DNS conflicts with an operator record.")

    monkeypatch.setattr(reverse_proxies, "delete_proxy", conflict)
    rejected = client.delete(f"{collection}/{proxy_id}", headers=headers)
    assert rejected.status_code == 422
    problem = ProblemDetails.model_validate(rejected.json())
    assert problem.status == 422
    assert "conflicts" in problem.detail
    assert client.get(f"{collection}/{proxy_id}", headers=headers).status_code == 200


@pytest.mark.parametrize("operation", ["physical", "vlan_create", "vlan_edit", "ui_vlan_create", "ui_vlan_edit"])
@pytest.mark.parametrize("upstream", ["10.10.20.30", "2001:db8::30"])
@pytest.mark.parametrize("proxy_enabled,collides", [(True, True), (False, True), (True, False)])
def test_interface_writers_preserve_proxy_upstream_ownership(client, operation, upstream, proxy_enabled, collides):
    """Reject appliance takeover of an enabled literal upstream before commit.

    Args:
        client: Isolated application HTTP client.
        operation: Physical or VLAN writer transport to exercise.
        upstream: Canonical IPv4 or IPv6 upstream literal.
        proxy_enabled: Whether the proxy must retain usable upstream ownership.
        collides: Whether the candidate assigns the upstream address itself.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, PhysicalInterface, VlanInterface
    from atlaso.app.services.reverse_proxies import save_proxy
    from atlaso.app.services.settings_archive import export_settings_archive
    from tests.routers.ui.helpers import login

    _enable_test_listener()
    ipv6 = ":" in upstream
    candidate = upstream if collides else ("2001:db8::40" if ipv6 else "10.10.20.40")
    cidr = candidate + ("/64" if ipv6 else "/24")
    with SessionLocal() as db:
        parent = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        parent.role = "access" if operation == "physical" else "unused"
        parent.mode = "access" if operation == "physical" else "trunk"
        parent.admin_state = parent.oper_state = "up"
        parent.ip_cidr = "10.10.40.1/24" if operation == "physical" else None
        db.commit()
        request = _payload(enabled=proxy_enabled, scheme="http", port=9443, redirect_http=False)
        request["routes"][0]["upstream_host"] = upstream
        save_proxy(db, request, actor="test")
        vlan_id = None
        if operation.endswith("edit"):
            vlan = VlanInterface(name="eth2.23", parent_interface="eth2", vlan_id=23,
                                 ip_cidr="10.10.40.1/24", role="access", enabled=True)
            db.add(vlan)
            db.commit()
            vlan_id = vlan.id
    token, _ = create_token(client, scopes=["write:interfaces", "write:vlans"])
    headers = {"Authorization": f"Bearer {token}"}
    values = {"parent_interface": "eth2", "vlan_id": 23, "role": "access", "enabled": True,
              "ip_cidr": "" if ipv6 else cidr, "ipv6_cidr": cidr if ipv6 else "",
              "check_duplicate_ip_addresses": False}
    if operation.startswith("ui_"):
        login(client)
        page = client.get("/vlan-interfaces")
        csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
        values.update(enabled="on", csrf=csrf, check_duplicate_ip_addresses="false")
        headers = {"X-Atlaso-Grid": "1", "Accept": "application/json"}
    with SessionLocal() as db:
        before = export_settings_archive(db, actor="test")["data"]
        audit_ids = list(db.scalars(select(AuditEvent.id)))
    if operation == "physical":
        response = client.patch("/api/v1/interfaces/physical/eth2", headers=headers, json={
            "ipv6_enabled": ipv6, "ipv6_cidr": cidr if ipv6 else "", "ip_cidr": "10.10.40.1/24" if ipv6 else cidr,
        })
    elif operation == "vlan_create":
        response = client.post("/api/v1/vlans", headers=headers, json=values)
    elif operation == "vlan_edit":
        response = client.patch(f"/api/v1/vlans/{vlan_id}", headers=headers, json=values)
    else:
        path = "/vlan-interfaces" if operation.endswith("create") else f"/vlan-interfaces/{vlan_id}/edit"
        response = client.post(path, headers=headers, data=values)
    if proxy_enabled and collides:
        assert response.status_code == 422, response.text
        assert "upstream address" in response.text
        with SessionLocal() as db:
            assert list(db.scalars(select(AuditEvent.id))) == audit_ids
            assert export_settings_archive(db, actor="test")["data"] == before
    else:
        assert response.status_code in {200, 201}, response.text


@pytest.mark.parametrize("interface_name", ["eth0", "eth1"])
@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("editing", [False, True])
def test_proxy_api_rejects_secondary_observed_ipv6_without_state_changes(client, interface_name, enabled, editing):
    """Reject a renumbered local upstream atomically at actual create and edit writers.

    Args:
        client: Isolated API test client.
        interface_name: Management or access owner of the observed local addresses.
        enabled: Saved proxy enabled state, including disabled intent.
        editing: Whether to replace an existing saved proxy instead of creating one.
    """
    import hashlib
    import json

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, PhysicalInterface
    from atlaso.app.services.reverse_proxies import save_proxy
    from atlaso.app.services.settings_archive import export_settings_archive

    _enable_test_listener()
    token, _ = create_token(client, scopes=["write:firewall"])
    headers = {"Authorization": f"Bearer {token}"}
    endpoint = "/api/v1/traffic-publishing/reverse-proxies"
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == interface_name))
        interface.host_ipv6_cidr = "2001:db8:1::10/64"
        interface.host_ipv6_cidrs = ["2001:db8:1::10/64", "bad-cidr", "2001:0db8:0002::0010/64"]
        db.commit()
        if editing:
            proxy = save_proxy(db, _payload(enabled=enabled), actor="test")
            endpoint += f"/{proxy.id}"
        before = hashlib.sha256(json.dumps(export_settings_archive(db, actor="test")["data"], sort_keys=True).encode()).hexdigest()
        audits = list(db.scalars(select(AuditEvent.id)))
    request = _payload(enabled=enabled)
    request["routes"][0]["upstream_host"] = "2001:db8:2::10"
    response = client.put(endpoint, json=request, headers=headers) if editing else client.post(endpoint, json=request, headers=headers)
    assert response.status_code == 422, response.text
    assert "assigned to this Atlaso appliance" in response.text
    with SessionLocal() as db:
        after = hashlib.sha256(json.dumps(export_settings_archive(db, actor="test")["data"], sort_keys=True).encode()).hexdigest()
        assert after == before
        assert list(db.scalars(select(AuditEvent.id))) == audits


@pytest.mark.parametrize("transport", ["api", "ui"])
@pytest.mark.parametrize("ipv6", [False, True])
@pytest.mark.parametrize("proxy_enabled,collides", [(True, True), (False, True), (True, False)])
def test_interface_service_rebase_preserves_proxy_sockets_atomically(client, transport, ipv6, proxy_enabled, collides):
    """Reject final rebased service claims without changing settings or audits.

    Args:
        client: Real application HTTP client.
        transport: Physical interface edit transport.
        ipv6: Whether the colliding socket belongs to IPv6.
        proxy_enabled: Whether the saved proxy reserves its listener.
        collides: Whether the rebased service takes the proxy address and port.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, KmsSettings, PhysicalInterface
    from atlaso.app.services.reverse_proxies import (
        save_proxy,
        validate_service_listener_sockets,
    )
    from atlaso.app.services.settings_archive import export_settings_archive
    from tests.routers.ui.helpers import login

    _enable_test_listener()
    proxy_address = "2001:db8::10" if ipv6 else "192.0.2.10"
    old_address = "2001:db8::20" if ipv6 else "198.51.100.20"
    candidate = proxy_address if collides else ("2001:db8::30" if ipv6 else "198.51.100.30")
    with SessionLocal() as db:
        first = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth1"))
        first.ipv6_enabled = ipv6
        first.ipv6_cidr = "2001:db8::10/64" if ipv6 else ""
        second = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        second.role = second.mode = "access"
        second.admin_state = second.oper_state = "up"
        second.ip_cidr = "198.51.100.20/24"
        second.ipv6_enabled = ipv6
        second.ipv6_cidr = "2001:db8::20/64" if ipv6 else ""
        second.check_duplicate_ip_addresses = False
        db.commit()
        values = _payload(enabled=proxy_enabled, scheme="http", port=5696, redirect_http=False)
        values["listeners"][0]["address"] = proxy_address
        save_proxy(db, values, actor="test")
        kms = db.scalar(select(KmsSettings))
        kms.enabled = True
        kms.port = 5696
        kms.listen_interface = "eth2"
        kms.listen_address = old_address
        db.commit()
        validate_service_listener_sockets(db)
        interface_id = second.id
    changes = {"ip_cidr": "198.51.100.20/24" if ipv6 else candidate + "/24",
               "ipv6_enabled": ipv6, "ipv6_cidr": candidate + "/64" if ipv6 else "",
               "check_duplicate_ip_addresses": False}
    if transport == "api":
        token, _ = create_token(client, scopes=["write:interfaces"])
        headers = {"Authorization": f"Bearer {token}"}
    else:
        login(client)
        page = client.get("/physical-interfaces")
        csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
        headers = {"X-Atlaso-Grid": "1", "Accept": "application/json"}
    with SessionLocal() as db:
        before = export_settings_archive(db, actor="test")["data"]
        audit_ids = list(db.scalars(select(AuditEvent.id)))
    if transport == "api":
        response = client.patch("/api/v1/interfaces/physical/eth2", headers=headers, json=changes)
    else:
        response = client.post(f"/physical-interfaces/{interface_id}/edit", headers=headers, data={
            **changes, "role": "access", "mode": "access", "ipv4_method": "static",
            "admin_state": "up", "mtu": 1500, "csrf": csrf,
            "ipv6_enabled": "on" if ipv6 else "false", "check_duplicate_ip_addresses": "false",
        })
    if proxy_enabled and collides:
        assert response.status_code == 422, response.text
        assert "Service listener conflicts" in response.text
        with SessionLocal() as db:
            assert export_settings_archive(db, actor="test")["data"] == before
            assert list(db.scalars(select(AuditEvent.id))) == audit_ids
    else:
        assert response.status_code in {200, 303}, response.text
        with SessionLocal() as db:
            assert candidate in db.scalar(select(KmsSettings)).listen_address
            validate_service_listener_sockets(db)
