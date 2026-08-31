"""Test Appliance Settings API v1 transports."""

from tests.routers.api_v1.helpers import create_token


def test_settings_api_router_owns_exact_transport_set():
    """Keep Settings API route identities and operation IDs exact."""
    from atlaso.app.api import v1

    assert [
        (
            route.path,
            tuple(sorted((route.methods or set()) - {"HEAD"})),
            route.name,
            route.operation_id,
        )
        for route in v1.settings_router.routes
    ] == [
        ("/api/v1/settings", ("GET",), "get_app_settings", "getSettings"),
        ("/api/v1/settings", ("PATCH",), "update_app_settings", "updateSettings"),
    ]


def test_settings_update_openapi_fields_are_omittable_but_non_nullable():
    """Describe PATCH omission without advertising null as an accepted value."""
    from atlaso.app.main import app

    schema = app.openapi()["components"]["schemas"]["SettingsUpdate"]
    assert "required" not in schema
    assert set(schema["properties"]) == {
        "appliance_fqdn",
        "management_https_enabled",
        "web_terminal_enabled",
        "web_terminal_interfaces",
        "root_ssh_enabled",
        "browser_session_idle_timeout_minutes",
        "api_token_max_lifetime_days",
        "external_dns_servers",
    }
    for property_schema in schema["properties"].values():
        assert "default" not in property_schema
        assert {"type": "null"} not in property_schema.get("anyOf", [])
    assert schema["properties"]["browser_session_idle_timeout_minutes"] == {
        "description": (
            "Maximum period of authenticated browser inactivity, in minutes, "
            "before Atlaso expires the session on its next protected request. "
            "Omit it to preserve the current value; null is not accepted."
        ),
        "maximum": 1440,
        "minimum": 5,
        "title": "Browser Session Idle Timeout Minutes",
        "type": "integer",
    }
    assert schema["properties"]["api_token_max_lifetime_days"] == {
        "description": (
            "Maximum lifetime, in days, applied to newly issued API bearer tokens; "
            "existing tokens are unchanged. Omit it to preserve the current value; "
            "null is not accepted."
        ),
        "maximum": 365,
        "minimum": 1,
        "title": "Api Token Max Lifetime Days",
        "type": "integer",
    }


def test_settings_api_updates_root_ssh_desired_state(client):
    """Verify that settings api updates root ssh desired state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    token, _metadata = create_token(client, scopes=["admin:all", "read:dashboard"])

    response = client.patch(
        "/api/v1/settings",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "appliance_fqdn": "api.atlaso.internal",
            "management_https_enabled": False,
            "root_ssh_enabled": True,
            "external_dns_servers": ["1.1.1.1", "9.9.9.9"],
        },
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["appliance_fqdn"] == "api.atlaso.internal"
    assert payload["root_ssh_enabled"] is True
    assert '"root_ssh_enabled": true' in payload["config_preview"]


def test_settings_api_preserves_omitted_authentication_lifetimes(client):
    """PATCH fields omitted by the caller retain their persisted policy values.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings

    with SessionLocal() as db:
        settings = db.execute(select(ApplianceSettings)).scalar_one()
        settings.browser_session_idle_timeout_minutes = 45
        settings.api_token_max_lifetime_days = 120
        db.commit()

    token, _metadata = create_token(client, scopes=["admin:all", "read:dashboard"])
    response = client.patch(
        "/api/v1/settings",
        headers={"Authorization": f"Bearer {token}"},
        json={"root_ssh_enabled": True},
    )

    assert response.status_code == 200, response.text
    assert response.json()["browser_session_idle_timeout_minutes"] == 45
    assert response.json()["api_token_max_lifetime_days"] == 120
    with SessionLocal() as db:
        settings = db.execute(select(ApplianceSettings)).scalar_one()
        assert settings.browser_session_idle_timeout_minutes == 45
        assert settings.api_token_max_lifetime_days == 120


def test_settings_api_lifetime_patch_preserves_operational_settings(client):
    """A lifetime-only PATCH must not reset unrelated appliance desired state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings

    with SessionLocal() as db:
        settings = db.execute(select(ApplianceSettings)).scalar_one()
        settings.fqdn = "custom.example.internal"
        settings.management_https_enabled = True
        settings.web_terminal_enabled = True
        settings.web_terminal_interfaces_json = '["custom-terminal"]'
        settings.root_ssh_enabled = True
        settings.external_dns_servers = "192.0.2.53"
        db.commit()

    token, _metadata = create_token(client, scopes=["admin:all", "read:dashboard"])
    response = client.patch(
        "/api/v1/settings",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "browser_session_idle_timeout_minutes": 45,
            "api_token_max_lifetime_days": 120,
        },
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["appliance_fqdn"] == "custom.example.internal"
    assert payload["management_https_enabled"] is True
    assert payload["web_terminal_enabled"] is True
    assert payload["web_terminal_interfaces"] == ["eth0", "custom-terminal"]
    assert payload["root_ssh_enabled"] is True
    assert payload["external_dns_servers"] == ["192.0.2.53"]
    assert payload["browser_session_idle_timeout_minutes"] == 45
    assert payload["api_token_max_lifetime_days"] == 120

    with SessionLocal() as db:
        settings = db.execute(select(ApplianceSettings)).scalar_one()
        assert settings.fqdn == "custom.example.internal"
        assert settings.management_https_enabled is True
        assert settings.web_terminal_enabled is True
        assert settings.web_terminal_interfaces_json == '["custom-terminal"]'
        assert settings.root_ssh_enabled is True
        assert settings.external_dns_servers == "192.0.2.53"


def test_settings_api_mixed_partial_patch_preserves_omitted_fields(client):
    """Explicit false and empty values retain their PATCH meanings.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings

    with SessionLocal() as db:
        settings = db.execute(select(ApplianceSettings)).scalar_one()
        settings.fqdn = "custom.example.internal"
        settings.management_https_enabled = True
        settings.web_terminal_enabled = True
        settings.web_terminal_interfaces_json = '["custom-terminal"]'
        settings.root_ssh_enabled = True
        settings.external_dns_servers = "192.0.2.53"
        settings.browser_session_idle_timeout_minutes = 45
        db.commit()

    token, _metadata = create_token(client, scopes=["admin:all", "read:dashboard"])
    response = client.patch(
        "/api/v1/settings",
        headers={"Authorization": f"Bearer {token}"},
        json={"root_ssh_enabled": False, "external_dns_servers": []},
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["appliance_fqdn"] == "custom.example.internal"
    assert payload["management_https_enabled"] is True
    assert payload["web_terminal_enabled"] is True
    assert payload["web_terminal_interfaces"] == ["eth0", "custom-terminal"]
    assert payload["root_ssh_enabled"] is False
    assert payload["external_dns_servers"] == []
    assert payload["browser_session_idle_timeout_minutes"] == 45


def test_settings_api_omitted_or_unchanged_fqdn_skips_domain_reconciliation(
    client, monkeypatch
):
    """Reconcile domain-coupled state only for a supplied, changed FQDN.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to observe reconciliation boundaries.
    """
    from atlaso.app import ui as ui_module

    calls: list[str] = []
    monkeypatch.setattr(
        ui_module,
        "reconcile_factory_service_identities",
        lambda *args, **kwargs: calls.append("identities") or [],
    )
    monkeypatch.setattr(
        ui_module,
        "ensure_dns_for_appliance_settings",
        lambda *args, **kwargs: calls.append("dns") or None,
    )
    monkeypatch.setattr(
        ui_module,
        "refresh_interface_service_dns_aliases",
        lambda *args, **kwargs: calls.append("aliases") or [],
    )

    token, _metadata = create_token(client, scopes=["admin:all", "read:dashboard"])
    headers = {"Authorization": f"Bearer {token}"}
    omitted = client.patch(
        "/api/v1/settings",
        headers=headers,
        json={"root_ssh_enabled": True},
    )
    unchanged = client.patch(
        "/api/v1/settings",
        headers=headers,
        json={"appliance_fqdn": "CORE.ATLASO.INTERNAL."},
    )

    assert omitted.status_code == 200, omitted.text
    assert unchanged.status_code == 200, unchanged.text
    assert calls == []


def test_settings_api_rejects_explicit_null_patch_values(client):
    """Null must not replace omission for fields that do not support clearing.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    token, _metadata = create_token(client, scopes=["admin:all", "read:dashboard"])

    response = client.patch(
        "/api/v1/settings",
        headers={"Authorization": f"Bearer {token}"},
        json={"management_https_enabled": None},
    )

    assert response.status_code == 422, response.text
    assert response.json()["error_code"] == "VALIDATION_ERROR"


def test_settings_api_reconciles_factory_service_identities(client, monkeypatch):
    """Keep API-driven appliance-domain changes coherent with factory service state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to observe the alias reconciliation boundary.
    """
    from sqlalchemy import select

    from atlaso.app import ui as ui_module
    from atlaso.app.api import v1
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        AuditEvent,
        CaSettings,
        DnsRecord,
        DnsSettings,
        EsxStorageSettings,
        KmsSettings,
        LdapSettings,
        NtpSettings,
        OidcProviderSettings,
        PhysicalInterface,
        Setting,
        VcfOfflineDepotSettings,
        VcfPrivateRegistrySettings,
    )
    from atlaso.app.services.appliance_settings import (
        APPLIANCE_DNS_RECORD_DESCRIPTION,
    )
    from atlaso.app.services.oidc import ensure_provider_settings
    from atlaso.app.services.service_dns_defaults import ESXI_PXE_HOSTNAME_KEY
    from atlaso.app.ui import get_esx_storage_settings_row

    alias_actors: list[str | None] = []
    appliance_dns_calls: list[tuple[str, str, str | None]] = []
    original_alias_refresher = v1.refresh_interface_service_dns_aliases
    original_appliance_dns_reconciler = ui_module.ensure_dns_for_appliance_settings

    def observe_alias_refresh(db, actor=None):
        """Record the audit boundary while preserving the real alias reconciliation.

        Args:
            db: Active database session.
            actor: Optional audit actor passed to the alias reconciler.
        """
        alias_actors.append(actor)
        return original_alias_refresher(db, actor=actor)

    monkeypatch.setattr(v1, "refresh_interface_service_dns_aliases", observe_alias_refresh)

    def observe_appliance_dns_reconciliation(
        db, appliance_settings, *, previous_fqdn, actor
    ):
        """Record API appliance-DNS inputs while preserving real reconciliation.

        Args:
            db: Active database session.
            appliance_settings: Desired appliance settings supplied by the API.
            previous_fqdn: Appliance FQDN before the update.
            actor: Optional audit actor passed to the DNS reconciler.
        """
        appliance_dns_calls.append(
            (previous_fqdn, appliance_settings.fqdn, actor)
        )
        return original_appliance_dns_reconciler(
            db,
            appliance_settings,
            previous_fqdn=previous_fqdn,
            actor=actor,
        )

    monkeypatch.setattr(
        ui_module,
        "ensure_dns_for_appliance_settings",
        observe_appliance_dns_reconciliation,
    )

    with SessionLocal() as db:
        ensure_provider_settings(db)
        get_esx_storage_settings_row(db)
        db.add(Setting(key=ESXI_PXE_HOSTNAME_KEY, value="esxi-pxe.atlaso.internal"))
        db.add(
            PhysicalInterface(
                name="api-mgmt",
                mac_address="02:00:00:00:57:04",
                ip_cidr="192.0.2.57/24",
                ipv6_enabled=True,
                ipv6_cidr="2001:db8::57/64",
                role="management",
                mode="dedicated",
            )
        )
        db.add_all(
            [
                DnsRecord(
                    hostname="core.atlaso.internal",
                    record_type="A",
                    address="192.0.2.57",
                    description=APPLIANCE_DNS_RECORD_DESCRIPTION,
                    enabled=True,
                ),
                DnsRecord(
                    hostname="core.atlaso.internal",
                    record_type="AAAA",
                    address="2001:db8::57",
                    description=APPLIANCE_DNS_RECORD_DESCRIPTION,
                    enabled=True,
                ),
            ]
        )
        db.commit()

    token, _metadata = create_token(client, scopes=["admin:all", "read:dashboard"])

    response = client.patch(
        "/api/v1/settings",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "appliance_fqdn": "api.lab.internal",
            "management_https_enabled": False,
            "root_ssh_enabled": False,
            "external_dns_servers": [],
        },
    )

    assert response.status_code == 200, response.text
    with SessionLocal() as db:
        assert db.execute(select(NtpSettings)).scalar_one().hostname == "ntp.lab.internal"
        assert db.execute(select(CaSettings)).scalar_one().portal_hostname == "ca.lab.internal"
        assert db.execute(select(KmsSettings)).scalar_one().hostname == "kms.lab.internal"
        assert db.execute(select(LdapSettings)).scalar_one().hostname == "ldap.lab.internal"
        oidc = db.execute(select(OidcProviderSettings)).scalar_one()
        assert oidc.hostname == "oidc.lab.internal"
        assert oidc.issuer_url == "https://oidc.lab.internal/identity"
        assert (
            db.execute(select(EsxStorageSettings)).scalar_one().hostname
            == "nfs.lab.internal"
        )
        assert (
            db.execute(select(VcfPrivateRegistrySettings)).scalar_one().hostname
            == "registry.lab.internal"
        )
        assert (
            db.execute(select(VcfOfflineDepotSettings)).scalar_one().hostname
            == "depot.lab.internal"
        )
        pxe = db.execute(
            select(Setting).where(Setting.key == ESXI_PXE_HOSTNAME_KEY)
        ).scalar_one()
        assert pxe.value == "esxi-pxe.lab.internal"
        dns_settings = db.execute(select(DnsSettings)).scalar_one()
        assert "lab.internal" in dns_settings.domain.split()
        appliance_records = db.execute(
            select(DnsRecord)
            .where(
                DnsRecord.description == APPLIANCE_DNS_RECORD_DESCRIPTION,
            )
            .order_by(DnsRecord.record_type)
        ).scalars().all()
        appliance_record_values = {
            (record.hostname, record.record_type, record.address)
            for record in appliance_records
        }
        assert {
            ("api.lab.internal", "A", "192.0.2.57"),
            ("api.lab.internal", "AAAA", "2001:db8::57"),
        }.issubset(appliance_record_values)
        assert {record.hostname for record in appliance_records} == {
            "api.lab.internal"
        }
        audit = db.execute(
            select(AuditEvent)
            .where(AuditEvent.action == "update_appliance_settings")
            .order_by(AuditEvent.id.desc())
        ).scalars().first()
        assert audit is not None
        assert "factory_service_identities=" in (audit.detail or "")
        assert "appliance_dns=" in (audit.detail or "")
    assert alias_actors == [None]
    assert appliance_dns_calls == [
        ("core.atlaso.internal", "api.lab.internal", None)
    ]


def test_settings_api_retains_read_and_admin_scope_boundaries(client):
    """Verify the extracted Settings operations keep their distinct scopes.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    read_token, _metadata = create_token(client, scopes=["read:dashboard"])
    headers = {"Authorization": f"Bearer {read_token}"}

    assert client.get("/api/v1/settings", headers=headers).status_code == 200
    assert (
        client.patch(
            "/api/v1/settings",
            headers=headers,
            json={
                "appliance_fqdn": "api.atlaso.internal",
                "management_https_enabled": False,
                "root_ssh_enabled": False,
                "external_dns_servers": [],
            },
        ).status_code
        == 403
    )


def test_settings_api_keeps_ca_reconciliation_in_request_transaction(
    client, monkeypatch
):
    """Run successful API CA reconciliation without an independent commit.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to observe the CA transaction boundary.
    """
    from sqlalchemy import select

    from atlaso.app import ui as ui_module
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaSettings

    commit_modes: list[bool] = []
    original_ensure_ca_state = ui_module.ensure_ca_state

    def observe_ca_state(db, *, commit=True):
        """Record and preserve the requested CA transaction mode.

        Args:
            db: Active database session.
            commit: Whether CA reconciliation may commit independently.
        """
        commit_modes.append(commit)
        return original_ensure_ca_state(db, commit=commit)

    monkeypatch.setattr(ui_module, "ensure_ca_state", observe_ca_state)
    with SessionLocal() as db:
        ca_settings = db.execute(select(CaSettings)).scalar_one()
        ca_settings.enabled = True
        db.commit()

    token, _metadata = create_token(client, scopes=["admin:all", "read:dashboard"])
    response = client.patch(
        "/api/v1/settings",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "appliance_fqdn": "api.lab.internal",
            "management_https_enabled": True,
            "root_ssh_enabled": False,
            "external_dns_servers": [],
        },
    )

    assert response.status_code == 200, response.text
    assert commit_modes == [False]


def test_settings_api_rolls_back_domain_when_ca_reconciliation_fails(
    client, monkeypatch
):
    """Reject CA errors without persisting any coupled domain mutation.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to inject a CA validation failure.
    """
    from sqlalchemy import select

    from atlaso.app import ui as ui_module
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, CaSettings, NtpSettings

    with SessionLocal() as db:
        ca_settings = db.execute(select(CaSettings)).scalar_one()
        ca_settings.enabled = True
        db.commit()

    monkeypatch.setattr(
        ui_module,
        "ensure_ca_state",
        lambda db, *, commit=True: ["CA certificate reconciliation failed."],
    )
    token, _metadata = create_token(client, scopes=["admin:all", "read:dashboard"])
    response = client.patch(
        "/api/v1/settings",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "appliance_fqdn": "api.lab.internal",
            "management_https_enabled": True,
            "root_ssh_enabled": False,
            "external_dns_servers": [],
        },
    )

    assert response.status_code == 422, response.text
    assert response.json()["detail"] == "CA certificate reconciliation failed."
    with SessionLocal() as db:
        assert db.execute(select(ApplianceSettings)).scalar_one().fqdn == (
            "core.atlaso.internal"
        )
        assert db.execute(select(NtpSettings)).scalar_one().hostname == (
            "ntp.atlaso.internal"
        )
