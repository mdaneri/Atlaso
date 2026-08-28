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


def test_settings_api_reconciles_factory_service_identities(client, monkeypatch):
    """Keep API-driven appliance-domain changes coherent with factory service state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to observe the alias reconciliation boundary.
    """
    from sqlalchemy import select

    from atlaso.app.api import v1
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        AuditEvent,
        CaSettings,
        EsxStorageSettings,
        KmsSettings,
        LdapSettings,
        NtpSettings,
        OidcProviderSettings,
        Setting,
        VcfOfflineDepotSettings,
        VcfPrivateRegistrySettings,
    )
    from atlaso.app.services.oidc import ensure_provider_settings
    from atlaso.app.services.service_dns_defaults import ESXI_PXE_HOSTNAME_KEY
    from atlaso.app.ui import get_esx_storage_settings_row

    alias_actors: list[str | None] = []
    original_alias_refresher = v1.refresh_interface_service_dns_aliases

    def observe_alias_refresh(db, actor=None):
        """Record the audit boundary while preserving the real alias reconciliation.

        Args:
            db: Active database session.
            actor: Optional audit actor passed to the alias reconciler.
        """
        alias_actors.append(actor)
        return original_alias_refresher(db, actor=actor)

    monkeypatch.setattr(v1, "refresh_interface_service_dns_aliases", observe_alias_refresh)

    with SessionLocal() as db:
        ensure_provider_settings(db)
        get_esx_storage_settings_row(db)
        db.add(Setting(key=ESXI_PXE_HOSTNAME_KEY, value="esxi-pxe.atlaso.internal"))
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
        audit = db.execute(
            select(AuditEvent)
            .where(AuditEvent.action == "update_appliance_settings")
            .order_by(AuditEvent.id.desc())
        ).scalars().first()
        assert audit is not None
        assert "factory_service_identities=" in (audit.detail or "")
    assert alias_actors == [None]


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
