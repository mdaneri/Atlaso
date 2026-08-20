"""Test Vault management UI transports."""

from sqlalchemy import select

from tests.routers.ui.helpers import login


def test_vaults_router_owns_exact_transport_set():
    """Keep Vault route identities in their established order."""
    from atlaso.app import ui

    assert [
        (route.path, tuple(sorted((route.methods or set()) - {"HEAD"})), route.name)
        for route in ui.vaults_router.routes
    ] == [
        ("/ui/management/vaults", ("GET",), "vaults_page"),
        ("/ui/management/vaults", ("POST",), "create_vault_from_ui"),
        (
            "/ui/management/vaults/{vault_id}/entries",
            ("POST",),
            "create_vault_entry_from_ui",
        ),
        (
            "/ui/management/vaults/{vault_id}/entries/{entry_id}/edit",
            ("POST",),
            "edit_vault_entry_from_ui",
        ),
        (
            "/ui/management/vaults/{vault_id}/entries/{entry_id}/reveal",
            ("POST",),
            "reveal_vault_entry_from_ui",
        ),
        (
            "/ui/management/vaults/{vault_id}/entries/{entry_id}/delete",
            ("POST",),
            "delete_vault_entry_from_ui",
        ),
        (
            "/ui/management/vaults/{vault_id}/delete",
            ("POST",),
            "delete_vault_from_ui",
        ),
    ]


def test_vaults_page_keeps_legacy_and_session_redirects(client):
    """Verify Vault page routing retains legacy and session boundaries.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    legacy = client.get("/vaults", follow_redirects=False)
    assert legacy.status_code == 307
    assert legacy.headers["location"] == "/ui/management/vaults"

    canonical = client.get("/ui/management/vaults", follow_redirects=False)
    assert canonical.status_code == 303
    assert (
        canonical.headers["location"]
        == "/ui/management/login?next=/ui/management/vaults"
    )


def test_vault_create_and_delete_keep_transport_contracts(client):
    """Verify Vault create/delete retain CSRF, redirect, and persistence behavior.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Vault

    login(client)
    page = client.get("/ui/management/vaults")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    invalid = client.post(
        "/ui/management/vaults",
        data={"csrf": "invalid", "name": "Transport contract"},
        follow_redirects=False,
    )
    assert invalid.status_code == 403

    created = client.post(
        "/ui/management/vaults",
        data={
            "csrf": csrf,
            "name": "Transport contract",
            "description": "Transport ownership coverage",
        },
        follow_redirects=False,
    )
    assert created.status_code == 303
    with SessionLocal() as db:
        vault = db.execute(
            select(Vault).where(Vault.name == "Transport contract")
        ).scalar_one()
        vault_id = vault.id
    assert (
        created.headers["location"]
        == f"/ui/management/vaults#vault-panel-{vault_id}"
    )

    deleted = client.post(
        f"/ui/management/vaults/{vault_id}/delete",
        data={"csrf": csrf},
        follow_redirects=False,
    )
    assert deleted.status_code == 303
    assert deleted.headers["location"] == "/ui/management/vaults"
    with SessionLocal() as db:
        assert db.get(Vault, vault_id) is None


def test_vault_create_keeps_facade_monkeypatch_seam(client, monkeypatch):
    """Verify the extracted transport resolves facade-owned helpers at call time.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest helper used to replace the facade compatibility seam.
    """
    from atlaso.app import ui

    def reject_create(*_args, **_kwargs):
        """Reject the synthetic Vault create operation.

        Args:
            *_args: Positional arguments supplied through the facade seam.
            **_kwargs: Keyword arguments supplied through the facade seam.
        """
        raise ValueError("Synthetic transport rejection.")

    login(client)
    page = client.get("/ui/management/vaults")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    monkeypatch.setattr(ui, "create_vault", reject_create)

    response = client.post(
        "/ui/management/vaults",
        data={"csrf": csrf, "name": "Rejected transport"},
    )
    assert response.status_code == 422
    assert "Synthetic transport rejection." in response.text
