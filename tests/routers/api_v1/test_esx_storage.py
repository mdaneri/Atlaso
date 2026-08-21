"""Test ESX Storage API v1 transports."""

from types import SimpleNamespace

from atlaso.app.adapters.system import AdapterResult
from atlaso.app.api import v1


def api_token(client, scopes: list[str]) -> str:
    """Return api token.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        scopes: Normalized authorization scopes granted or required by the operation.
    """
    response = client.post(
        "/api/v1/auth/login?username=admin&password=atlaso-admin",
        json={"name": "esx storage test", "scopes": scopes},
    )
    assert response.status_code == 200, response.text
    return response.json()["raw_token"]


def test_esx_storage_api_router_owns_exact_transport_set() -> None:
    """Keep the extracted API router limited to established ESX Storage operations."""
    assert [
        (route.path, tuple(sorted(route.methods or ())), route.name)
        for route in v1.esx_storage_router.routes
    ] == [
        ("/api/v1/esx-storage/status", ("GET",), "get_esx_storage_status"),
        ("/api/v1/esx-storage/status", ("PATCH",), "update_esx_storage_settings"),
        ("/api/v1/esx-storage/disks", ("GET",), "get_esx_storage_disks"),
        ("/api/v1/esx-storage/volumes", ("GET",), "get_esx_storage_volumes"),
        ("/api/v1/esx-storage/volumes", ("POST",), "create_esx_storage_volume"),
        (
            "/api/v1/esx-storage/volumes/{volume_id}",
            ("PATCH",),
            "update_esx_storage_volume",
        ),
        ("/api/v1/esx-storage/shares", ("GET",), "get_esx_nfs_shares"),
        ("/api/v1/esx-storage/shares", ("POST",), "create_esx_nfs_share"),
        ("/api/v1/esx-storage/shares/{share_id}", ("PATCH",), "update_esx_nfs_share"),
        ("/api/v1/esx-storage/shares/{share_id}", ("DELETE",), "delete_esx_nfs_share"),
    ]


def test_esx_storage_api_keeps_late_bound_facade_adapter_seam(
    client, monkeypatch
) -> None:
    """Resolve the API facade adapter when an inventory-backed request executes.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """

    class FacadeAdapter:
        """Return a distinctive bounded inventory failure."""

        def __init__(self, **_kwargs) -> None:
            """Accept the established adapter constructor contract.

            Args:
                **_kwargs: Adapter constructor options supplied by the facade.
            """

        def esx_storage_inventory(self) -> AdapterResult:
            """Return the facade-owned inventory result."""
            return AdapterResult(
                command=["atlaso-helper", "esx-storage", "inventory"],
                dry_run=False,
                returncode=1,
                stderr="late-bound API facade adapter",
            )

    monkeypatch.setattr(v1, "SystemAdapter", FacadeAdapter)
    monkeypatch.setattr(
        "atlaso.app.routers.api_v1.esx_storage.get_settings",
        lambda: SimpleNamespace(dry_run_system_adapters=False),
    )
    token = api_token(client, ["write:esx-storage"])

    response = client.post(
        "/api/v1/esx-storage/volumes",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "late-bound-api",
            "source_type": "mounted_ext4",
            "mount_path": "/mnt/late-bound-api",
        },
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "late-bound API facade adapter"


def test_esx_storage_write_scope_is_enforced(client):
    """Verify that esx storage write scope is enforced.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    token = api_token(client, ["read:esx-storage"])
    response = client.post(
        "/api/v1/esx-storage/volumes",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "forbidden",
            "source_type": "mounted_ext4",
            "mount_path": "/mnt/forbidden",
        },
    )
    assert response.status_code == 403
