"""Test ESX Storage management UI transports."""

from types import SimpleNamespace

from atlaso.app import ui
from atlaso.app.adapters.system import AdapterResult
from tests.routers.ui.helpers import login


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


def test_esx_storage_ui_router_owns_exact_transport_set() -> None:
    """Keep the extracted UI router limited to established ESX Storage transports."""
    assert [
        (route.path, tuple(sorted(route.methods or ())), route.name)
        for route in ui.esx_storage_router.routes
    ] == [
        ("/ui/management/esx-storage", ("GET",), "esx_storage_page"),
        (
            "/ui/management/esx-storage/settings",
            ("POST",),
            "update_esx_storage_settings_from_ui",
        ),
        (
            "/ui/management/esx-storage/volumes",
            ("POST",),
            "create_esx_storage_volume_from_ui",
        ),
        (
            "/ui/management/esx-storage/shares",
            ("POST",),
            "create_esx_nfs_share_from_ui",
        ),
        (
            "/ui/management/esx-storage/shares/{share_id}",
            ("POST",),
            "update_esx_nfs_share_from_ui",
        ),
        (
            "/ui/management/esx-storage/shares/{share_id}/delete",
            ("POST",),
            "delete_esx_nfs_share_from_ui",
        ),
    ]


def test_esx_storage_ui_keeps_late_bound_facade_adapter_seam(
    client, monkeypatch
) -> None:
    """Resolve the facade adapter when an inventory-backed request executes.

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
                stderr="late-bound UI facade adapter",
            )

    login(client)
    page = client.get("/ui/management/esx-storage")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    monkeypatch.setattr(ui, "SystemAdapter", FacadeAdapter)
    monkeypatch.setattr(
        "atlaso.app.routers.ui.esx_storage.get_settings",
        lambda: SimpleNamespace(dry_run_system_adapters=False),
    )

    response = client.post(
        "/ui/management/esx-storage/volumes",
        data={
            "name": "late-bound-ui",
            "source_type": "mounted_ext4",
            "mount_path": "/mnt/late-bound-ui",
            "csrf": csrf,
        },
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "late-bound UI facade adapter"


def test_esx_storage_page_and_dual_stack_api_contract(client):
    """Verify that esx storage page and dual stack api contract.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    page = client.get("/login")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    assert (
        client.post(
            "/login",
            data={"username": "admin", "password": "atlaso-admin", "csrf": csrf},
            follow_redirects=False,
        ).status_code
        == 303
    )
    page = client.get("/esx-storage")
    assert page.status_code == 200
    assert "IPv4 and IPv6 are equivalent connection paths" in page.text
    assert 'id="esx-storage-volumes-table"' in page.text
    assert 'id="esx-storage-shares-table"' in page.text
    assert 'data-esx-storage-wizard-open="volume"' in page.text
    assert "+ Add storage volume here" in page.text
    assert 'id="esx-storage-volume-modal"' in page.text
    assert 'data-esx-storage-wizard="volume"' in page.text
    assert "Select an eligible blank disk" not in page.text
    assert "Select an eligible mounted ext4 volume" not in page.text
    assert "No eligible blank disks available" in page.text
    assert "No eligible mounted ext4 volumes available" in page.text
    assert 'data-esx-storage-wizard-open="share"' in page.text
    assert "+ Add NFS datastore here" in page.text
    assert 'id="esx-storage-share-modal"' in page.text
    assert 'data-esx-storage-wizard="share"' in page.text
    assert 'data-tab-storage-key="atlaso:esx-storage:active-tab"' in page.text
    assert 'data-tab-target="connection-instructions"' in page.text
    assert 'id="connection-instructions"' in page.text
    assert 'name="enabled" checked' in page.text
    assert 'data-esx-storage-review="share-state"' in page.text
    assert "Step 1 of 5" in page.text
    assert "<strong>State</strong><small>Enable or disable</small>" in page.text
    assert "Choose datastore state" in client.get("/static/app.js").text
    assert "Leave empty to allow any IPv4 client (0.0.0.0/0)." in page.text
    assert "Leave empty to allow any IPv6 client (::/0)." in page.text
    assert "initializeEsxStorageWizards" in client.get("/static/app.js").text
    assert "any IPv4 client" in client.get("/static/app.js").text
    assert "await fetch(form.action" in client.get("/static/app.js").text
    assert (
        'window.history.replaceState(null, "", target)'
        in client.get("/static/app.js").text
    )
    assert (
        "`${window.location.pathname}${window.location.search}#${targetId}`"
        in client.get("/static/app.js").text
    )
    apply_refresh_js = (
        client.get("/static/app.js")
        .text.split("function refreshCurrentWorkflowAfterApplianceApply", 1)[1]
        .split("async function submitApplianceApplyForm", 1)[0]
    )
    assert (
        'new Set([managementUiPath("/esx-storage"), managementUiPath("/vcf-offline-depot")])'
        in apply_refresh_js
    )
    assert "refreshableWorkflows.has(window.location.pathname)" in apply_refresh_js
    assert 'label: "Edit datastore"' in client.get("/static/app.js").text
    assert (
        "rowDblClick: (_event, row) => editRow(row)"
        in client.get("/static/app.js").text
    )
    assert 'editor: "tickCross"' in client.get("/static/app.js").text
    assert "cellEdited: saveEnabledState" in client.get("/static/app.js").text

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord, DnsSettings, PhysicalInterface

    with SessionLocal() as db:
        db.add(
            PhysicalInterface(
                name="storage87",
                mac_address="00:15:5d:00:87:01",
                role="access",
                mode="access",
                ip_cidr="192.168.87.254/24",
                ipv6_enabled=True,
                ipv6_cidr="2001:db8:87::fe/64",
            )
        )
        dns = db.query(DnsSettings).first()
        if dns is None:
            dns = DnsSettings()
            db.add(dns)
        dns.enabled = True
        dns.domain = "atlaso.internal"
        db.commit()

    token = api_token(
        client, ["read:esx-storage", "write:esx-storage", "read:interfaces"]
    )
    headers = {"Authorization": f"Bearer {token}"}
    interfaces = client.get("/api/v1/interfaces/physical", headers=headers).json()
    interface = next(row for row in interfaces if row["name"] == "storage87")
    for reserved_path in ["/mnt/atlaso-vcf-backups", "/mnt/atlaso-vcf-offline-depot"]:
        rejected_volume = client.post(
            "/api/v1/esx-storage/volumes",
            headers=headers,
            json={
                "name": f"reserved-{reserved_path.rsplit('/', 1)[-1]}",
                "source_type": "mounted_ext4",
                "mount_path": reserved_path,
            },
        )
        assert rejected_volume.status_code == 422
        assert "reserved for" in rejected_volume.json()["detail"]
    volume_response = client.post(
        "/api/v1/esx-storage/volumes",
        headers=headers,
        json={
            "name": "existing-ext4",
            "source_type": "mounted_ext4",
            "mount_path": "/mnt/existing-ext4",
        },
    )
    assert volume_response.status_code == 201, volume_response.text
    share_response = client.post(
        "/api/v1/esx-storage/shares",
        headers=headers,
        json={
            "datastore_name": "dual-stack-ds",
            "volume_id": volume_response.json()["id"],
            "relative_path": "datastores/dual-stack",
            "preferred_nfs_version": "4.1",
            "interface_name": interface["name"],
            "address_families": ["ipv4", "ipv6"],
            "ipv4_clients": ["192.0.2.10/32"],
            "ipv6_clients": ["2001:db8:87::10/128"],
            "enabled": True,
        },
    )
    assert share_response.status_code == 201, share_response.text
    assert share_response.json()["address_families"] == ["ipv4", "ipv6"]
    assert share_response.json()["connection_commands"]["ipv4"]
    assert share_response.json()["connection_commands"]["ipv6"]
    assert share_response.json()["powercli_commands"]["ipv4"]
    assert share_response.json()["powercli_commands"]["ipv6"]
    edit_page = client.get("/esx-storage")
    edit_csrf = edit_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    assert "esx-storage-command-details" in edit_page.text
    assert "PowerCLI · IPv4 · NFS 4.1" in edit_page.text
    assert "PowerCLI · IPv6 · NFS 4.1" in edit_page.text
    assert "data-copy-value=" in edit_page.text
    updated_share = client.post(
        f"/esx-storage/shares/{share_response.json()['id']}",
        data={
            "datastore_name": "dual-stack-ds",
            "volume_id": volume_response.json()["id"],
            "relative_path": "datastores/dual-stack",
            "preferred_nfs_version": "4.1",
            "interface_name": interface["name"],
            "address_families": ["ipv4", "ipv6"],
            "ipv4_clients": "",
            "ipv6_clients": "",
            "enabled": "on",
            "csrf": edit_csrf,
        },
        follow_redirects=False,
    )
    assert updated_share.status_code == 303, updated_share.text
    edited = client.get("/api/v1/esx-storage/shares", headers=headers).json()[0]
    assert edited["ipv4_clients"] == ["0.0.0.0/0"]
    assert edited["ipv6_clients"] == ["::/0"]
    disabled_share = client.post(
        f"/esx-storage/shares/{share_response.json()['id']}",
        data={
            "datastore_name": "dual-stack-ds",
            "volume_id": volume_response.json()["id"],
            "relative_path": "datastores/dual-stack",
            "preferred_nfs_version": "4.1",
            "interface_name": interface["name"],
            "address_families": ["ipv4", "ipv6"],
            "ipv4_clients": "",
            "ipv6_clients": "",
            "csrf": edit_csrf,
        },
        follow_redirects=False,
    )
    assert disabled_share.status_code == 303, disabled_share.text
    assert (
        client.get("/api/v1/esx-storage/shares", headers=headers).json()[0]["enabled"]
        is False
    )
    reenabled_share = client.post(
        f"/esx-storage/shares/{share_response.json()['id']}",
        data={
            "datastore_name": "dual-stack-ds",
            "volume_id": volume_response.json()["id"],
            "relative_path": "datastores/dual-stack",
            "preferred_nfs_version": "4.1",
            "interface_name": interface["name"],
            "address_families": ["ipv4", "ipv6"],
            "ipv4_clients": "",
            "ipv6_clients": "",
            "enabled": "on",
            "csrf": edit_csrf,
        },
        follow_redirects=False,
    )
    assert reenabled_share.status_code == 303, reenabled_share.text
    status = client.patch(
        "/api/v1/esx-storage/status",
        headers=headers,
        json={"enabled": True, "hostname": "nfs.atlaso.internal"},
    )
    assert status.status_code == 200, status.text
    assert status.json()["valid"] is True

    with SessionLocal() as db:
        owned = (
            db.query(DnsRecord)
            .filter(DnsRecord.description == "Created from ESX Storage endpoint.")
            .all()
        )
        assert {(row.hostname, row.record_type, row.address) for row in owned} == {
            ("nfs.atlaso.internal", "A", "192.168.87.254"),
            ("nfs.atlaso.internal", "AAAA", "2001:db8:87::fe"),
            ("nfs-192-168-87-254.atlaso.internal", "A", "192.168.87.254"),
            ("nfs-2001-db8-87-0-0-0-0-fe.atlaso.internal", "AAAA", "2001:db8:87::fe"),
        }
        storage = (
            db.query(PhysicalInterface)
            .filter(PhysicalInterface.name == "storage87")
            .one()
        )
        storage.ip_cidr = "203.0.113.254/24"
        storage.ipv6_cidr = "2001:db8:88::fe/64"
        db.add(
            DnsRecord(
                hostname="nfs-203-0-113-254.atlaso.internal",
                record_type="A",
                address="203.0.113.254",
                description="Operator owned",
                enabled=True,
            )
        )
        db.commit()

        from atlaso.app.ui import ensure_dns_for_esx_storage, esx_storage_context

        ensure_dns_for_esx_storage(db, "admin")
        db.commit()
        remaining_owned = (
            db.query(DnsRecord)
            .filter(DnsRecord.description == "Created from ESX Storage endpoint.")
            .all()
        )
        assert not any(
            row.address in {"192.168.87.254", "2001:db8:87::fe"}
            for row in remaining_owned
        )
        assert any(
            "operator-owned" in error
            for error in esx_storage_context(db)["esx_storage_validation_errors"]
        )
