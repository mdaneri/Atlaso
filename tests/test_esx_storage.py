"""Test esx storage behavior."""

import importlib.machinery
import importlib.util
import json
import subprocess
from pathlib import Path, PurePosixPath

from atlaso.app.models import EsxNfsShare, EsxStorageSettings, EsxStorageVolume
from atlaso.app.services.esx_storage import (
    StorageInterface,
    desired_dns_records,
    firewall_rule_specs,
    format_authorization,
    normalize_disk_inventory_entry,
    powercli_connection_command,
    render_manifest,
    share_paths_overlap,
    validate_mounted_volume_path,
)


HELPER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "appliance" / "atlaso-helper"


def load_helper_module():
    """Return helper module."""
    loader = importlib.machinery.SourceFileLoader("atlaso_esx_storage_helper", str(HELPER_PATH))
    spec = importlib.util.spec_from_loader("atlaso_esx_storage_helper", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def state(*, families: str = "ipv4\nipv6", ipv4_clients: str = "192.168.87.11/32", ipv6_clients: str = "2001:db8:87::11/128"):
    """Return state."""
    settings = EsxStorageSettings(enabled=True, hostname="nfs.atlaso.internal")
    settings.id = 1
    volume = EsxStorageVolume(
        name="esx-data",
        source_type="blank_disk",
        stable_device_id="/dev/disk/by-id/wwn-0x1234",
        capacity_bytes=10 * 1024**3,
        mount_path="/mnt/atlaso-esx-storage/esx-data",
    )
    volume.id = 1
    share = EsxNfsShare(
        datastore_name="esx-datastore",
        volume_id=1,
        relative_path="datastores/esx",
        preferred_nfs_version="4.1",
        interface_name="storage.87",
        address_families=families,
        ipv4_clients=ipv4_clients,
        ipv6_clients=ipv6_clients,
        enabled=True,
    )
    share.id = 1
    interfaces = {
        "storage.87": StorageInterface(
            "storage.87",
            ("192.168.87.254/24",),
            ("2001:db8:87::fe/64",),
        )
    }
    return settings, [volume], [share], interfaces


def render(**kwargs):
    """Render operation.

    Returns:
        The render result.
    """
    settings, volumes, shares, interfaces = state(**kwargs)
    return render_manifest(settings, volumes, shares, interfaces, dns_enabled=True, dns_naming_mode="ip")


def test_dual_stack_share_renders_equal_family_endpoints_and_commands():
    """Verify that dual stack share renders equal family endpoints and commands."""
    manifest = render()
    share = manifest["shares"][0]

    assert manifest["validation"]["errors"] == []
    assert share["listeners"] == {"ipv4": ["192.168.87.254"], "ipv6": ["2001:db8:87::fe"]}
    assert share["target_hostnames"]["ipv4"] == ["nfs-192-168-87-254.atlaso.internal"]
    assert share["target_hostnames"]["ipv6"] == ["nfs-2001-db8-87-0-0-0-0-fe.atlaso.internal"]
    assert "--hosts=nfs-192-168-87-254.atlaso.internal" in share["connection_commands"]["ipv4"][0]
    assert "--hosts=nfs-2001-db8-87-0-0-0-0-fe.atlaso.internal" in share["connection_commands"]["ipv6"][0]
    assert share["powercli_commands"]["ipv4"] == [
        "New-Datastore -Nfs -VMHost $vmHost -Name 'esx-datastore' "
        "-NfsHost 'nfs-192-168-87-254.atlaso.internal' -Path '/esx-datastore' "
        "-FileSystemVersion 'NFS41'"
    ]
    assert share["powercli_commands"]["ipv6"] == [
        "New-Datastore -Nfs -VMHost $vmHost -Name 'esx-datastore' "
        "-NfsHost 'nfs-2001-db8-87-0-0-0-0-fe.atlaso.internal' -Path '/esx-datastore' "
        "-FileSystemVersion 'NFS41'"
    ]


def test_powercli_command_escapes_single_quoted_values():
    """Verify that powercli command escapes single quoted values."""
    command = powercli_connection_command(
        version="3",
        hostname="nfs.example.test",
        remote_path="/srv/atlaso/esx-storage/team's-data",
        datastore_name="team's-data",
    )

    assert "-Name 'team''s-data'" in command
    assert "-Path '/srv/atlaso/esx-storage/team''s-data'" in command
    assert "-FileSystemVersion 'NFS'" in command


def test_ipv4_only_and_ipv6_only_do_not_create_implicit_fallback():
    """Verify that ipv4 only and ipv6 only do not create implicit fallback."""
    ipv4 = render(families="ipv4")
    ipv6 = render(families="ipv6")

    assert ipv4["shares"][0]["listeners"]["ipv6"] == []
    assert ipv4["shares"][0]["connection_commands"]["ipv6"] == []
    assert ipv4["shares"][0]["powercli_commands"]["ipv6"] == []
    assert ipv6["shares"][0]["listeners"]["ipv4"] == []
    assert ipv6["shares"][0]["connection_commands"]["ipv4"] == []
    assert ipv6["shares"][0]["powercli_commands"]["ipv4"] == []


def test_mixed_family_client_allowlist_is_rejected():
    """Verify that mixed family client allowlist is rejected."""
    manifest = render(ipv4_clients="2001:db8::10/128")
    assert any("does not match the enabled IPV4 family" in message for message in manifest["validation"]["errors"])


def test_empty_client_lists_explicitly_allow_any_client_per_enabled_family():
    """Verify that empty client lists explicitly allow any client per enabled family."""
    manifest = render(ipv4_clients="", ipv6_clients="")
    share = manifest["shares"][0]

    assert manifest["validation"]["errors"] == []
    assert share["clients"] == {"ipv4": ["0.0.0.0/0"], "ipv6": ["::/0"]}
    assert {rule["source_expression"] for rule in firewall_rule_specs(manifest)} == {
        "ip saddr 0.0.0.0/0",
        "ip6 saddr ::/0",
    }


def test_dns_records_include_canonical_alias_and_both_address_families():
    """Verify that dns records include canonical alias and both address families."""
    records = desired_dns_records(render())
    assert records[:2] == [{
        "hostname": "nfs.atlaso.internal",
        "record_type": "A",
        "address": "192.168.87.254",
    }, {
        "hostname": "nfs.atlaso.internal",
        "record_type": "AAAA",
        "address": "2001:db8:87::fe",
    }]
    assert {record["record_type"] for record in records} == {"A", "AAAA"}


def test_firewall_rules_are_family_specific_and_match_preferred_protocol():
    """Verify that firewall rules are family specific and match preferred protocol."""
    manifest = render()
    rules = firewall_rule_specs(manifest)
    assert {rule["source_expression"] for rule in rules} == {
        "ip saddr 192.168.87.11/32",
        "ip6 saddr 2001:db8:87::11/128",
    }
    assert {rule["ports"] for rule in rules} == {"2049"}

    manifest["shares"][0]["preferred_nfs_version"] = "3"
    assert {rule["ports"] for rule in firewall_rule_specs(manifest)} == {"111,20048,2049"}


def test_blank_disk_inventory_rejects_every_destructive_risk_and_claim():
    """Verify that blank disk inventory rejects every destructive risk and claim."""
    eligible = normalize_disk_inventory_entry(
        {
            "stable_device_id": "/dev/disk/by-id/wwn-0x1234",
            "device_path": "/dev/sdb",
            "type": "disk",
            "size_bytes": 1024,
        }
    )
    rejected = normalize_disk_inventory_entry(
        {
            "stable_device_id": "/dev/disk/by-id/wwn-0x5678",
            "device_path": "/dev/sda",
            "type": "disk",
            "partitions": ["/dev/sda1"],
            "filesystem_type": "ext4",
            "mount_path": "/",
            "holders": ["dm-0"],
            "os_related": True,
        },
        claimed_ids={"/dev/disk/by-id/wwn-0x5678"},
    )

    assert eligible["eligible"] is True
    assert rejected["eligible"] is False
    assert "operating-system disk" in rejected["eligibility_reason"]
    assert "already claimed" in rejected["eligibility_reason"]


def test_mounted_ext4_inventory_rejects_vcf_backup_and_depot_mounts():
    """Verify that mounted ext4 inventory rejects vcf backup and depot mounts.

    Raises:
        AssertionError: If an expected invariant is not satisfied.
    """
    for mount_path, owner in [
        ("/mnt/atlaso-vcf-backups", "VCF Backups"),
        ("/mnt/atlaso-vcf-offline-depot", "VCF Offline Depot / VCFDT"),
        ("/mnt/atlaso-vcf-offline-depot/PROD", "VCF Offline Depot / VCFDT"),
    ]:
        candidate = normalize_disk_inventory_entry(
            {
                "candidate_type": "mounted_ext4",
                "filesystem_type": "ext4",
                "filesystem_uuid": f"uuid-{owner}",
                "mount_path": mount_path,
            }
        )

        assert candidate["eligible"] is False
        assert f"reserved for {owner}" in candidate["eligibility_reason"]

        try:
            validate_mounted_volume_path(mount_path)
        except ValueError as exc:
            assert owner in str(exc)
        else:
            raise AssertionError(f"reserved mount {mount_path} was accepted")


def test_desired_state_rejects_existing_volume_on_vcf_managed_mount():
    """Verify that desired state rejects existing volume on vcf managed mount."""
    settings, volumes, shares, interfaces = state()
    volumes[0].source_type = "mounted_ext4"
    volumes[0].stable_device_id = ""
    volumes[0].mount_path = "/mnt/atlaso-vcf-backups"

    manifest = render_manifest(settings, volumes, shares, interfaces, dns_enabled=True)

    assert any("reserved for VCF Backups" in error for error in manifest["validation"]["errors"])


def test_format_authorization_is_job_manifest_and_device_bound():
    """Verify that format authorization is job manifest and device bound."""
    manifest = render()
    authorization = format_authorization(
        job_id="job-123",
        manifest=manifest,
        volume=manifest["volumes"][0],
        confirmation="FORMAT esx-data",
    )
    assert authorization["job_id"] == "job-123"
    assert authorization["stable_device_id"] == "/dev/disk/by-id/wwn-0x1234"
    assert len(authorization["manifest_sha256"]) == 64


def test_export_paths_reject_root_children_and_siblings_remain_valid():
    """Verify that export paths reject root children and siblings remain valid."""
    assert share_paths_overlap("datastores", "datastores/esx") is True
    assert share_paths_overlap("datastores/esx-a", "datastores/esx-b") is False


def test_helper_requires_job_scoped_format_authorization_for_apply():
    """Verify that helper requires job scoped format authorization for apply."""
    helper = load_helper_module()
    manifest = render()
    assert helper._esx_storage_manifest_errors(manifest, require_authorization=False) == []
    assert helper._esx_storage_manifest_errors(manifest, require_authorization=True) == [
        "volume esx-data is missing job-scoped format authorization"
    ]

    manifest["format_authorizations"] = [
        format_authorization(
            job_id="job-123",
            manifest=manifest,
            volume=manifest["volumes"][0],
            confirmation="FORMAT esx-data",
        )
    ]
    assert helper._esx_storage_manifest_errors(manifest, require_authorization=True) == []


def test_helper_rejects_existing_volume_on_vcf_managed_mount():
    """Verify that helper rejects existing volume on vcf managed mount."""
    helper = load_helper_module()
    manifest = render()
    manifest["volumes"][0].update(
        {
            "source_type": "mounted_ext4",
            "stable_device_id": "",
            "mount_path": "/mnt/atlaso-vcf-offline-depot",
            "requires_format": False,
        }
    )

    assert "existing volume esx-data mount path is reserved for VCF Offline Depot / VCFDT" in helper._esx_storage_manifest_errors(manifest)


def test_helper_blank_disk_revalidation_rejects_partition_mount_lvm_raid_and_os_relationship():
    """Verify that helper blank disk revalidation rejects partition mount lvm raid and os relationship."""
    helper = load_helper_module()
    errors = helper._esx_storage_blank_disk_errors(
        {
            "type": "disk",
            "stable_device_id": "/dev/disk/by-id/wwn-test",
            "partitions": ["/dev/sdb1"],
            "filesystem_type": "ext4",
            "mount_path": "/mnt/data",
            "swap": True,
            "lvm": True,
            "raid": True,
            "holders": ["dm-0"],
            "os_related": True,
            "read_only": False,
        }
    )
    assert errors == [
        "has partitions",
        "has a filesystem",
        "is mounted",
        "is swap",
        "belongs to LVM",
        "belongs to RAID",
        "has holders",
        "is related to the operating-system disk",
    ]


def test_helper_inventory_prefers_uuid_mount_and_keeps_all_mountpoints(monkeypatch):
    """Verify that helper inventory prefers uuid mount and keeps all mountpoints."""
    helper = load_helper_module()
    lsblk_payload = {
        "blockdevices": [{
            "name": "sdd",
            "kname": "sdd",
            "path": "/dev/sdd",
            "type": "disk",
            "size": 20 * 1024**3,
            "model": "VMware Virtual S",
            "fstype": "ext4",
            "uuid": "3f832583-beec-4be7-969c-92519ea77273",
            "label": "lf-ad26e4d9384f",
            "mountpoints": [
                "/srv/atlaso/esx-storage/vmware-nfs3",
                "/mnt/atlaso-esx-storage/vmware-esx-data",
            ],
        }]
    }
    monkeypatch.setattr(helper, "_command_path", lambda command: f"/usr/bin/{command}")
    monkeypatch.setattr(
        helper,
        "_run",
        lambda command: subprocess.CompletedProcess(command, 0, stdout=json.dumps(lsblk_payload), stderr=""),
    )
    monkeypatch.setattr(
        helper,
        "_esx_storage_by_id_map",
        lambda: {"/dev/sdd": "/dev/disk/by-id/atlaso-path-pci-0000_03_00_0-scsi-0_0_3_0"},
    )
    monkeypatch.setattr(helper, "_esx_storage_os_devices", lambda: set())

    disk = helper._esx_storage_inventory()[0]

    assert disk["mount_path"] == "/mnt/atlaso-esx-storage/vmware-esx-data"
    assert disk["mount_paths"] == [
        "/srv/atlaso/esx-storage/vmware-nfs3",
        "/mnt/atlaso-esx-storage/vmware-esx-data",
    ]


def test_helper_initialized_disk_retry_accepts_expected_mount_among_bind_mounts():
    """Verify that helper initialized disk retry accepts expected mount among bind mounts."""
    helper = load_helper_module()
    entry = {
        "filesystem_type": "ext4",
        "filesystem_label": "lf-ad26e4d9384f",
        "filesystem_uuid": "3f832583-beec-4be7-969c-92519ea77273",
        "partitions": [],
        "mount_paths": [
            "/srv/atlaso/esx-storage/vmware-nfs3",
            "/mnt/atlaso-esx-storage/vmware-esx-data",
        ],
        "holders": [],
        "os_related": False,
    }

    assert helper._esx_storage_disk_is_initialized(
        entry,
        label="lf-ad26e4d9384f",
        mount_path=PurePosixPath("/mnt/atlaso-esx-storage/vmware-esx-data"),
    )
    assert not helper._esx_storage_disk_is_initialized(
        entry,
        label="lf-wrong-label",
        mount_path=PurePosixPath("/mnt/atlaso-esx-storage/vmware-esx-data"),
    )


def api_token(client, scopes: list[str]) -> str:
    """Return api token."""
    response = client.post(
        "/api/v1/auth/login?username=admin&password=atlaso-admin",
        json={"name": "esx storage test", "scopes": scopes},
    )
    assert response.status_code == 200, response.text
    return response.json()["raw_token"]


def test_esx_storage_page_and_dual_stack_api_contract(client):
    """Verify that esx storage page and dual stack api contract."""
    page = client.get("/login")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    assert client.post(
        "/login",
        data={"username": "admin", "password": "atlaso-admin", "csrf": csrf},
        follow_redirects=False,
    ).status_code == 303
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
    assert 'window.history.replaceState(null, "", target)' in client.get("/static/app.js").text
    assert '`${window.location.pathname}${window.location.search}#${targetId}`' in client.get("/static/app.js").text
    apply_refresh_js = client.get("/static/app.js").text.split("function refreshCurrentWorkflowAfterApplianceApply", 1)[1].split(
        "async function submitApplianceApplyForm", 1
    )[0]
    assert 'new Set(["/esx-storage", "/vcf-offline-depot"])' in apply_refresh_js
    assert "refreshableWorkflows.has(window.location.pathname)" in apply_refresh_js
    assert 'label: "Edit datastore"' in client.get("/static/app.js").text
    assert "rowDblClick: (_event, row) => editRow(row)" in client.get("/static/app.js").text
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

    token = api_token(client, ["read:esx-storage", "write:esx-storage", "read:interfaces"])
    headers = {"Authorization": f"Bearer {token}"}
    interfaces = client.get("/api/v1/interfaces/physical", headers=headers).json()
    interface = next(row for row in interfaces if row["name"] == "storage87")
    for reserved_path in ["/mnt/atlaso-vcf-backups", "/mnt/atlaso-vcf-offline-depot"]:
        rejected_volume = client.post(
            "/api/v1/esx-storage/volumes",
            headers=headers,
            json={"name": f"reserved-{reserved_path.rsplit('/', 1)[-1]}", "source_type": "mounted_ext4", "mount_path": reserved_path},
        )
        assert rejected_volume.status_code == 422
        assert "reserved for" in rejected_volume.json()["detail"]
    volume_response = client.post(
        "/api/v1/esx-storage/volumes",
        headers=headers,
        json={"name": "existing-ext4", "source_type": "mounted_ext4", "mount_path": "/mnt/existing-ext4"},
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
    edited = client.get(f"/api/v1/esx-storage/shares", headers=headers).json()[0]
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
    assert client.get("/api/v1/esx-storage/shares", headers=headers).json()[0]["enabled"] is False
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
        owned = db.query(DnsRecord).filter(DnsRecord.description == "Created from ESX Storage endpoint.").all()
        assert {(row.hostname, row.record_type, row.address) for row in owned} == {
            ("nfs.atlaso.internal", "A", "192.168.87.254"),
            ("nfs.atlaso.internal", "AAAA", "2001:db8:87::fe"),
            ("nfs-192-168-87-254.atlaso.internal", "A", "192.168.87.254"),
            ("nfs-2001-db8-87-0-0-0-0-fe.atlaso.internal", "AAAA", "2001:db8:87::fe"),
        }
        storage = db.query(PhysicalInterface).filter(PhysicalInterface.name == "storage87").one()
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
        remaining_owned = db.query(DnsRecord).filter(DnsRecord.description == "Created from ESX Storage endpoint.").all()
        assert not any(row.address in {"192.168.87.254", "2001:db8:87::fe"} for row in remaining_owned)
        assert any("operator-owned" in error for error in esx_storage_context(db)["esx_storage_validation_errors"])


def test_esx_storage_write_scope_is_enforced(client):
    """Verify that esx storage write scope is enforced."""
    token = api_token(client, ["read:esx-storage"])
    response = client.post(
        "/api/v1/esx-storage/volumes",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "forbidden", "source_type": "mounted_ext4", "mount_path": "/mnt/forbidden"},
    )
    assert response.status_code == 403
