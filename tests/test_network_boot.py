import hashlib
import io
import json
import re
import threading
import time
import zipfile
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from email.message import Message
from pathlib import Path
from subprocess import CompletedProcess
from types import SimpleNamespace
from urllib.error import HTTPError, URLError
from urllib.request import Request

import pytest
import pycdlib
from fastapi import HTTPException
from sqlalchemy import select
from starlette.requests import Request as StarletteRequest

import atlaso.app.audit as audit_service
import atlaso.app.api.network_boot as network_boot_api
import atlaso.app.services.network_boot as network_boot
from atlaso.app.api.network_boot import (
    _allowlisted_media_file,
    _installed_media_directory,
    _MEDIA_ENVIRONMENT_ROOTS,
)
from atlaso.app.models import (
    AuditEvent,
    EsxiPxeHost,
    Job,
    JobStatus,
    NetworkBootDiscoveredHost,
    NetworkBootEnvironment,
    NetworkBootHostBootOverride,
    NetworkBootMedia,
    NetworkBootInventoryCommand,
    NetworkBootInventoryReport,
    NetworkBootInventorySession,
    Setting,
    utcnow,
)
from atlaso.app.services.network_boot import (
    _extract_shredos_kernel,
    _extract_zip_allowlist,
    _BoundedHttpsRedirectHandler,
    _release_descriptor,
    available_network_boot_versions,
    BoundedHttpsDownloader,
    checksum_for_filename,
    NetworkBootMediaSyncCancelled,
    NETWORK_BOOT_MAX_DISKS,
    NETWORK_BOOT_MAX_DIMMS,
    NETWORK_BOOT_MAX_INTERFACES,
    NETWORK_BOOT_MAX_PCI_DEVICES,
    NETWORK_BOOT_MAX_STORAGE_CONTROLLERS,
    NETWORK_BOOT_MAX_USB_DEVICES,
    NETWORK_BOOT_REPORT_MAX_BYTES,
    NETWORK_BOOT_REPORTS_PER_HOST,
    ensure_environment_rows,
    issue_inventory_session,
    inventory_session_for_token,
    latest_live_session,
    network_boot_upload_path,
    normalize_inventory_report,
    poll_inventory_command,
    queue_reboot_command,
    claim_host_boot_override,
    record_verified_media,
    register_bundled_inventory_media,
    render_network_boot_menu,
    request_host_boot_override,
    store_inventory_report,
    sync_network_boot_media,
    touch_inventory_heartbeat,
    acknowledge_inventory_command,
    send_wake_on_lan,
    verify_signed_checksum,
    WakeOnLanDeliveryError,
    wake_on_lan_broadcast_targets,
    wake_on_lan_packet,
)
from atlaso.app.services.esxi_pxe import (
    esxi_pxe_boot_settings,
    esxi_pxe_default_host_settings,
    esxi_pxe_host_artifacts,
)


@pytest.fixture()
def db_session(client):
    from atlaso.app.database import SessionLocal

    with SessionLocal() as db:
        yield db


def create_api_token(client, scopes):
    response = client.post(
        "/api/v1/auth/login?username=admin&password=atlaso-admin",
        json={"name": "network boot tests", "scopes": scopes},
    )
    assert response.status_code == 200, response.text
    return response.json()["raw_token"]


def use_test_shredos_extractor(monkeypatch):
    def extract(archive, destination):
        target = destination / "shredos"
        target.write_bytes(archive.read_bytes())
        target.chmod(0o644)
        return ["shredos"]

    monkeypatch.setattr(network_boot, "_extract_shredos_kernel", extract)


def login_session(client):
    page = client.get("/login")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/login",
        data={"username": "admin", "password": "atlaso-admin", "csrf": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 303
    page = client.get("/network-boot")
    assert page.status_code == 200
    return page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]


def set_applied_pxe_runtime(
    db_session,
    *,
    boot=None,
    artifacts=None,
    environments=None,
):
    setting = db_session.execute(
        select(Setting).where(Setting.key == "appliance_apply.baselines.v1")
    ).scalar_one_or_none()
    baselines = json.loads(setting.value) if setting else {}
    baselines["esxi_pxe"] = {
        "config_preview": json.dumps(
            {
                "kind": "atlaso-esxi-pxe",
                "schema_version": 1,
                "boot": boot or {},
                "artifacts": artifacts or [],
                "network_boot": {
                    "schema_version": 1,
                    "environments": environments or [],
                },
            }
        )
    }
    if setting is None:
        setting = Setting(key="appliance_apply.baselines.v1", value="")
    setting.value = json.dumps(baselines)
    db_session.add(setting)
    db_session.commit()


def test_network_boot_catalog_identifies_authoritative_download_sources(db_session):
    from atlaso.app.services.network_boot import catalog_rows

    sources = {
        row["key"]: (row["source_label"], row["release_page"])
        for row in catalog_rows(db_session)
    }

    assert sources == {
        "inventory": (
            "Atlaso Inventory Linux releases",
            "https://github.com/mdaneri/Atlaso/releases?q=inventory-linux-v&expanded=true",
        ),
        "memtest86plus": ("Memtest86+ official site", "https://www.memtest.org/"),
        "shredos": (
            "ShredOS GitHub releases",
            "https://github.com/PartialVolume/shredos.x86_64/releases/latest",
        ),
        "gparted": (
            "GParted official downloads",
            "https://gparted.org/download.php",
        ),
        "clonezilla": (
            "Clonezilla official downloads",
            "https://clonezilla.org/downloads.php",
        ),
    }


def test_network_boot_catalog_distinguishes_installed_media_from_active_readiness(
    db_session,
):
    from atlaso.app.services.network_boot import catalog_rows

    record_verified_media(
        db_session,
        environment_key="memtest86plus",
        version="8.10",
        source_url="https://www.memtest.org/download/v8.10/example.zip",
        artifact_sha256="a" * 64,
        installed_path="/var/lib/atlaso/pxe/media/memtest86plus/8.10",
        manifest={"schema_version": 1},
    )
    row = next(
        item for item in catalog_rows(db_session)
        if item["key"] == "memtest86plus"
    )

    assert row["media_ready"] is True
    assert row["ready"] is False


def inventory_report(
    *,
    dmi_uuid="4c4c4544-004b-4d10-8052-cac04f4c5132",
    boot_mac="52:54:00:12:34:56",
):
    return {
        "schema_version": 1,
        "boot_interface": "eth0",
        "boot_mac": boot_mac,
        "assigned_addresses": ["192.0.2.10/24"],
        "firmware_mode": "uefi",
        "system": {
            "dmi_uuid": dmi_uuid,
            "manufacturer": "Atlaso Test",
            "product_name": "Inventory VM",
            "serial_number": "SERIAL-1",
            "bios_vendor": "Example Firmware",
            "bios_version": "1.0",
            "bios_date": "2026-07-29",
        },
        "cpu": {
            "architecture": "x86_64",
            "vendor": "GenuineIntel",
            "model": "Example CPU",
            "sockets": 1,
            "cores": 4,
            "threads": 8,
        },
        "memory": {"total_bytes": 8 * 1024**3},
        "disks": [
            {
                "device": "/dev/sda",
                "model": "Example Disk",
                "serial": "DISK-1",
                "wwn": "0x5000",
                "transport": "sata",
                "size_bytes": 100 * 1024**3,
                "rotational": False,
                "removable": False,
                "read_only": False,
            }
        ],
        "interfaces": [
            {
                "name": "eth0",
                "permanent_mac": boot_mac,
                "current_mac": boot_mac,
                "driver": "virtio_net",
                "link_state": "up",
                "speed_mbps": 10000,
                "addresses": ["192.0.2.10/24"],
                "boot_interface": True,
            }
        ],
    }


def inventory_report_v2():
    payload = inventory_report()
    payload["schema_version"] = 2
    payload["system"].update(
        {
            "product_version": "2.0",
            "product_sku": "SKU-42",
            "product_family": "Atlaso Lab",
            "bios_release": "1.2",
            "baseboard": {
                "manufacturer": "Board Vendor",
                "product": "Board Product",
                "version": "B1",
                "serial": "BOARD-1",
                "asset_tag": "BOARD-ASSET",
            },
            "chassis": {
                "manufacturer": "Chassis Vendor",
                "type": "Rack Mount Chassis",
                "version": "C1",
                "serial": "CHASSIS-1",
                "asset_tag": "CHASSIS-ASSET",
            },
        }
    )
    payload["cpu"].update({"cores_per_socket": 4, "threads_per_core": 2})
    payload["memory"].update(
        {
            "total_human": "8.00 GiB",
            "dimms": [
                {
                    "locator": "DIMM_A1",
                    "bank": "BANK 0",
                    "size_bytes": 8 * 1024**3,
                    "size_human": "8.00 GiB",
                    "type": "DDR5",
                    "speed_mts": 4800,
                    "manufacturer": "Memory Vendor",
                    "part_number": "MEM-8G",
                    "serial": "DIMM-1",
                }
            ],
        }
    )
    payload["interfaces"][0].update(
        {
            "pci_address": "0000:02:00.0",
            "vendor_id": "8086",
            "device_id": "10fb",
            "vendor": "Intel Corporation",
            "device": "10-Gigabit Network Connection",
        }
    )
    payload["disks"][0].update(
        {
            "size_human": "100 GiB",
            "type": "SSD",
            "flags": [],
            "controller_pci_address": "0000:03:00.0",
        }
    )
    payload["storage_controllers"] = [
        {
            "pci_address": "0000:03:00.0",
            "type": "SATA",
            "vendor_id": "8086",
            "device_id": "2922",
            "vendor": "Intel Corporation",
            "device": "SATA Controller",
            "driver": "ahci",
        }
    ]
    payload["pci_devices"] = [
        {
            "pci_address": "0000:02:00.0",
            "class_id": "020000",
            "class": "Ethernet controller",
            "vendor_id": "8086",
            "device_id": "10fb",
            "vendor": "Intel Corporation",
            "device": "10-Gigabit Network Connection",
            "subsystem_vendor_id": "8086",
            "subsystem_device_id": "0001",
            "driver": "ixgbe",
        }
    ]
    payload["usb_devices"] = [
        {
            "bus": 1,
            "device_number": 2,
            "port": "1-1",
            "vendor_id": "0781",
            "product_id": "5581",
            "manufacturer": "USB Vendor",
            "product": "Flash Drive",
            "serial": "USB-1",
            "class": "Mass storage",
            "driver": "usb-storage",
        }
    ]
    return payload


def test_network_boot_api_accepts_scoped_ui_session_and_requires_csrf(client):
    csrf = login_session(client)

    assert client.get("/api/v1/network-boot/environments").status_code == 200
    payload = {"enabled": False, "desired_version": ""}
    denied = client.patch("/api/v1/network-boot/environments/memtest86plus", json=payload)
    assert denied.status_code == 403
    assert denied.json()["detail"] == "Invalid CSRF token"

    updated = client.patch(
        "/api/v1/network-boot/environments/memtest86plus",
        json=payload,
        headers={"X-CSRF-Token": csrf},
    )
    assert updated.status_code == 200
    assert updated.json()["enabled"] is False
    persisted = {
        row["key"]: row
        for row in client.get("/api/v1/network-boot/environments").json()
    }
    assert persisted["memtest86plus"]["enabled"] is False


def test_network_boot_available_versions_endpoint_uses_read_scope(client, monkeypatch):
    login_session(client)
    expected = [
        {
            "key": "inventory",
            "available_version": "2026.05.1+8",
            "available_status": "current",
            "available_checked_at": "2026-08-04T01:00:00+00:00",
        }
    ]
    monkeypatch.setattr(network_boot_api, "available_network_boot_versions", lambda: expected)

    response = client.get("/api/v1/network-boot/environments/available-versions")

    assert response.status_code == 200
    assert response.json() == expected


def test_network_boot_mutation_endpoints_persist_jobs_commands_profiles_and_audits(client):
    raw_token = create_api_token(client, ["read:pxe", "write:pxe"])
    api_headers = {"Authorization": f"Bearer {raw_token}"}

    sync = client.post(
        "/api/v1/network-boot/environments/gparted/sync",
        headers=api_headers,
    )
    assert sync.status_code == 202, sync.text

    inventory_session = client.post("/pxe/inventory/sessions").json()
    report = client.post(
        "/pxe/inventory/report",
        json=inventory_report(),
        headers={"Authorization": f"Bearer {inventory_session['access_token']}"},
    )
    assert report.status_code == 201, report.text
    host_id = report.json()["host_id"]

    reboot = client.post(
        f"/api/v1/network-boot/hosts/{host_id}/reboot",
        headers=api_headers,
    )
    assert reboot.status_code == 202, reboot.text
    command_id = reboot.json()["id"]
    inventory_headers = {
        "Authorization": f"Bearer {inventory_session['access_token']}"
    }
    delivered = client.get("/pxe/inventory/commands", headers=inventory_headers)
    assert delivered.status_code == 200
    assert delivered.json()["command"]["id"] == command_id
    acknowledged = client.post(
        f"/pxe/inventory/commands/{command_id}/acknowledge",
        headers=inventory_headers,
    )
    assert acknowledged.status_code == 200
    assert acknowledged.json()["status"] == "acknowledged"

    overlong_promotion = client.post(
        f"/api/v1/network-boot/hosts/{host_id}/promote",
        headers=api_headers,
        json={
            "hostname": "h" * 121,
            "mac_address": "52:54:00:12:34:56",
            "ip_address": "192.0.2.10",
            "kickstart_id": "",
            "installer_iso_path": "",
            "variables": {},
            "enabled": False,
        },
    )
    assert overlong_promotion.status_code == 422
    assert "Promotion hostname is invalid" in overlong_promotion.json()["detail"]

    promotion = client.post(
        f"/api/v1/network-boot/hosts/{host_id}/promote",
        headers=api_headers,
        json={
            "hostname": "esxi-inventory-01",
            "mac_address": "52:54:00:12:34:56",
            "ip_address": "192.0.2.10",
            "kickstart_id": "",
            "installer_iso_path": "",
            "variables": {},
            "enabled": False,
        },
    )
    assert promotion.status_code == 201, promotion.text

    discovered_hosts = client.get("/api/v1/network-boot/hosts", headers=api_headers)
    assert discovered_hosts.status_code == 200, discovered_hosts.text
    assigned = next(row for row in discovered_hosts.json() if row["id"] == host_id)
    assert assigned["assigned_to_esxi"] is True
    assert assigned["esxi_host_id"] == promotion.json()["id"]
    assert assigned["esxi_hostname"] == "esxi-inventory-01"
    assert assigned["esxi_ip_address"] == "192.0.2.10"
    assert assigned["esxi_assignments"] == [
        {
            "id": promotion.json()["id"],
            "hostname": "esxi-inventory-01",
            "ip_address": "192.0.2.10",
            "mac_address": "52:54:00:12:34:56",
            "enabled": False,
        }
    ]

    from atlaso.app.database import SessionLocal

    with SessionLocal() as db:
        assert db.get(Job, sync.json()["job_id"]) is not None
        assert db.get(NetworkBootInventoryCommand, command_id) is not None
        promoted_host = db.get(EsxiPxeHost, promotion.json()["id"])
        assert promoted_host is not None
        assert promoted_host.kickstart_id is None
        actions = set(
            db.execute(
                select(AuditEvent.action).where(
                    AuditEvent.action.in_(
                        {
                            "queue_pxe_media_sync",
                            "queue_inventory_reboot",
                            "deliver_inventory_command",
                            "acknowledge_inventory_command",
                            "promote_inventory_host_to_esxi",
                        }
                    )
                )
            ).scalars()
        )
    assert actions == {
        "queue_pxe_media_sync",
        "queue_inventory_reboot",
        "deliver_inventory_command",
        "acknowledge_inventory_command",
        "promote_inventory_host_to_esxi",
    }


def test_api_schedules_and_claims_esxi_inventory_boot_override(client):
    raw_token = create_api_token(client, ["read:pxe", "write:pxe"])
    from atlaso.app.database import SessionLocal

    with SessionLocal() as db:
        states = {row.key: row for row in ensure_environment_rows(db)}
        inventory = record_verified_media(
            db,
            environment_key="inventory",
            version="2026.05.1",
            source_url="https://example.test/atlaso-inventory-linux.zip",
            artifact_sha256="a" * 64,
            installed_path="/var/lib/atlaso/pxe/media/inventory/2026.05.1",
            manifest={"boot": {"kernel": "/bzImage", "initrd": "/rootfs.cpio.gz"}},
        )
        states["inventory"].enabled = True
        states["inventory"].active_version = inventory.version
        host = EsxiPxeHost(
            hostname="esxi-api-utility",
            mac_address="52:54:00:ab:cd:ef",
            enabled=True,
        )
        db.add(host)
        db.commit()
        host_id = host.id

    response = client.post(
        f"/api/v1/network-boot/esxi-hosts/{host_id}/boot-inventory-once",
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert response.status_code == 202, response.text
    assert response.json()["environment_key"] == "inventory"

    menu = client.get(
        "/pxe/boot.ipxe?mac=52:54:00:ab:cd:ef&firmware=efi",
    )
    assert menu.status_code == 200
    assert "choose --timeout 10000 --default inventory" in menu.text

    with SessionLocal() as db:
        override = db.get(NetworkBootHostBootOverride, host_id)
        assert override is not None
        assert override.claimed_at is not None
        assert db.execute(
            select(AuditEvent).where(
                AuditEvent.action == "request_esxi_host_inventory_boot",
                AuditEvent.resource_id == str(host_id),
            )
        ).scalar_one_or_none() is not None


def test_wake_on_lan_packet_and_distinct_broadcast_delivery():
    packet = wake_on_lan_packet("52:54:00:12:34:56")
    assert packet == (b"\xff" * 6) + (bytes.fromhex("525400123456") * 16)

    calls = []

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def setsockopt(self, *args):
            calls.append(("setsockopt", args))

        def sendto(self, payload, target):
            calls.append(("sendto", payload, target))

    targets = send_wake_on_lan(
        "52:54:00:12:34:56",
        ["192.0.2.255", "198.51.100.255", "192.0.2.255"],
        socket_factory=lambda *_args: FakeSocket(),
    )

    assert targets == ["192.0.2.255", "198.51.100.255"]
    assert [entry[2] for entry in calls if entry[0] == "sendto"] == [
        ("192.0.2.255", 9),
        ("198.51.100.255", 9),
    ]
    assert all(entry[1] == packet for entry in calls if entry[0] == "sendto")


def test_wake_on_lan_preserves_targets_sent_before_udp_failure():
    calls = []

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def setsockopt(self, *_args):
            return None

        def sendto(self, _payload, target):
            calls.append(target)
            if len(calls) == 2:
                raise OSError("test second broadcast failed")

    with pytest.raises(WakeOnLanDeliveryError) as captured:
        send_wake_on_lan(
            "52:54:00:12:34:56",
            ["192.0.2.255", "198.51.100.255"],
            socket_factory=lambda *_args: FakeSocket(),
        )

    assert captured.value.sent_targets == ["192.0.2.255"]
    assert captured.value.failed_target == "198.51.100.255"
    assert calls == [("192.0.2.255", 9), ("198.51.100.255", 9)]


def test_wake_on_lan_preserves_retryable_error_before_any_delivery():
    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def setsockopt(self, *_args):
            return None

        def sendto(self, *_args):
            raise OSError("test first broadcast failed")

    with pytest.raises(OSError, match="test first broadcast failed") as captured:
        send_wake_on_lan(
            "52:54:00:12:34:56",
            ["192.0.2.255"],
            socket_factory=lambda *_args: FakeSocket(),
        )
    assert not isinstance(captured.value, WakeOnLanDeliveryError)


def test_wake_broadcast_targets_use_applied_ipv4_network_boot_scopes(
    db_session,
):
    set_applied_pxe_runtime(
        db_session,
        boot={
            "dhcp_scopes": [
                {"address_family": "ipv4", "site_address": "192.0.2.1", "prefix_length": 24},
                {"address_family": "ipv4", "site_address": "192.0.2.9", "prefix_length": 24},
                {"address_family": "ipv4", "site_address": "198.51.100.1", "prefix_length": 25},
                {"address_family": "ipv6", "site_address": "2001:db8::1", "prefix_length": 64},
                {"address_family": "ipv4", "site_address": "invalid", "prefix_length": 24},
            ]
        },
    )
    assert wake_on_lan_broadcast_targets(db_session) == [
        "192.0.2.255",
        "198.51.100.127",
    ]


@pytest.mark.parametrize(
    ("mac_address", "targets", "message"),
    [
        ("not-a-mac", ["192.0.2.255"], "valid host MAC"),
        ("00:00:00:00:00:00", ["192.0.2.255"], "valid host MAC"),
        ("52:54:00:12:34:56", [], "Configure an IPv4"),
        ("52:54:00:12:34:56", ["2001:db8::ffff"], "IPv4"),
    ],
)
def test_wake_on_lan_rejects_invalid_inputs(mac_address, targets, message):
    with pytest.raises(ValueError, match=message):
        send_wake_on_lan(mac_address, targets)


def test_wake_endpoints_send_server_owned_macs_and_audit(client, monkeypatch):
    raw_token = create_api_token(client, ["read:pxe", "write:pxe"])
    headers = {"Authorization": f"Bearer {raw_token}"}
    inventory_session = client.post("/pxe/inventory/sessions").json()
    submitted = client.post(
        "/pxe/inventory/report",
        json=inventory_report(),
        headers={"Authorization": f"Bearer {inventory_session['access_token']}"},
    )
    assert submitted.status_code == 201, submitted.text
    discovered_id = submitted.json()["host_id"]

    from atlaso.app.database import SessionLocal

    with SessionLocal() as db:
        reference = EsxiPxeHost(
            hostname="esxi-wake-test",
            mac_address="52:54:00:aa:bb:cc",
            enabled=False,
        )
        db.add(reference)
        db.commit()
        reference_id = reference.id

    sent = []
    logged_wake_events = []
    monkeypatch.setattr(
        audit_service,
        "log_audit_event",
        lambda event: logged_wake_events.append(
            (event.success, event.detail)
        ) if event.action == "send_wake_on_lan" else None,
    )
    monkeypatch.setattr(
        network_boot_api,
        "wake_on_lan_broadcast_targets",
        lambda _db: ["192.0.2.255", "198.51.100.255"],
    )

    def capture(mac_address, targets):
        with SessionLocal() as db:
            pending = db.execute(
                select(AuditEvent)
                .where(AuditEvent.action == "send_wake_on_lan")
                .order_by(AuditEvent.id.desc())
                .limit(1)
            ).scalar_one()
            assert pending.success is False
            assert "outcome=pending" in pending.detail
            assert "broadcasts_planned=192.0.2.255,198.51.100.255" in pending.detail
        assert len(logged_wake_events) == len(sent)
        assert all("outcome=pending" not in detail for _success, detail in logged_wake_events)
        sent.append((mac_address, list(targets)))
        return list(targets)

    monkeypatch.setattr(network_boot_api, "send_wake_on_lan", capture)

    discovered = client.post(
        f"/api/v1/network-boot/hosts/{discovered_id}/wake",
        headers=headers,
    )
    reference_response = client.post(
        f"/api/v1/network-boot/esxi-hosts/{reference_id}/wake",
        headers=headers,
    )

    assert discovered.status_code == 200, discovered.text
    assert reference_response.status_code == 200, reference_response.text
    assert discovered.json()["status"] == "packet_sent"
    assert "not confirmed" in discovered.json()["message"]
    assert sent == [
        ("52:54:00:12:34:56", ["192.0.2.255", "198.51.100.255"]),
        ("52:54:00:aa:bb:cc", ["192.0.2.255", "198.51.100.255"]),
    ]
    assert logged_wake_events == [
        (True, "outcome=packet_sent; broadcasts_sent=2"),
        (True, "outcome=packet_sent; broadcasts_sent=2"),
    ]

    with SessionLocal() as db:
        events = db.execute(
            select(AuditEvent).where(AuditEvent.action == "send_wake_on_lan")
        ).scalars().all()
        assert {(event.resource_type, event.resource_id) for event in events} == {
            ("network_boot_discovered_host", str(discovered_id)),
            ("esxi_pxe_host", str(reference_id)),
        }
        assert all(event.success for event in events)


def test_wake_endpoint_returns_recoverable_conflict_and_audits_failure(
    client,
    monkeypatch,
):
    raw_token = create_api_token(client, ["write:pxe"])
    inventory_session = client.post("/pxe/inventory/sessions").json()
    submitted = client.post(
        "/pxe/inventory/report",
        json=inventory_report(),
        headers={"Authorization": f"Bearer {inventory_session['access_token']}"},
    )
    host_id = submitted.json()["host_id"]
    monkeypatch.setattr(
        network_boot_api,
        "wake_on_lan_broadcast_targets",
        lambda _db: [],
    )

    response = client.post(
        f"/api/v1/network-boot/hosts/{host_id}/wake",
        headers={"Authorization": f"Bearer {raw_token}"},
    )

    assert response.status_code == 409
    assert "Configure an IPv4" in response.json()["detail"]

    from atlaso.app.database import SessionLocal

    with SessionLocal() as db:
        event = db.execute(
            select(AuditEvent).where(
                AuditEvent.action == "send_wake_on_lan",
                AuditEvent.resource_id == str(host_id),
            )
        ).scalar_one()
        assert event.success is False


def test_wake_endpoint_reports_udp_send_failure_as_retryable_service_error(
    client,
    monkeypatch,
):
    raw_token = create_api_token(client, ["write:pxe"])
    inventory_session = client.post("/pxe/inventory/sessions").json()
    submitted = client.post(
        "/pxe/inventory/report",
        json=inventory_report(),
        headers={"Authorization": f"Bearer {inventory_session['access_token']}"},
    )
    host_id = submitted.json()["host_id"]
    logged_wake_events = []
    monkeypatch.setattr(
        audit_service,
        "log_audit_event",
        lambda event: logged_wake_events.append(
            (event.success, event.detail)
        ) if event.action == "send_wake_on_lan" else None,
    )
    monkeypatch.setattr(
        network_boot_api,
        "wake_on_lan_broadcast_targets",
        lambda _db: ["192.0.2.255"],
    )
    monkeypatch.setattr(
        network_boot_api,
        "send_wake_on_lan",
        lambda *_args: (_ for _ in ()).throw(OSError("test UDP send failed")),
    )

    response = client.post(
        f"/api/v1/network-boot/hosts/{host_id}/wake",
        headers={"Authorization": f"Bearer {raw_token}"},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "test UDP send failed"
    assert logged_wake_events == [
        (False, "outcome=packet_not_sent; broadcasts_sent=0")
    ]


def test_wake_endpoint_reports_and_audits_partial_udp_delivery(client, monkeypatch):
    raw_token = create_api_token(client, ["write:pxe"])
    inventory_session = client.post("/pxe/inventory/sessions").json()
    submitted = client.post(
        "/pxe/inventory/report",
        json=inventory_report(),
        headers={"Authorization": f"Bearer {inventory_session['access_token']}"},
    )
    host_id = submitted.json()["host_id"]
    logged_wake_events = []
    monkeypatch.setattr(
        audit_service,
        "log_audit_event",
        lambda event: logged_wake_events.append(
            (event.success, event.detail)
        ) if event.action == "send_wake_on_lan" else None,
    )
    monkeypatch.setattr(
        network_boot_api,
        "wake_on_lan_broadcast_targets",
        lambda _db: ["192.0.2.255", "198.51.100.255"],
    )
    monkeypatch.setattr(
        network_boot_api,
        "send_wake_on_lan",
        lambda *_args: (_ for _ in ()).throw(
            WakeOnLanDeliveryError(
                "198.51.100.255",
                ["192.0.2.255"],
                OSError("test second broadcast failed"),
            )
        ),
    )

    response = client.post(
        f"/api/v1/network-boot/hosts/{host_id}/wake",
        headers={"Authorization": f"Bearer {raw_token}"},
    )

    assert response.status_code == 207
    assert response.json() == {
        "status": "packet_partially_sent",
        "mac_address": "52:54:00:12:34:56",
        "broadcast_targets": ["192.0.2.255"],
        "failed_broadcast_target": "198.51.100.255",
        "message": (
            "Wake-on-LAN reached only some broadcasts before a UDP send failed. "
            "Do not retry automatically; host power-on is not confirmed."
        ),
    }
    assert logged_wake_events == [
        (False, "outcome=packet_partially_sent; broadcasts_sent=1")
    ]

    from atlaso.app.database import SessionLocal

    with SessionLocal() as db:
        event = db.execute(
            select(AuditEvent).where(
                AuditEvent.action == "send_wake_on_lan",
                AuditEvent.resource_id == str(host_id),
            )
        ).scalar_one()
        assert event.success is False
        assert "broadcasts_sent=192.0.2.255" in event.detail
        assert "failed_broadcast=198.51.100.255" in event.detail


def test_report_download_is_exact_self_contained_and_rejects_cross_host(client):
    raw_token = create_api_token(client, ["read:pxe"])
    headers = {"Authorization": f"Bearer {raw_token}"}
    first_session = client.post("/pxe/inventory/sessions").json()
    first_payload = inventory_report_v2()
    first = client.post(
        "/pxe/inventory/report",
        json=first_payload,
        headers={"Authorization": f"Bearer {first_session['access_token']}"},
    )
    assert first.status_code == 201, first.text
    first_download = client.get(
        f"/api/v1/network-boot/hosts/{first.json()['host_id']}/reports/"
        f"{first.json()['report_id']}/download",
        headers=headers,
    )
    assert first_download.status_code == 200, first_download.text

    newer_payload = inventory_report_v2()
    newer_payload["system"]["manufacturer"] = "Newer Vendor"
    newer_payload["cpu"]["model"] = "Newer CPU"
    newer_payload["disks"].append(dict(newer_payload["disks"][0], device="/dev/sdb"))
    second_session = client.post("/pxe/inventory/sessions").json()
    newer = client.post(
        "/pxe/inventory/report",
        json=newer_payload,
        headers={"Authorization": f"Bearer {second_session['access_token']}"},
    )
    assert newer.status_code == 201, newer.text
    assert newer.json()["host_id"] == first.json()["host_id"]

    download = client.get(
        f"/api/v1/network-boot/hosts/{first.json()['host_id']}/reports/"
        f"{first.json()['report_id']}/download",
        headers=headers,
    )
    assert download.status_code == 200, download.text
    assert download.content == first_download.content
    exported = download.json()
    assert exported["host"] == {
        "id": first.json()["host_id"],
        "identity_key": (
            "uuid:4c4c4544-004b-4d10-8052-cac04f4c5132:"
            "6aa1a7a23e5008c9"
        ),
        "dmi_uuid": "4c4c4544-004b-4d10-8052-cac04f4c5132",
        "boot_mac": "52:54:00:12:34:56",
        "macs": ["52:54:00:12:34:56"],
        "manufacturer": "Atlaso Test",
        "product_name": "Inventory VM",
        "serial_number": "SERIAL-1",
        "cpu_model": "Example CPU",
        "total_memory_bytes": 8 * 1024**3,
        "disk_count": 1,
        "interface_count": 1,
    }
    assert download.headers["content-type"] == "application/json"
    assert download.headers["cache-control"] == "no-store"
    assert download.headers["content-disposition"] == (
        f'attachment; filename="atlaso-inventory-host-{first.json()["host_id"]}'
        f'-report-{first.json()["report_id"]}.json"'
    )

    other_payload = inventory_report_v2()
    other_payload["system"]["dmi_uuid"] = "4c4c4544-004b-4d10-8052-cac04f4c5199"
    other_payload["boot_mac"] = "52:54:00:12:34:99"
    other_payload["interfaces"][0]["permanent_mac"] = "52:54:00:12:34:99"
    other_payload["interfaces"][0]["current_mac"] = "52:54:00:12:34:99"
    other_session = client.post("/pxe/inventory/sessions").json()
    other = client.post(
        "/pxe/inventory/report",
        json=other_payload,
        headers={"Authorization": f"Bearer {other_session['access_token']}"},
    )
    assert other.status_code == 201, other.text
    cross_host = client.get(
        f"/api/v1/network-boot/hosts/{other.json()['host_id']}/reports/"
        f"{first.json()['report_id']}/download",
        headers=headers,
    )
    assert cross_host.status_code == 404


def test_remove_discovered_host_cleans_inventory_and_preserves_esxi_state(client):
    raw_token = create_api_token(client, ["write:pxe"])
    headers = {"Authorization": f"Bearer {raw_token}"}
    inventory_session = client.post("/pxe/inventory/sessions").json()
    submitted = client.post(
        "/pxe/inventory/report",
        json=inventory_report(),
        headers={"Authorization": f"Bearer {inventory_session['access_token']}"},
    )
    host_id = submitted.json()["host_id"]
    reboot = client.post(
        f"/api/v1/network-boot/hosts/{host_id}/reboot",
        headers=headers,
    )
    assert reboot.status_code == 202, reboot.text

    from atlaso.app.database import SessionLocal

    with SessionLocal() as db:
        reference = EsxiPxeHost(
            hostname="promoted-state-remains",
            mac_address="52:54:00:12:34:56",
            enabled=False,
        )
        db.add(reference)
        db.commit()
        reference_id = reference.id

    response = client.delete(
        f"/api/v1/network-boot/hosts/{host_id}",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    assert response.json() == {
        "host_id": host_id,
        "removed": True,
        "commands": 1,
        "sessions": 1,
        "reports": 1,
    }

    with SessionLocal() as db:
        assert db.get(NetworkBootDiscoveredHost, host_id) is None
        assert db.get(NetworkBootInventorySession, inventory_session["session_id"]) is None
        assert db.get(NetworkBootInventoryCommand, reboot.json()["id"]) is None
        assert db.get(NetworkBootInventoryReport, submitted.json()["report_id"]) is None
        assert db.get(EsxiPxeHost, reference_id) is not None
        event = db.execute(
            select(AuditEvent).where(
                AuditEvent.action == "remove_discovered_host",
                AuditEvent.resource_id == str(host_id),
            )
        ).scalar_one()
        assert event.detail == "reports=1; sessions=1; commands=1"


def test_host_management_requires_scopes_and_returns_missing_resources(client):
    read_token = create_api_token(client, ["read:pxe"])
    write_token = create_api_token(client, ["write:pxe"])
    read_headers = {"Authorization": f"Bearer {read_token}"}
    write_headers = {"Authorization": f"Bearer {write_token}"}

    assert client.delete(
        "/api/v1/network-boot/hosts/999999", headers=read_headers
    ).status_code == 403
    assert client.post(
        "/api/v1/network-boot/hosts/999999/wake", headers=read_headers
    ).status_code == 403
    assert client.get(
        "/api/v1/network-boot/hosts/999999/reports/999999/download",
        headers=write_headers,
    ).status_code == 403
    assert client.delete(
        "/api/v1/network-boot/hosts/999999", headers=write_headers
    ).status_code == 404
    assert client.post(
        "/api/v1/network-boot/hosts/999999/wake", headers=write_headers
    ).status_code == 404
    assert client.post(
        "/api/v1/network-boot/esxi-hosts/999999/wake", headers=write_headers
    ).status_code == 404
    assert client.get(
        "/api/v1/network-boot/hosts/999999/reports/999999/download",
        headers=read_headers,
    ).status_code == 404


def test_remove_discovered_host_rolls_back_cleanup_when_audit_fails(
    client,
    monkeypatch,
):
    raw_token = create_api_token(client, ["write:pxe"])
    inventory_session = client.post("/pxe/inventory/sessions").json()
    submitted = client.post(
        "/pxe/inventory/report",
        json=inventory_report(),
        headers={"Authorization": f"Bearer {inventory_session['access_token']}"},
    )
    host_id = submitted.json()["host_id"]
    monkeypatch.setattr(
        network_boot_api,
        "record_audit",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("audit failed")),
    )

    with pytest.raises(RuntimeError, match="audit failed"):
        client.delete(
            f"/api/v1/network-boot/hosts/{host_id}",
            headers={"Authorization": f"Bearer {raw_token}"},
        )

    from atlaso.app.database import SessionLocal

    with SessionLocal() as db:
        assert db.get(NetworkBootDiscoveredHost, host_id) is not None
        assert db.get(NetworkBootInventorySession, inventory_session["session_id"]) is not None
        assert db.get(NetworkBootInventoryReport, submitted.json()["report_id"]) is not None


def test_media_downloads_queue_fifo_and_only_deduplicate_same_source(client):
    raw_token = create_api_token(client, ["write:pxe"])
    headers = {"Authorization": f"Bearer {raw_token}"}

    first = client.post(
        "/api/v1/network-boot/environments/gparted/sync",
        headers=headers,
    )
    second = client.post(
        "/api/v1/network-boot/environments/clonezilla/sync",
        headers=headers,
    )
    duplicate = client.post(
        "/api/v1/network-boot/environments/gparted/sync",
        headers=headers,
    )

    assert first.status_code == 202, first.text
    assert second.status_code == 202, second.text
    assert duplicate.status_code == 409
    assert first.json()["job_id"] in duplicate.json()["detail"]

    from atlaso.app.database import SessionLocal

    with SessionLocal() as db:
        jobs = db.execute(
            select(Job)
            .where(Job.type == "pxe-media-sync")
            .order_by(Job.created_at, Job.id)
        ).scalars().all()
        assert [job.id for job in jobs] == [
            first.json()["job_id"],
            second.json()["job_id"],
        ]
        assert [json.loads(job.task_config_json)["environment"] for job in jobs] == [
            "gparted",
            "clonezilla",
        ]

    upload = client.post(
        "/api/v1/network-boot/environments/shredos/upload",
        headers=headers,
        files={"artifact": ("shredos.iso", b"not-read-while-active", "application/octet-stream")},
    )
    assert upload.status_code == 409
    assert first.json()["job_id"] in upload.json()["detail"]


def test_concurrent_duplicate_media_download_admission_is_atomic(client, monkeypatch):
    original_active_media_job = network_boot_api._active_media_job
    barrier = threading.Barrier(2)
    call_lock = threading.Lock()
    initial_calls = 0

    def synchronized_active_media_job(*args, **kwargs):
        nonlocal initial_calls
        result = original_active_media_job(*args, **kwargs)
        with call_lock:
            initial_calls += 1
            wait_for_competitor = initial_calls <= 2
        if wait_for_competitor:
            barrier.wait(timeout=5)
        return result

    monkeypatch.setattr(
        network_boot_api,
        "_active_media_job",
        synchronized_active_media_job,
    )

    from atlaso.app.database import SessionLocal

    def queue_download(index):
        request = SimpleNamespace(
            state=SimpleNamespace(request_id=f"concurrent-download-{index}")
        )
        identity = SimpleNamespace(username="admin")
        with SessionLocal() as db:
            try:
                return network_boot_api.sync_network_boot_environment(
                    "gparted",
                    request,
                    identity,
                    db,
                )
            except HTTPException as exc:
                return exc

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(queue_download, range(2)))

    accepted = next(response for response in responses if isinstance(response, dict))
    rejected = next(response for response in responses if isinstance(response, HTTPException))
    assert rejected.status_code == 409
    assert accepted["job_id"] in rejected.detail

    with SessionLocal() as db:
        jobs = db.execute(
            select(Job).where(
                Job.type == "pxe-media-sync",
                Job.network_boot_environment_key == "gparted",
                Job.network_boot_source == "download",
                Job.status.in_((JobStatus.PENDING.value, JobStatus.RUNNING.value)),
            )
        ).scalars().all()
        assert [job.id for job in jobs] == [accepted["job_id"]]


def test_inventory_report_is_bounded_and_uses_mac_for_placeholder_uuid():
    payload = inventory_report(dmi_uuid="00000000-0000-0000-0000-000000000000")
    normalized = normalize_inventory_report(payload)
    assert normalized["system"]["dmi_uuid"] == ""
    assert normalized["boot_mac"] == "52:54:00:12:34:56"

    payload["disks"] = [{}] * (NETWORK_BOOT_MAX_DISKS + 1)
    with pytest.raises(ValueError, match="at most 128 disks"):
        normalize_inventory_report(payload)


def test_inventory_report_v1_normalizes_to_v2_compatibility_shape():
    normalized = normalize_inventory_report(inventory_report())

    assert normalized["schema_version"] == 2
    assert normalized["source_schema_version"] == 1
    assert normalized["cpu"]["cores_per_socket"] == 0
    assert normalized["cpu"]["threads_per_core"] == 0
    assert normalized["memory"]["dimms"] == []
    assert normalized["storage_controllers"] == []
    assert normalized["pci_devices"] == []
    assert normalized["usb_devices"] == []
    assert normalized["system"]["baseboard"]["serial"] == ""
    assert normalized["interfaces"][0]["pci_address"] == ""
    assert normalized["disks"][0]["type"] == ""


def test_complete_inventory_report_v2_normalizes_all_structured_hardware():
    payload = inventory_report_v2()

    normalized = normalize_inventory_report(payload)

    assert normalized["schema_version"] == 2
    assert normalized["source_schema_version"] == 2
    assert normalized["system"]["baseboard"]["asset_tag"] == "BOARD-ASSET"
    assert normalized["system"]["chassis"]["type"] == "Rack Mount Chassis"
    assert normalized["cpu"]["cores_per_socket"] == 4
    assert normalized["cpu"]["threads_per_core"] == 2
    assert normalized["memory"]["dimms"][0]["part_number"] == "MEM-8G"
    assert normalized["interfaces"][0]["vendor_id"] == "8086"
    assert normalized["disks"][0]["controller_pci_address"] == "0000:03:00.0"
    assert normalized["storage_controllers"][0]["driver"] == "ahci"
    assert normalized["pci_devices"][0]["class_id"] == "020000"
    assert normalized["usb_devices"][0]["product_id"] == "5581"


@pytest.mark.parametrize(
    ("field", "limit"),
    (
        ("interfaces", NETWORK_BOOT_MAX_INTERFACES),
        ("storage_controllers", NETWORK_BOOT_MAX_STORAGE_CONTROLLERS),
        ("pci_devices", NETWORK_BOOT_MAX_PCI_DEVICES),
        ("usb_devices", NETWORK_BOOT_MAX_USB_DEVICES),
    ),
)
def test_inventory_report_rejects_collection_count_limits(field, limit):
    payload = inventory_report_v2()
    payload[field] = [{}] * (limit + 1)

    with pytest.raises(ValueError, match=f"at most {limit}"):
        normalize_inventory_report(payload)


def test_inventory_report_rejects_dimm_string_and_report_size_limits():
    payload = inventory_report_v2()
    payload["memory"]["dimms"] = [{}] * (NETWORK_BOOT_MAX_DIMMS + 1)
    with pytest.raises(ValueError, match=f"at most {NETWORK_BOOT_MAX_DIMMS}"):
        normalize_inventory_report(payload)

    payload = inventory_report_v2()
    payload["memory"]["dimms"][0]["part_number"] = "x" * 241
    with pytest.raises(ValueError, match="240 characters or fewer"):
        normalize_inventory_report(payload)

    payload = inventory_report_v2()
    payload["ignored_padding"] = "x" * NETWORK_BOOT_REPORT_MAX_BYTES
    with pytest.raises(ValueError, match="256 KiB"):
        normalize_inventory_report(payload)


def test_inventory_report_rejects_normalized_report_size_limit():
    payload = inventory_report_v2()
    payload["interfaces"] = [{}] * NETWORK_BOOT_MAX_INTERFACES
    payload["disks"] = [{}] * NETWORK_BOOT_MAX_DISKS
    payload["memory"]["dimms"] = [{}] * NETWORK_BOOT_MAX_DIMMS
    payload["storage_controllers"] = [{}] * NETWORK_BOOT_MAX_STORAGE_CONTROLLERS
    payload["pci_devices"] = [
        {"vendor": "x" * 200, "device": "y" * 200}
    ] * NETWORK_BOOT_MAX_PCI_DEVICES
    payload["usb_devices"] = [{}] * NETWORK_BOOT_MAX_USB_DEVICES

    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    assert len(encoded) < NETWORK_BOOT_REPORT_MAX_BYTES
    with pytest.raises(ValueError, match="Normalized inventory report exceeds"):
        normalize_inventory_report(payload)


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        (lambda payload: payload["system"].update({"baseboard": []}), "baseboard"),
        (
            lambda payload: payload["interfaces"][0].update({"boot_interface": "false"}),
            "must be a boolean",
        ),
        (lambda payload: payload["pci_devices"][0].update({"class_id": "0200"}), "six hexadecimal"),
        (lambda payload: payload["usb_devices"][0].update({"vendor_id": "xyz"}), "four hexadecimal"),
    ),
)
def test_inventory_report_rejects_malformed_hardware(mutation, message):
    payload = inventory_report_v2()
    mutation(payload)

    with pytest.raises(ValueError, match=message):
        normalize_inventory_report(payload)


def test_inventory_report_retains_complete_normalized_v2_json(db_session):
    session, _token = issue_inventory_session(db_session)
    payload = inventory_report_v2()

    _host, stored = store_inventory_report(db_session, session=session, payload=payload)
    retained = json.loads(stored.payload_json)

    assert stored.schema_version == 2
    assert retained == normalize_inventory_report(payload)
    assert retained["memory"]["dimms"][0]["serial"] == "DIMM-1"
    assert retained["pci_devices"][0]["device"] == "10-Gigabit Network Connection"


def test_inventory_report_ignores_optional_placeholder_interface_macs():
    payload = inventory_report()
    payload["interfaces"].append(
        {
            "name": "eth1",
            "permanent_mac": "00:00:00:00:00:00",
            "current_mac": "ff:ff:ff:ff:ff:ff",
            "driver": "placeholder",
            "link_state": "down",
            "speed_mbps": 0,
            "addresses": [],
            "boot_interface": False,
        }
    )

    normalized = normalize_inventory_report(payload)

    assert normalized["interfaces"][1]["permanent_mac"] == ""
    assert normalized["interfaces"][1]["current_mac"] == ""
    assert normalized["boot_mac"] == "52:54:00:12:34:56"


def test_uuid_with_disjoint_macs_is_flagged_as_collision(db_session):
    first_session, _token = issue_inventory_session(db_session)
    first, _report = store_inventory_report(
        db_session,
        session=first_session,
        payload=inventory_report(boot_mac="52:54:00:12:34:56"),
    )
    second_session, _token = issue_inventory_session(db_session)
    second, _report = store_inventory_report(
        db_session,
        session=second_session,
        payload=inventory_report(boot_mac="52:54:00:aa:bb:cc"),
    )
    assert first.id != second.id
    assert first.collision is True
    assert second.collision is True


def test_dmi_only_report_rejects_ambiguous_collision_candidates(db_session):
    dmi_uuid = "4c4c4544-004b-4d10-8052-cac04f4c5100"
    for mac in ("52:54:00:12:34:56", "52:54:00:aa:bb:cc"):
        session, _token = issue_inventory_session(db_session)
        store_inventory_report(
            db_session,
            session=session,
            payload=inventory_report(dmi_uuid=dmi_uuid, boot_mac=mac),
        )
    existing_reports = db_session.execute(
        select(NetworkBootInventoryReport)
    ).scalars().all()
    ambiguous = inventory_report(
        dmi_uuid=dmi_uuid,
        boot_mac="00:00:00:00:00:00",
    )
    ambiguous["interfaces"][0]["permanent_mac"] = "00:00:00:00:00:00"
    ambiguous["interfaces"][0]["current_mac"] = "ff:ff:ff:ff:ff:ff"
    session, _token = issue_inventory_session(db_session)

    with pytest.raises(ValueError, match="matches multiple hosts"):
        store_inventory_report(
            db_session,
            session=session,
            payload=ambiguous,
        )

    reports = db_session.execute(select(NetworkBootInventoryReport)).scalars().all()
    assert len(reports) == len(existing_reports)


def test_dmi_only_report_preserves_single_candidate_macs(db_session):
    dmi_uuid = "4c4c4544-004b-4d10-8052-cac04f4c5100"
    expected_mac = "52:54:00:12:34:56"
    first_session, _token = issue_inventory_session(db_session)
    first, _report = store_inventory_report(
        db_session,
        session=first_session,
        payload=inventory_report(dmi_uuid=dmi_uuid, boot_mac=expected_mac),
    )
    dmi_only = inventory_report(
        dmi_uuid=dmi_uuid,
        boot_mac="00:00:00:00:00:00",
    )
    dmi_only["interfaces"][0]["permanent_mac"] = "00:00:00:00:00:00"
    dmi_only["interfaces"][0]["current_mac"] = "ff:ff:ff:ff:ff:ff"
    second_session, _token = issue_inventory_session(db_session)
    second, _report = store_inventory_report(
        db_session,
        session=second_session,
        payload=dmi_only,
    )
    third_session, _token = issue_inventory_session(db_session)
    third, _report = store_inventory_report(
        db_session,
        session=third_session,
        payload=inventory_report(dmi_uuid=dmi_uuid, boot_mac=expected_mac),
    )

    assert second.id == first.id
    assert third.id == first.id
    assert second.boot_mac == expected_mac
    assert json.loads(second.macs_json) == [expected_mac]
    assert third.collision is False


def test_inventory_retains_latest_and_ten_previous_reports(db_session):
    host_id = None
    for index in range(NETWORK_BOOT_REPORTS_PER_HOST + 3):
        session, _token = issue_inventory_session(db_session)
        host, _report = store_inventory_report(
            db_session,
            session=session,
            payload=inventory_report(),
        )
        host_id = host.id
        db_session.commit()
    rows = db_session.execute(
        select(NetworkBootInventoryReport).where(
            NetworkBootInventoryReport.host_id == host_id
        )
    ).scalars().all()
    assert len(rows) == NETWORK_BOOT_REPORTS_PER_HOST


def test_inventory_prunes_global_hosts_reports_and_sessions(db_session, monkeypatch):
    monkeypatch.setattr(network_boot, "NETWORK_BOOT_MAX_HOSTS", 2)
    monkeypatch.setattr(network_boot, "NETWORK_BOOT_MAX_REPORTS", 2)
    monkeypatch.setattr(network_boot, "NETWORK_BOOT_MAX_SESSIONS", 2)

    for index in range(3):
        session, _token = issue_inventory_session(db_session)
        store_inventory_report(
            db_session,
            session=session,
            payload=inventory_report(
                dmi_uuid=f"4c4c4544-004b-4d10-8052-cac04f4c51{index:02d}",
                boot_mac=f"52:54:00:12:34:{index:02x}",
            ),
        )
        session.heartbeat_at = utcnow() - timedelta(minutes=5)
        db_session.commit()

    assert len(db_session.execute(select(NetworkBootDiscoveredHost)).scalars().all()) == 2
    assert len(db_session.execute(select(NetworkBootInventoryReport)).scalars().all()) == 2
    assert len(db_session.execute(select(NetworkBootInventorySession)).scalars().all()) <= 2


def test_inventory_storage_pruning_preserves_live_hosts(db_session, monkeypatch):
    monkeypatch.setattr(network_boot, "NETWORK_BOOT_MAX_HOSTS", 2)
    monkeypatch.setattr(network_boot, "NETWORK_BOOT_MAX_REPORTS", 2)

    live_session, _token = issue_inventory_session(db_session)
    live_host, _report = store_inventory_report(
        db_session,
        session=live_session,
        payload=inventory_report(
            dmi_uuid="4c4c4544-004b-4d10-8052-cac04f4c5101",
            boot_mac="52:54:00:12:34:01",
        ),
    )
    db_session.commit()

    stale_session, _token = issue_inventory_session(db_session)
    stale_host, _report = store_inventory_report(
        db_session,
        session=stale_session,
        payload=inventory_report(
            dmi_uuid="4c4c4544-004b-4d10-8052-cac04f4c5102",
            boot_mac="52:54:00:12:34:02",
        ),
    )
    stale_session.heartbeat_at = utcnow() - timedelta(minutes=5)
    db_session.commit()

    newest_session, _token = issue_inventory_session(db_session)
    newest_host, _report = store_inventory_report(
        db_session,
        session=newest_session,
        payload=inventory_report(
            dmi_uuid="4c4c4544-004b-4d10-8052-cac04f4c5103",
            boot_mac="52:54:00:12:34:03",
        ),
    )
    db_session.flush()

    assert db_session.get(NetworkBootDiscoveredHost, live_host.id) is not None
    assert db_session.get(NetworkBootDiscoveredHost, newest_host.id) is not None
    assert db_session.get(NetworkBootDiscoveredHost, stale_host.id) is None


def test_inventory_session_cap_preserves_live_and_command_sessions(
    db_session,
    monkeypatch,
):
    monkeypatch.setattr(network_boot, "NETWORK_BOOT_MAX_SESSIONS", 2)
    live, _token = issue_inventory_session(db_session)
    live_host, _report = store_inventory_report(
        db_session,
        session=live,
        payload=inventory_report(),
    )
    touch_inventory_heartbeat(live, identity_key=live_host.identity_key)
    commanded, _token = issue_inventory_session(db_session)
    commanded_host, _report = store_inventory_report(
        db_session,
        session=commanded,
        payload=inventory_report(
            dmi_uuid="4c4c4544-004b-4d10-8052-cac04f4c5199",
            boot_mac="52:54:00:12:34:99",
        ),
    )
    touch_inventory_heartbeat(commanded, identity_key=commanded_host.identity_key)
    queue_reboot_command(db_session, host=commanded_host, requested_by="admin")
    commanded.heartbeat_at = utcnow() - timedelta(minutes=5)
    db_session.commit()

    with pytest.raises(ValueError, match="occupied by live clients"):
        issue_inventory_session(db_session)

    assert db_session.get(NetworkBootInventorySession, live.id) is not None
    assert db_session.get(NetworkBootInventorySession, commanded.id) is not None


def test_issuing_inventory_session_prunes_expired_sessions(db_session):
    expired, _token = issue_inventory_session(db_session)
    expired.expires_at = utcnow() - timedelta(seconds=1)
    db_session.commit()

    current, _token = issue_inventory_session(db_session)
    db_session.flush()

    assert db_session.get(NetworkBootInventorySession, expired.id) is None
    assert db_session.get(NetworkBootInventorySession, current.id) is not None


def test_public_inventory_session_binds_identity_and_rejects_replay(client):
    session_response = client.post("/pxe/inventory/sessions")
    assert session_response.status_code == 201
    assert session_response.headers["cache-control"] == "no-store"
    token = session_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    submitted = client.post(
        "/pxe/inventory/report",
        headers=headers,
        json=inventory_report(),
    )
    assert submitted.status_code == 201, submitted.text
    assert submitted.json()["identity_key"].startswith("uuid:")
    replay = client.post(
        "/pxe/inventory/report",
        headers=headers,
        json=inventory_report(),
    )
    assert replay.status_code == 409


def test_public_inventory_report_marks_live_capacity_as_retryable(client, monkeypatch):
    session_response = client.post("/pxe/inventory/sessions")
    assert session_response.status_code == 201
    token = session_response.json()["access_token"]

    def capacity_error(*_args, **_kwargs):
        raise ValueError(
            "Inventory storage capacity is occupied by live clients; retry later."
        )

    monkeypatch.setattr(network_boot_api, "store_inventory_report", capacity_error)
    response = client.post(
        "/pxe/inventory/report",
        headers={"Authorization": f"Bearer {token}"},
        json=inventory_report(),
    )

    assert response.status_code == 503
    assert response.json()["detail"].endswith("retry later.")


def test_public_inventory_report_logs_sanitized_validation_reason(client, caplog):
    session_response = client.post("/pxe/inventory/sessions")
    assert session_response.status_code == 201
    token = session_response.json()["access_token"]

    invalid = inventory_report()
    invalid["interfaces"][0]["current_mac"] = "not-a-mac"
    with caplog.at_level("WARNING", logger="uvicorn.error"):
        response = client.post(
            "/pxe/inventory/report",
            headers={"Authorization": f"Bearer {token}"},
            json=invalid,
        )

    assert response.status_code == 422
    assert "Rejected Inventory Linux report: MAC address must contain six hexadecimal octets." in caplog.text


def test_media_upload_is_staged_as_a_durable_verification_job(
    client,
    db_session,
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(
        "atlaso.app.api.network_boot.network_boot_upload_path",
        lambda job_id: tmp_path / job_id / "artifact",
    )
    token = create_api_token(client, ["write:pxe"])
    response = client.post(
        "/api/v1/network-boot/environments/shredos/upload",
        headers={"Authorization": f"Bearer {token}"},
        files={
            "artifact": (
                "shredos-2025.11.iso",
                b"uploaded boot media",
                "application/x-iso9660-image",
            )
        },
    )

    assert response.status_code == 202, response.text
    payload = response.json()
    staged = tmp_path / payload["job_id"] / "artifact"
    assert staged.read_bytes() == b"uploaded boot media"
    job = db_session.get(Job, payload["job_id"])
    config = json.loads(job.task_config_json)
    assert config["source"] == "upload"
    assert config["environment"] == "shredos"
    assert config["filename"] == "shredos-2025.11.iso"


def test_deleting_inactive_media_cleans_environment_upload_staging(
    client,
    db_session,
    monkeypatch,
    tmp_path,
):
    media_root = tmp_path / "media"
    environment_root = media_root / "shredos"
    installed = environment_root / "2025.11"
    installed.mkdir(parents=True)
    (installed / "manifest.json").write_text("{}", encoding="utf-8")
    upload_root = tmp_path / "uploads"
    job = Job(
        id="job_" + ("e" * 32),
        type="pxe-media-sync",
        status=JobStatus.PENDING.value,
        created_by="admin",
        task_config_json=json.dumps(
            {"environment": "shredos", "source": "upload"}
        ),
    )
    staged = network_boot_upload_path(job.id, upload_root=upload_root)
    staged.parent.mkdir(parents=True)
    staged.write_bytes(b"terminal staged artifact")
    media = record_verified_media(
        db_session,
        environment_key="shredos",
        version="2025.11",
        source_url="https://example.test/shredos.iso",
        artifact_sha256="a" * 64,
        installed_path=str(installed.resolve()),
        manifest={"schema_version": 1},
    )
    media_id = media.id
    db_session.add(job)
    db_session.commit()
    monkeypatch.setitem(
        _MEDIA_ENVIRONMENT_ROOTS,
        "shredos",
        environment_root.resolve(),
    )
    monkeypatch.setattr(network_boot, "NETWORK_BOOT_UPLOAD_ROOT", upload_root)
    token = create_api_token(client, ["write:pxe"])

    blocked = client.delete(
        "/api/v1/network-boot/environments/shredos/media/2025.11",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert blocked.status_code == 409
    assert installed.exists()
    assert staged.exists()

    job.status = JobStatus.SUCCEEDED.value
    db_session.commit()
    response = client.delete(
        "/api/v1/network-boot/environments/shredos/media/2025.11",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["staged_uploads_cleaned"] == 1
    assert not installed.exists()
    assert not staged.exists()
    db_session.expire_all()
    assert db_session.get(NetworkBootMedia, media_id) is None


def test_inventory_session_stores_only_token_hash_and_expires(db_session):
    session, token = issue_inventory_session(db_session)
    assert token not in session.token_hash
    assert len(session.token_hash) == 64
    assert inventory_session_for_token(db_session, token).id == session.id
    session.expires_at = utcnow() - timedelta(seconds=1)
    db_session.flush()
    with pytest.raises(ValueError, match="invalid or expired"):
        inventory_session_for_token(db_session, token)


def test_inventory_identity_heartbeat_and_one_time_reboot(db_session):
    session, token = issue_inventory_session(db_session)
    host, _report = store_inventory_report(
        db_session,
        session=session,
        payload=inventory_report(),
    )
    touch_inventory_heartbeat(session, identity_key=host.identity_key)
    with pytest.raises(ValueError, match="does not match"):
        touch_inventory_heartbeat(session, identity_key="mac:52:54:00:ff:ff:ff")
    command = queue_reboot_command(db_session, host=host, requested_by="admin")
    assert latest_live_session(db_session, host.id).id == session.id
    delivered = poll_inventory_command(db_session, session=session)
    assert delivered.id == command.id
    assert delivered.status == "delivered"
    redelivered = poll_inventory_command(db_session, session=session)
    assert redelivered.id == command.id
    assert redelivered.delivered_at == delivered.delivered_at
    acknowledged = acknowledge_inventory_command(
        db_session,
        session=session,
        command_id=command.id,
    )
    assert acknowledged.status == "acknowledged"
    assert poll_inventory_command(db_session, session=session) is None
    repeated = acknowledge_inventory_command(
        db_session,
        session=session,
        command_id=command.id,
    )
    assert repeated.status == "acknowledged"
    assert repeated.acknowledged_at == acknowledged.acknowledged_at


def test_stale_inventory_session_is_offline_and_reboot_conflicts(db_session):
    session, _token = issue_inventory_session(db_session)
    host, _report = store_inventory_report(
        db_session,
        session=session,
        payload=inventory_report(),
    )
    session.heartbeat_at = utcnow() - timedelta(seconds=31)
    db_session.flush()
    assert latest_live_session(db_session, host.id) is None
    with pytest.raises(ValueError, match="does not have a live"):
        queue_reboot_command(db_session, host=host, requested_by="admin")


def test_settings_archive_keeps_desired_environment_but_excludes_media_and_history(
    db_session,
):
    from atlaso.app.services.settings_archive import export_settings_archive

    states = {row.key: row for row in ensure_environment_rows(db_session)}
    media = record_verified_media(
        db_session,
        environment_key="memtest86plus",
        version="8.10",
        source_url="https://www.memtest.org/download/v8.10/example.zip",
        artifact_sha256="a" * 64,
        installed_path="/var/lib/atlaso/pxe/media/memtest86plus/8.10",
        manifest={"schema_version": 1},
    )
    states["memtest86plus"].enabled = True
    states["memtest86plus"].desired_version = media.version
    states["memtest86plus"].active_version = media.version
    session, _token = issue_inventory_session(db_session)
    store_inventory_report(db_session, session=session, payload=inventory_report())
    archive = export_settings_archive(db_session, actor="test")
    data = archive["data"]
    environment = next(
        row for row in data["network_boot_environments"] if row["key"] == "memtest86plus"
    )
    assert environment["enabled"] is True
    assert environment["desired_version"] == "8.10"
    assert "active_version" not in environment
    assert "network_boot_media" not in data
    assert "network_boot_inventory_reports" not in data
    assert "network_boot_inventory_sessions" not in data


def test_settings_restore_and_factory_reset_preserve_installed_media_metadata(
    db_session,
):
    from atlaso.app.services.settings_archive import (
        export_settings_archive,
        factory_reset_desired_state,
        restore_settings_archive,
    )

    states = {row.key: row for row in ensure_environment_rows(db_session)}
    media = record_verified_media(
        db_session,
        environment_key="memtest86plus",
        version="8.10",
        source_url="https://www.memtest.org/download/v8.10/example.zip",
        artifact_sha256="a" * 64,
        installed_path="/var/lib/atlaso/pxe/media/memtest86plus/8.10",
        manifest={"schema_version": 1},
    )
    states["memtest86plus"].enabled = True
    states["memtest86plus"].desired_version = media.version
    states["memtest86plus"].active_version = media.version
    db_session.commit()
    archive = export_settings_archive(db_session, actor="test")

    restore_settings_archive(db_session, archive)
    assert db_session.get(NetworkBootMedia, media.id) is not None
    restored = db_session.get(type(states["memtest86plus"]), "memtest86plus")
    assert restored.desired_version == "8.10"
    assert restored.active_version == ""

    factory_reset_desired_state(db_session)
    assert db_session.get(NetworkBootMedia, media.id) is not None
    reset = db_session.get(type(states["memtest86plus"]), "memtest86plus")
    assert reset.enabled is False
    assert reset.desired_version == ""
    assert reset.active_version == ""


def test_legacy_settings_restore_clears_unarchived_network_boot_state(db_session):
    from atlaso.app.services.settings_archive import (
        export_settings_archive,
        restore_settings_archive,
    )

    states = {row.key: row for row in ensure_environment_rows(db_session)}
    media = record_verified_media(
        db_session,
        environment_key="inventory",
        version="2026.05.1+3",
        source_url="https://buildroot.org/downloads/buildroot-2026.05.1.tar.xz",
        artifact_sha256="b" * 64,
        installed_path="/var/lib/atlaso/pxe/media/inventory/2026.05.1+3",
        manifest={"schema_version": 1},
    )
    archive = export_settings_archive(db_session, actor="test")
    archive["data"].pop("network_boot_environments")
    states["inventory"].enabled = True
    states["inventory"].desired_version = media.version
    states["inventory"].active_version = media.version
    db_session.commit()

    restore_settings_archive(db_session, archive)

    restored = db_session.get(NetworkBootEnvironment, "inventory")
    assert restored.enabled is False
    assert restored.desired_version == ""
    assert restored.active_version == ""
    assert db_session.get(NetworkBootMedia, media.id) is not None


def test_generic_pxe_scopes_do_not_follow_legacy_esxi_scope(client):
    legacy = create_api_token(client, ["read:esxi-pxe"])
    denied = client.get(
        "/api/v1/network-boot/hosts",
        headers={"Authorization": f"Bearer {legacy}"},
    )
    assert denied.status_code == 403

    generic = create_api_token(client, ["read:pxe"])
    allowed = client.get(
        "/api/v1/network-boot/hosts",
        headers={"Authorization": f"Bearer {generic}"},
    )
    assert allowed.status_code == 200


def test_unknown_host_defaults_to_inventory_and_shredos_has_cancel_guard(db_session):
    states = {row.key: row for row in ensure_environment_rows(db_session)}
    inventory = record_verified_media(
        db_session,
        environment_key="inventory",
        version="2026.05.1",
        source_url="https://buildroot.org/downloads/buildroot-2026.05.1.tar.xz",
        artifact_sha256="a" * 64,
        installed_path="/var/lib/atlaso/pxe/media/inventory/2026.05.1",
        manifest={
            "boot": {
                "kernel": "http://192.0.2.1/pxe/media/inventory/2026.05.1/bzImage",
                "initrd": "http://192.0.2.1/pxe/media/inventory/2026.05.1/rootfs.cpio.gz",
            }
        },
    )
    shredos = record_verified_media(
        db_session,
        environment_key="shredos",
        version="2025.11_30_x86-64_0.41",
        source_url="https://github.com/PartialVolume/shredos.x86_64/releases/download/example/shredos.iso",
        artifact_sha256="b" * 64,
        installed_path="/var/lib/atlaso/pxe/media/shredos/2025.11_30_x86-64_0.41",
        manifest={"boot": {"script": "http://192.0.2.1/pxe/media/shredos/boot.ipxe"}},
    )
    states["inventory"].enabled = True
    states["inventory"].active_version = inventory.version
    states["shredos"].enabled = True
    states["shredos"].active_version = shredos.version
    db_session.commit()

    menu = render_network_boot_menu(
        db_session,
        mac_address="52:54:00:de:ad:be",
    )
    assert "choose --timeout 10000 --default inventory" in menu
    assert "atlaso.boot_mac=${net0/mac}" in menu
    assert "menu ShredOS can permanently erase selected disks" in menu
    assert "choose --default cancel" in menu
    assert "--timeout" not in menu.split(
        "menu ShredOS can permanently erase selected disks",
        1,
    )[1].split("iseq ${shred_choice}", 1)[0]
    assert "autonuke" not in menu.lower()


def test_active_media_remains_available_until_disable_is_applied(db_session):
    states = {row.key: row for row in ensure_environment_rows(db_session)}
    inventory = record_verified_media(
        db_session,
        environment_key="inventory",
        version="2026.05.1",
        source_url="https://example.test/atlaso-inventory-linux.zip",
        artifact_sha256="a" * 64,
        installed_path="/var/lib/atlaso/pxe/media/inventory/2026.05.1",
        manifest={"boot": {"kernel": "/bzImage", "initrd": "/rootfs.cpio.gz"}},
    )
    states["inventory"].enabled = False
    states["inventory"].active_version = inventory.version
    db_session.commit()

    menu = render_network_boot_menu(db_session)

    assert "item inventory Atlaso Inventory Linux" in menu
    assert "choose --timeout 10000 --default inventory" in menu


def test_media_file_remains_available_until_disable_is_applied(
    client,
    db_session,
    monkeypatch,
    tmp_path,
):
    states = {row.key: row for row in ensure_environment_rows(db_session)}
    installed = tmp_path / "inventory" / "2026.05.1"
    installed.mkdir(parents=True)
    (installed / "bzImage").write_bytes(b"kernel")
    media = record_verified_media(
        db_session,
        environment_key="inventory",
        version="2026.05.1",
        source_url="https://example.test/atlaso-inventory-linux.zip",
        artifact_sha256="a" * 64,
        installed_path=str(installed.resolve()),
        manifest={"boot": {"kernel": "/bzImage"}, "files": ["bzImage"]},
    )
    states["inventory"].enabled = False
    states["inventory"].active_version = media.version
    db_session.commit()
    monkeypatch.setitem(
        network_boot_api._MEDIA_ENVIRONMENT_ROOTS,
        "inventory",
        (tmp_path / "inventory").resolve(),
    )

    response = client.get("/pxe/media/inventory/2026.05.1/bzImage")
    head_response = client.head("/pxe/media/inventory/2026.05.1/bzImage")

    assert response.status_code == 200, response.text
    assert response.content == b"kernel"
    assert head_response.status_code == 200, head_response.text
    assert head_response.content == b""
    assert head_response.headers["content-length"] == str(len(b"kernel"))


def test_same_version_shredos_repair_serves_applied_snapshot_until_apply(
    client,
    db_session,
    monkeypatch,
    tmp_path,
):
    environment_root = tmp_path / "shredos"
    applied = environment_root / "2025.11"
    replacement = environment_root / (
        "2025.11.sha256-" + ("b" * 12) + "-" + ("d" * 12)
    )
    applied.mkdir(parents=True)
    replacement.mkdir()
    (applied / "boot.ipxe").write_bytes(b"legacy applied script")
    (replacement / "boot.ipxe").write_bytes(b"verified replacement script")
    applied_manifest = {"files": ["boot.ipxe"], "artifacts": {"boot.ipxe": "a" * 64}}
    replacement_manifest = {
        "files": ["boot.ipxe"],
        "artifacts": {"boot.ipxe": "b" * 64},
    }
    media = record_verified_media(
        db_session,
        environment_key="shredos",
        version="2025.11",
        source_url="https://example.test/shredos.iso",
        artifact_sha256="b" * 64,
        installed_path=str(replacement.resolve()),
        manifest=replacement_manifest,
    )
    state = db_session.get(NetworkBootEnvironment, "shredos")
    assert state is not None
    state.enabled = True
    state.desired_version = media.version
    state.active_version = media.version
    db_session.commit()
    monkeypatch.setitem(
        network_boot_api._MEDIA_ENVIRONMENT_ROOTS,
        "shredos",
        environment_root.resolve(),
    )
    set_applied_pxe_runtime(
        db_session,
        environments=[
            {
                "key": "shredos",
                "enabled": True,
                "desired_version": media.version,
                "installed_path": str(applied.resolve()),
                "artifact_sha256": "a" * 64,
                "manifest": applied_manifest,
            }
        ],
    )

    response = client.get("/pxe/media/shredos/2025.11/boot.ipxe")

    assert response.status_code == 200, response.text
    assert response.content == b"legacy applied script"

    set_applied_pxe_runtime(
        db_session,
        environments=[
            {
                "key": "shredos",
                "enabled": True,
                "desired_version": media.version,
                "installed_path": media.installed_path,
                "artifact_sha256": media.artifact_sha256,
                "manifest": replacement_manifest,
            }
        ],
    )

    stale_response = client.get("/pxe/media/shredos/2025.11/boot.ipxe")
    response = client.get(
        f"/pxe/media/shredos/{replacement.name}/boot.ipxe"
    )

    assert stale_response.status_code == 404
    assert response.status_code == 200, response.text
    assert response.content == b"verified replacement script"
    assert "immutable" in response.headers["cache-control"]


def test_explicit_invalid_runtime_preview_does_not_fall_back_to_desired_media(
    db_session,
    tmp_path,
):
    installed = tmp_path / "shredos" / "2025.11"
    installed.mkdir(parents=True)
    media = record_verified_media(
        db_session,
        environment_key="shredos",
        version="2025.11",
        source_url="https://example.test/shredos.iso",
        artifact_sha256="b" * 64,
        installed_path=str(installed.resolve()),
        manifest={"boot": {"script": "/pxe/media/shredos/2025.11/boot.ipxe"}},
    )
    state = db_session.get(NetworkBootEnvironment, "shredos")
    assert state is not None
    state.enabled = True
    state.desired_version = media.version
    state.active_version = media.version
    setting = db_session.execute(
        select(Setting).where(Setting.key == "appliance_apply.baselines.v1")
    ).scalar_one_or_none()
    baselines = json.loads(setting.value) if setting else {}
    baselines["esxi_pxe"] = {
        "config_preview": json.dumps(
            {
                "kind": "atlaso-esxi-pxe",
                "schema_version": 1,
                "network_boot": {
                    "schema_version": 1,
                    "environments": [
                        {
                            "key": "shredos",
                            "enabled": True,
                            "desired_version": media.version,
                            "installed_path": media.installed_path,
                            "manifest": json.loads(media.manifest_json),
                        }
                    ],
                },
            }
        ),
        "runtime_config_preview": "",
    }
    if setting is None:
        setting = Setting(
            key="appliance_apply.baselines.v1",
            value=json.dumps(baselines),
        )
    else:
        setting.value = json.dumps(baselines)
    db_session.add(setting)
    db_session.commit()

    assert network_boot.active_network_boot_media(
        db_session,
        environment_key="shredos",
    ) is None


def test_prune_superseded_shredos_media_waits_for_applied_manifest(
    db_session,
    tmp_path,
):
    media_root = tmp_path / "media"
    environment_root = media_root / "shredos"
    version = "2025.11"

    def write_snapshot(path: Path, digest: str) -> dict:
        path.mkdir(parents=True)
        manifest = {
            "kind": "atlaso-network-boot-media",
            "schema_version": 1,
            "environment": "shredos",
            "version": version,
            "sha256": digest,
            "artifacts": {
                "boot.ipxe": "d" * 64,
                "shredos": "e" * 64,
            },
        }
        (path / "manifest.json").write_text(
            json.dumps(manifest),
            encoding="utf-8",
        )
        return manifest

    applied = environment_root / version
    applied_manifest = write_snapshot(applied, "a" * 64)
    current = environment_root / (
        f"{version}.sha256-{'b' * 12}-{'1' * 12}"
    )
    current_manifest = write_snapshot(current, "b" * 64)
    orphan = environment_root / (
        f"{version}.sha256-{'c' * 12}-{'2' * 12}"
    )
    write_snapshot(orphan, "c" * 64)
    unrelated = environment_root / "operator-files"
    unrelated.mkdir()

    media = record_verified_media(
        db_session,
        environment_key="shredos",
        version=version,
        source_url="https://example.test/shredos.iso",
        artifact_sha256="b" * 64,
        installed_path=str(current.resolve()),
        manifest=current_manifest,
    )
    db_session.commit()
    set_applied_pxe_runtime(
        db_session,
        environments=[
            {
                "key": "shredos",
                "enabled": True,
                "desired_version": version,
                "installed_path": str(applied.resolve()),
                "artifact_sha256": "a" * 64,
                "manifest": applied_manifest,
            }
        ],
    )

    assert network_boot.prune_superseded_shredos_media(
        db_session,
        media_root=media_root,
    ) == 1
    assert applied.exists()
    assert current.exists()
    assert not orphan.exists()
    assert unrelated.exists()

    set_applied_pxe_runtime(
        db_session,
        environments=[
            {
                "key": "shredos",
                "enabled": True,
                "desired_version": version,
                "installed_path": media.installed_path,
                "artifact_sha256": media.artifact_sha256,
                "manifest": current_manifest,
            }
        ],
    )

    assert network_boot.prune_superseded_shredos_media(
        db_session,
        media_root=media_root,
    ) == 1
    assert not applied.exists()
    assert current.exists()
    assert unrelated.exists()


@pytest.mark.parametrize("environment_key", ["gparted", "clonezilla"])
def test_debian_live_media_uses_fetch_with_implicit_dhcp(environment_key):
    manifest = network_boot._media_boot_manifest(
        environment_key,
        "1.0",
        extracted=["vmlinuz", "initrd.img", "filesystem.squashfs"],
    )

    arguments = manifest["boot"]["arguments"].split()
    assert "boot=live" in arguments
    assert "username=user" in arguments
    assert "fetch=/pxe/media/" + environment_key + "/1.0/filesystem.squashfs" in arguments
    assert "ip=dhcp" not in arguments


@pytest.mark.parametrize("environment_key", ["gparted", "clonezilla"])
def test_debian_live_chain_normalizes_existing_media_arguments(environment_key):
    media = NetworkBootMedia(
        environment_key=environment_key,
        version="1.0",
        manifest_json=json.dumps(
            {
                "boot": {
                    "kernel": f"/pxe/media/{environment_key}/1.0/vmlinuz",
                    "initrd": f"/pxe/media/{environment_key}/1.0/initrd.img",
                    "arguments": (
                        "boot=live config components ip=dhcp "
                        f"fetch=/pxe/media/{environment_key}/1.0/filesystem.squashfs"
                    ),
                }
            }
        ),
    )

    chain = network_boot._chain_line(media, http_origin="http://192.0.2.10:8080")

    assert " ip=dhcp " not in f" {chain} "
    assert "username=user" in chain
    assert "vga=788" in chain
    assert (
        "fetch=http://192.0.2.10:8080/pxe/media/"
        + environment_key
        + "/1.0/filesystem.squashfs"
    ) in chain


def test_public_rate_limit_prunes_expired_client_keys():
    network_boot_api._rate_windows.clear()
    network_boot_api._rate_windows["menu:192.0.2.1"] = deque([time.monotonic() - 120])
    request = StarletteRequest(
        {
            "type": "http",
            "method": "GET",
            "path": "/pxe/boot.ipxe",
            "headers": [(b"x-real-ip", b"198.51.100.20")],
            "client": ("127.0.0.1", 12345),
        }
    )

    network_boot_api._bounded_rate_limit(request, bucket="menu", limit=120)

    assert "menu:192.0.2.1" not in network_boot_api._rate_windows
    assert list(network_boot_api._rate_windows) == ["menu:198.51.100.20"]
    network_boot_api._rate_windows.clear()


def test_unknown_host_defaults_to_local_when_inventory_is_inactive(db_session):
    ensure_environment_rows(db_session)
    db_session.commit()

    menu = render_network_boot_menu(
        db_session,
        mac_address="52:54:00:de:ad:be",
    )

    assert "choose --timeout 10000 --default local" in menu
    assert "item inventory Atlaso Inventory Linux" not in menu


def test_boot_menu_uses_the_verified_secondary_listener_origin(
    db_session,
):
    states = {row.key: row for row in ensure_environment_rows(db_session)}
    inventory = record_verified_media(
        db_session,
        environment_key="inventory",
        version="2026.05.1",
        source_url="https://example.test/atlaso-inventory-linux.zip",
        artifact_sha256="a" * 64,
        installed_path="/var/lib/atlaso/pxe/media/inventory/2026.05.1",
        manifest={
            "boot": {
                "kernel": "/pxe/media/inventory/2026.05.1/bzImage",
                "initrd": "/pxe/media/inventory/2026.05.1/rootfs.cpio.gz",
            }
        },
    )
    states["inventory"].enabled = True
    states["inventory"].active_version = inventory.version
    boot = esxi_pxe_boot_settings(db_session)
    boot["listen_address"] = "192.0.2.10\n198.51.100.20"
    boot["http_port"] = 8080
    set_applied_pxe_runtime(db_session, boot=boot)

    menu = render_network_boot_menu(
        db_session,
        request_origin="http://198.51.100.20:8080",
    )

    assert (
        "kernel http://198.51.100.20:8080/pxe/media/inventory/"
        "2026.05.1/bzImage"
    ) in menu
    assert (
        "initrd http://198.51.100.20:8080/pxe/media/inventory/"
        "2026.05.1/rootfs.cpio.gz"
    ) in menu
    assert "http://192.0.2.10:8080/pxe/media/inventory" not in menu

    spoofed = render_network_boot_menu(
        db_session,
        request_origin="http://attacker.example:8080",
    )
    assert (
        "kernel http://192.0.2.10:8080/pxe/media/inventory/"
        "2026.05.1/bzImage"
    ) in spoofed
    assert "attacker.example" not in spoofed


def test_known_enabled_esxi_mac_becomes_timed_default(db_session):
    host = EsxiPxeHost(
        hostname="esx01.atlaso.internal",
        mac_address="52:54:00:12:34:56",
        installer_iso_path="/mnt/atlaso-vcf-offline-depot/PROD/COMP/ESX_HOST/esxi.iso",
        enabled=True,
    )
    db_session.add(host)
    db_session.commit()

    pending = render_network_boot_menu(
        db_session,
        mac_address="52:54:00:12:34:56",
    )
    assert "choose --timeout 10000 --default local" in pending

    boot = esxi_pxe_boot_settings(db_session)
    artifacts = esxi_pxe_host_artifacts(
        [host],
        boot,
        esxi_pxe_default_host_settings(db_session),
    )
    set_applied_pxe_runtime(db_session, boot=boot, artifacts=artifacts)
    menu = render_network_boot_menu(
        db_session,
        mac_address="52:54:00:12:34:56",
    )
    assert "choose --timeout 10000 --default esxi_assigned" in menu


@pytest.mark.parametrize(
    ("firmware", "expected_lines"),
    [
        (
            "efi",
            [
                "chain http://192.0.2.10:8080/pxe/esxi/"
                "01-52-54-00-12-34-56/mboot.efi || goto menu",
            ],
        ),
        (
            "pcbios",
            [
                "set 209:string pxelinux.cfg/01-52-54-00-12-34-56",
                "set 210:string tftp://${next-server}/",
                "chain tftp://${next-server}/pxelinux.0 || goto menu",
            ],
        ),
        (
            "",
            [
                "iseq ${platform} efi && goto esxi_assigned_uefi || "
                "goto esxi_assigned_bios",
                ":esxi_assigned_uefi",
                "chain http://192.0.2.10:8080/pxe/esxi/"
                "01-52-54-00-12-34-56/mboot.efi || goto menu",
                ":esxi_assigned_bios",
                "set 209:string pxelinux.cfg/01-52-54-00-12-34-56",
                "chain tftp://${next-server}/pxelinux.0 || goto menu",
            ],
        ),
    ],
)
def test_esxi_menu_executes_the_firmware_loader(
    db_session,
    firmware,
    expected_lines,
):
    host = EsxiPxeHost(
        hostname="esx01.atlaso.internal",
        mac_address="52:54:00:12:34:56",
        installer_iso_path=(
            "/mnt/atlaso-vcf-offline-depot/PROD/COMP/ESX_HOST/esxi.iso"
        ),
        enabled=True,
    )
    db_session.add(host)
    db_session.flush()
    boot = esxi_pxe_boot_settings(db_session)
    boot["listen_address"] = "192.0.2.10"
    boot["http_port"] = 8080
    artifacts = esxi_pxe_host_artifacts(
        [host],
        boot,
        esxi_pxe_default_host_settings(db_session),
    )
    set_applied_pxe_runtime(db_session, boot=boot, artifacts=artifacts)

    menu = render_network_boot_menu(
        db_session,
        mac_address=host.mac_address,
        firmware=firmware,
        request_origin="http://192.0.2.10:8080",
    )

    for expected in expected_lines:
        assert expected in menu
    assert "/boot.cfg || goto menu" not in menu


def test_known_esxi_host_can_claim_one_time_inventory_boot(db_session):
    states = {row.key: row for row in ensure_environment_rows(db_session)}
    inventory = record_verified_media(
        db_session,
        environment_key="inventory",
        version="2026.05.1",
        source_url="https://example.test/atlaso-inventory-linux.zip",
        artifact_sha256="a" * 64,
        installed_path="/var/lib/atlaso/pxe/media/inventory/2026.05.1",
        manifest={"boot": {"kernel": "/bzImage", "initrd": "/rootfs.cpio.gz"}},
    )
    states["inventory"].enabled = True
    states["inventory"].active_version = inventory.version
    host = EsxiPxeHost(
        hostname="esxi-utility-test",
        mac_address="52:54:00:12:34:56",
        installer_iso_path="/mnt/atlaso-vcf-offline-depot/PROD/COMP/ESX_HOST/esxi.iso",
        enabled=True,
    )
    db_session.add(host)
    db_session.flush()
    boot = esxi_pxe_boot_settings(db_session)
    artifacts = esxi_pxe_host_artifacts(
        [host],
        boot,
        esxi_pxe_default_host_settings(db_session),
    )
    set_applied_pxe_runtime(db_session, boot=boot, artifacts=artifacts)
    request_host_boot_override(
        db_session,
        host_id=host.id,
        mac_address=host.mac_address,
        environment_key="inventory",
        requested_by="admin",
    )
    db_session.commit()

    claimed = claim_host_boot_override(
        db_session,
        mac_address=host.mac_address,
    )
    menu = render_network_boot_menu(
        db_session,
        mac_address=host.mac_address,
        default_environment_key=claimed,
    )
    override = db_session.get(NetworkBootHostBootOverride, host.id)

    assert claimed == "inventory"
    assert override is not None
    assert override.claimed_at is not None
    assert "item esxi_assigned ESXi: esxi-utility-test" in menu
    assert "choose --timeout 10000 --default inventory" in menu
    assert (
        claim_host_boot_override(db_session, mac_address=host.mac_address)
        == "inventory"
    )


@pytest.mark.parametrize(
    ("environment", "source", "expected_version"),
    [
        (
            "memtest86plus",
            '<a href="/download/v8.10/mt86plus_8.10.binaries.zip">binaries</a>',
            "8.10",
        ),
        (
            "gparted",
            '<a href="gparted-live-1.8.1-3-amd64.iso">stable</a>',
            "1.8.1-3",
        ),
        (
            "clonezilla",
            (
                '<a href="?branch=alternative"><b>alternative stable</b> - '
                '<font>20260705-resolute</font></a>'
                '<a href="?branch=stable"><b>stable</b> - '
                '<font color=red>3.3.3-15</font></a>'
            ),
            "3.3.3-15",
        ),
    ],
)
def test_fixed_catalog_resolves_expected_stable_branch(
    monkeypatch,
    environment,
    source,
    expected_version,
):
    monkeypatch.setattr(
        "atlaso.app.services.network_boot._fetch_https_text",
        lambda *_args, **_kwargs: source,
    )
    assert _release_descriptor(environment)["version"] == expected_version


def test_available_network_boot_versions_cache_and_stale_fallback(monkeypatch):
    versions = {entry.key: f"version-{entry.key}" for entry in network_boot.ENVIRONMENT_CATALOG}

    def resolve(key):
        if key == "shredos":
            raise ValueError("source unavailable")
        return {"version": versions[key]}

    network_boot._AVAILABLE_VERSION_CACHE.clear()
    monkeypatch.setattr(network_boot, "_release_descriptor", resolve)
    try:
        first = {
            row["key"]: row
            for row in available_network_boot_versions(force_refresh=True)
        }
        assert first["inventory"]["available_version"] == "version-inventory"
        assert first["inventory"]["available_status"] == "current"
        assert first["shredos"]["available_version"] == ""
        assert first["shredos"]["available_status"] == "unavailable"

        monkeypatch.setattr(
            network_boot,
            "_release_descriptor",
            lambda _key: (_ for _ in ()).throw(OSError("offline")),
        )
        second = {
            row["key"]: row
            for row in available_network_boot_versions(force_refresh=True)
        }
        assert second["inventory"]["available_version"] == "version-inventory"
        assert second["inventory"]["available_status"] == "stale"
        assert second["inventory"]["available_checked_at"] == first["inventory"]["available_checked_at"]
        assert second["shredos"]["available_status"] == "unavailable"
    finally:
        network_boot._AVAILABLE_VERSION_CACHE.clear()


def test_shredos_requires_published_full_iso_digest(monkeypatch):
    payload = {
        "tag_name": "v2025.11_31_x86-64_0.42",
        "draft": False,
        "prerelease": False,
        "assets": [
            {
                "name": "shredos-2025.11_31_x86-64_v0.42_lite.iso",
                "browser_download_url": "https://github.com/example/shredos-lite.iso",
                "digest": "sha256:" + ("c" * 64),
            },
            {
                "name": "shredos-2025.11_31_x86-64_v0.42_plus-partition.iso",
                "browser_download_url": "https://github.com/example/shredos-plus.iso",
                "digest": "sha256:" + ("d" * 64),
            },
            {
                "name": "shredos-2025.11_31_x86-64_v0.42.iso",
                "browser_download_url": "https://github.com/example/shredos.iso",
                "digest": "sha256:" + ("a" * 64),
            }
        ],
    }
    monkeypatch.setattr(
        "atlaso.app.services.network_boot._fetch_https_text",
        lambda *_args, **_kwargs: json.dumps(payload),
    )
    descriptor = _release_descriptor("shredos")
    assert descriptor["sha256"] == "a" * 64
    assert descriptor["filename"] == "shredos-2025.11_31_x86-64_v0.42.iso"
    payload["assets"][2]["digest"] = ""
    with pytest.raises(ValueError, match="does not publish"):
        _release_descriptor("shredos")


def test_shredos_iso_extracts_only_allowlisted_kernel(tmp_path):
    archive = tmp_path / "shredos.iso"
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3, rock_ridge="1.09")
    iso.add_directory("/BOOT", rr_name="boot", joliet_path="/boot")
    kernel = b"verified ShredOS kernel"
    iso.add_fp(
        io.BytesIO(kernel),
        len(kernel),
        "/BOOT/BZIMAGE.;1",
        rr_name="bzImage",
        joliet_path="/boot/bzImage",
    )
    extra = b"must not be extracted"
    iso.add_fp(
        io.BytesIO(extra),
        len(extra),
        "/AUTONUKE.;1",
        rr_name="autonuke",
        joliet_path="/autonuke",
    )
    iso.write(str(archive))
    iso.close()
    destination = tmp_path / "install"
    destination.mkdir()

    assert _extract_shredos_kernel(archive, destination) == ["shredos"]
    assert (destination / "shredos").read_bytes() == kernel
    assert sorted(path.name for path in destination.iterdir()) == ["shredos"]


@pytest.mark.parametrize("mode", ["missing", "invalid"])
def test_shredos_iso_rejects_missing_or_invalid_kernel(tmp_path, mode):
    archive = tmp_path / "shredos.iso"
    if mode == "missing":
        iso = pycdlib.PyCdlib()
        iso.new(interchange_level=3, joliet=3, rock_ridge="1.09")
        content = b"not the kernel"
        iso.add_fp(
            io.BytesIO(content),
            len(content),
            "/README.;1",
            rr_name="README",
            joliet_path="/README",
        )
        iso.write(str(archive))
        iso.close()
        expected = "missing the /boot/bzImage kernel"
    else:
        archive.write_bytes(b"not an ISO")
        expected = "not a valid ISO image"
    destination = tmp_path / "install"
    destination.mkdir()

    with pytest.raises(ValueError, match=expected):
        _extract_shredos_kernel(archive, destination)


def test_inventory_linux_resolves_signed_dedicated_release_package(monkeypatch):
    payload = {
        "version": "2026.05.1+8",
        "package": {
            "name": "atlaso-inventory-linux-2026.05.1+8.zip",
            "url": "https://github.com/mdaneri/Atlaso/releases/download/inventory-linux-v2026.05.1%2B8/atlaso-inventory-linux-2026.05.1%2B8.zip",
            "size": 123,
            "sha256": "b" * 64,
        },
    }
    requests = []

    def fetch(url, **_kwargs):
        requests.append(url)
        return b"signed document" if url.endswith("manifest.json") else b"signature"

    monkeypatch.setattr(
        "atlaso.app.services.network_boot._fetch_https_bytes",
        fetch,
    )
    monkeypatch.setattr(
        "atlaso.app.services.network_boot.verify_signed_json",
        lambda raw, signature, *, document_kind: (
            payload
            if raw == b"signed document"
            and signature == b"signature"
            and document_kind == "inventory"
            else pytest.fail("unexpected signed manifest verification")
        ),
    )
    descriptor = _release_descriptor("inventory")
    assert descriptor["version"] == "2026.05.1+8"
    assert descriptor["sha256"] == "b" * 64
    assert requests == [
        "https://mdaneri.github.io/Atlaso/updates/inventory-linux/latest/manifest.json",
        "https://mdaneri.github.io/Atlaso/updates/inventory-linux/latest/manifest.json.sig",
    ]


def test_inventory_linux_missing_release_is_actionable(monkeypatch):
    def missing(url, **_kwargs):
        raise HTTPError(url, 404, "Not Found", {}, None)

    monkeypatch.setattr(network_boot, "_fetch_https_bytes", missing)
    with pytest.raises(ValueError, match="No Atlaso Inventory Linux release has been published"):
        _release_descriptor("inventory")


def test_inventory_linux_package_upload_installs_verified_immutable_media(
    db_session,
    monkeypatch,
    tmp_path,
):
    kernel = b"inventory kernel"
    initrd = b"inventory initramfs"
    source_manifest = {
        "kind": "atlaso-inventory-linux",
        "schema_version": 1,
        "environment": "inventory",
        "version": "2026.05.1",
        "boot": {
            "arguments": (
                "rdinit=/sbin/init console=tty0 quiet loglevel=3 "
                "vga=791 video=1024x768 fbcon=font:VGA8x16 "
                "atlaso.inventory=1"
            ),
        },
        "artifacts": {
            "bzImage": hashlib.sha256(kernel).hexdigest(),
            "rootfs.cpio.gz": hashlib.sha256(initrd).hexdigest(),
        },
    }
    package = tmp_path / "atlaso-inventory-linux-2026.05.1.zip"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("manifest.json", json.dumps(source_manifest))
        archive.writestr("bzImage", kernel)
        archive.writestr("rootfs.cpio.gz", initrd)
    package_digest = hashlib.sha256(package.read_bytes()).hexdigest()
    monkeypatch.setattr(
        network_boot,
        "_release_descriptor",
        lambda _key: {
            "version": "2026.05.1",
            "filename": package.name,
            "asset_url": "https://example.test/" + package.name,
            "sha256": package_digest,
        },
    )
    media_root = tmp_path / "media"
    environment_root = (media_root / "inventory").resolve()
    original_replace = Path.replace
    replacements = []

    def assert_same_filesystem_staging(source, target):
        replacements.append((source.resolve(), Path(target).resolve()))
        assert source.resolve().is_relative_to(environment_root)
        return original_replace(source, target)

    monkeypatch.setattr(Path, "replace", assert_same_filesystem_staging)

    media = sync_network_boot_media(
        db_session,
        environment_key="inventory",
        media_root=media_root,
        uploaded_artifact=package,
        uploaded_filename=package.name,
    )
    manifest = json.loads(media.manifest_json)

    assert manifest["boot"]["kernel"].endswith("/inventory/2026.05.1/bzImage")
    assert manifest["boot"]["arguments"] == source_manifest["boot"]["arguments"]
    chain = network_boot._chain_line(media, http_origin="http://192.0.2.10:8080")
    assert "vga=791" in chain
    assert "video=1024x768" in chain
    assert "fbcon=font:VGA8x16" in chain
    assert manifest["acquisition"] == "upload"
    assert (Path(media.installed_path) / "rootfs.cpio.gz").read_bytes() == initrd
    assert replacements


def test_inventory_linux_package_rejects_signed_size_mismatch(
    db_session,
    monkeypatch,
    tmp_path,
):
    kernel = b"inventory kernel"
    initrd = b"inventory initramfs"
    version = "2026.05.1+8"
    package = tmp_path / f"atlaso-inventory-linux-{version}.zip"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr(
            "manifest.json",
            json.dumps(
                {
                    "kind": "atlaso-inventory-linux",
                    "schema_version": 1,
                    "environment": "inventory",
                    "version": version,
                    "artifacts": {
                        "bzImage": hashlib.sha256(kernel).hexdigest(),
                        "rootfs.cpio.gz": hashlib.sha256(initrd).hexdigest(),
                    },
                }
            ),
        )
        archive.writestr("bzImage", kernel)
        archive.writestr("rootfs.cpio.gz", initrd)
    monkeypatch.setattr(
        network_boot,
        "_release_descriptor",
        lambda _key: {
            "version": version,
            "filename": package.name,
            "asset_url": "https://example.test/" + package.name,
            "sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
            "size": str(package.stat().st_size + 1),
        },
    )
    with pytest.raises(ValueError, match="verified size"):
        sync_network_boot_media(
            db_session,
            environment_key="inventory",
            media_root=tmp_path / "media",
            uploaded_artifact=package,
            uploaded_filename=package.name,
        )


def test_boot_media_archive_rejects_traversal(tmp_path):
    archive = tmp_path / "media.zip"
    with zipfile.ZipFile(archive, "w") as rows:
        rows.writestr("../escape", b"bad")
        rows.writestr("live/vmlinuz", b"kernel")
    with pytest.raises(ValueError, match="unsafe path"):
        _extract_zip_allowlist(
            archive,
            tmp_path / "extract",
            allowed_names={"live/vmlinuz": "vmlinuz"},
        )


def test_boot_media_downloader_rejects_https_downgrade_redirect():
    handler = _BoundedHttpsRedirectHandler(max_redirects=5)
    with pytest.raises(ValueError, match="redirected away from HTTPS"):
        handler.redirect_request(
            Request("https://example.test/media"),
            None,
            302,
            "Found",
            Message(),
            "http://example.test/media",
        )


def test_boot_media_downloader_rejects_declared_oversize(monkeypatch, tmp_path):
    class FakeResponse:
        headers = {"Content-Length": "11"}

        def geturl(self):
            return "https://example.test/media"

        def close(self):
            return None

    class FakeOpener:
        def open(self, *_args, **_kwargs):
            return FakeResponse()

    monkeypatch.setattr(
        "atlaso.app.services.network_boot.urllib.request.build_opener",
        lambda *_args: FakeOpener(),
    )
    with pytest.raises(ValueError, match="exceeds the size limit"):
        BoundedHttpsDownloader(max_bytes=10).download(
            "https://example.test/media",
            tmp_path / "media",
        )


def test_boot_media_downloader_retries_transient_open_failure(monkeypatch, tmp_path):
    class FakeResponse:
        headers = {"Content-Length": "5"}

        def geturl(self):
            return "https://mirror.example.test/media"

        def read(self, _size):
            if getattr(self, "_read", False):
                return b""
            self._read = True
            return b"media"

        def close(self):
            return None

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.close()

    attempts = 0

    class FakeOpener:
        def open(self, *_args, **_kwargs):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise URLError(ConnectionRefusedError())
            return FakeResponse()

    monkeypatch.setattr(
        "atlaso.app.services.network_boot.urllib.request.build_opener",
        lambda *_args: FakeOpener(),
    )
    monkeypatch.setattr(
        "atlaso.app.services.network_boot.time.sleep",
        lambda *_args: None,
    )

    final_url, digest = BoundedHttpsDownloader().download(
        "https://example.test/media",
        tmp_path / "media",
    )

    assert attempts == 2
    assert final_url == "https://mirror.example.test/media"
    assert digest == hashlib.sha256(b"media").hexdigest()


def test_checksum_filename_accepts_publisher_relative_path():
    digest = "a" * 64

    assert checksum_for_filename(
        f"{digest}  v8.10/mt86plus_8.10.binaries.zip",
        "mt86plus_8.10.binaries.zip",
    ) == digest


def test_bundled_inventory_registration_defers_active_version_until_apply(
    db_session,
    tmp_path,
):
    version = "2026.05.1"
    installed = tmp_path / "inventory" / version
    installed.mkdir(parents=True)
    artifacts = {
        "bzImage": b"inventory kernel",
        "rootfs.cpio.gz": b"inventory initramfs",
    }
    for filename, content in artifacts.items():
        (installed / filename).write_bytes(content)
    (installed / "manifest.json").write_text(
        json.dumps(
            {
                "kind": "atlaso-inventory-linux",
                "schema_version": 1,
                "version": version,
                "buildroot": {
                    "source": "https://buildroot.org/downloads/buildroot-2026.05.1.tar.xz"
                },
                "artifacts": {
                    filename: hashlib.sha256(content).hexdigest()
                    for filename, content in artifacts.items()
                },
            }
        ),
        encoding="utf-8",
    )

    media = register_bundled_inventory_media(db_session, media_root=tmp_path)
    state = {
        row.key: row for row in ensure_environment_rows(db_session)
    }["inventory"]

    assert media is not None
    assert state.enabled is True
    assert state.desired_version == version
    assert state.active_version == ""


def test_bundled_inventory_registration_records_and_selects_latest_revision(
    db_session,
    tmp_path,
):
    artifacts = {
        "bzImage": b"inventory kernel",
        "rootfs.cpio.gz": b"inventory initramfs",
    }
    for version in ("2026.05.1+9", "2026.05.1+10"):
        installed = tmp_path / "inventory" / version
        installed.mkdir(parents=True)
        for filename, content in artifacts.items():
            (installed / filename).write_bytes(content + version.encode())
        (installed / "manifest.json").write_text(
            json.dumps(
                {
                    "kind": "atlaso-inventory-linux",
                    "schema_version": 1,
                    "version": version,
                    "artifacts": {
                        filename: hashlib.sha256(
                            content + version.encode()
                        ).hexdigest()
                        for filename, content in artifacts.items()
                    },
                }
            ),
            encoding="utf-8",
        )

    latest = register_bundled_inventory_media(db_session, media_root=tmp_path)
    state = db_session.get(NetworkBootEnvironment, "inventory")
    registered = db_session.execute(
        select(NetworkBootMedia)
        .where(NetworkBootMedia.environment_key == "inventory")
        .order_by(NetworkBootMedia.version)
    ).scalars().all()

    assert latest is not None
    assert latest.version == "2026.05.1+10"
    assert [row.version for row in registered] == [
        "2026.05.1+10",
        "2026.05.1+9",
    ]
    assert state is not None
    assert state.desired_version == "2026.05.1+10"


def test_bundled_inventory_registration_preserves_explicit_reset_state(
    db_session,
    tmp_path,
):
    version = "2026.05.1"
    installed = tmp_path / "inventory" / version
    installed.mkdir(parents=True)
    artifacts = {
        "bzImage": b"inventory kernel",
        "rootfs.cpio.gz": b"inventory initramfs",
    }
    for filename, content in artifacts.items():
        (installed / filename).write_bytes(content)
    (installed / "manifest.json").write_text(
        json.dumps(
            {
                "kind": "atlaso-inventory-linux",
                "schema_version": 1,
                "version": version,
                "artifacts": {
                    filename: hashlib.sha256(content).hexdigest()
                    for filename, content in artifacts.items()
                },
            }
        ),
        encoding="utf-8",
    )
    assert register_bundled_inventory_media(db_session, media_root=tmp_path)
    state = db_session.get(NetworkBootEnvironment, "inventory")
    state.enabled = False
    state.desired_version = ""
    state.active_version = ""
    db_session.commit()

    assert register_bundled_inventory_media(db_session, media_root=tmp_path)

    assert state.enabled is False
    assert state.desired_version == ""
    assert state.active_version == ""


def test_failed_inventory_package_replacement_preserves_active_bundled_media(
    db_session,
    monkeypatch,
    tmp_path,
):
    version = "2026.05.1"
    installed = tmp_path / "inventory" / version
    installed.mkdir(parents=True)
    artifacts = {
        "bzImage": b"inventory kernel",
        "rootfs.cpio.gz": b"inventory initramfs",
    }
    for filename, content in artifacts.items():
        (installed / filename).write_bytes(content)
    (installed / "manifest.json").write_text(
        json.dumps(
            {
                "kind": "atlaso-inventory-linux",
                "schema_version": 1,
                "version": version,
                "buildroot": {"source": "https://example.test/buildroot.tar.xz"},
                "artifacts": {
                    filename: hashlib.sha256(content).hexdigest()
                    for filename, content in artifacts.items()
                },
            }
        ),
        encoding="utf-8",
    )
    media = register_bundled_inventory_media(db_session, media_root=tmp_path)
    state = {
        row.key: row for row in ensure_environment_rows(db_session)
    }["inventory"]
    state.active_version = version
    db_session.commit()
    monkeypatch.setattr(
        network_boot,
        "_release_descriptor",
        lambda _key: {
            "version": version,
            "filename": f"atlaso-inventory-linux-{version}.zip",
            "asset_url": "https://example.test/atlaso-inventory-linux.zip",
            "sha256": "f" * 64,
        },
    )

    def fail_download(*_args, **_kwargs):
        raise ValueError("simulated acquisition failure")

    monkeypatch.setattr(BoundedHttpsDownloader, "download", fail_download)

    with pytest.raises(ValueError, match="simulated acquisition failure"):
        sync_network_boot_media(
            db_session,
            environment_key="inventory",
            media_root=tmp_path,
        )

    assert media is not None
    assert db_session.get(NetworkBootMedia, media.id) is not None
    assert (installed / "bzImage").read_bytes() == artifacts["bzImage"]
    assert (installed / "rootfs.cpio.gz").read_bytes() == artifacts["rootfs.cpio.gz"]


def test_cancelled_media_worker_cannot_overwrite_terminal_status(
    db_session,
    monkeypatch,
    tmp_path,
):
    from atlaso.app import worker

    media = record_verified_media(
        db_session,
        environment_key="shredos",
        version="2025.11",
        source_url="https://example.test/shredos.iso",
        artifact_sha256="a" * 64,
        installed_path="/var/lib/atlaso/pxe/media/shredos/2025.11",
        manifest={"schema_version": 1},
    )
    job = Job(
        id="job_" + ("b" * 32),
        type="pxe-media-sync",
        status=JobStatus.RUNNING.value,
        created_by="admin",
        task_config_json=json.dumps(
            {"environment": "shredos", "source": "download"}
        ),
    )
    db_session.add(job)
    db_session.commit()

    final_dir = tmp_path / "installed"
    backup_dir = tmp_path / "backup"
    final_dir.mkdir()
    backup_dir.mkdir()
    (final_dir / "shredos").write_bytes(b"replacement")
    (backup_dir / "shredos").write_bytes(b"original")
    filesystem_sync = network_boot.DeferredNetworkBootMediaSync(
        media=media,
        final_dir=final_dir,
        backup_dir=backup_dir,
    )

    def cancel_during_sync(*_args, cancelled, **_kwargs):
        job.status = JobStatus.CANCELLED.value
        db_session.add(job)
        db_session.commit()
        assert cancelled() is True
        return filesystem_sync

    monkeypatch.setattr(network_boot, "sync_network_boot_media", cancel_during_sync)

    with pytest.raises(NetworkBootMediaSyncCancelled):
        worker._run_pxe_media_sync(db_session, job)

    db_session.refresh(job)
    assert job.status == JobStatus.CANCELLED.value
    assert not db_session.execute(
        select(AuditEvent).where(
            AuditEvent.action == "sync_network_boot_media",
            AuditEvent.resource_id == f"shredos:{media.version}",
        )
    ).scalars().all()
    assert (final_dir / "shredos").read_bytes() == b"original"
    assert not backup_dir.exists()


def test_deferred_unchanged_media_rollback_preserves_installed_files(
    db_session,
    tmp_path,
):
    installed = tmp_path / "installed"
    installed.mkdir()
    artifact = installed / "shredos"
    artifact.write_bytes(b"verified")
    media = record_verified_media(
        db_session,
        environment_key="shredos",
        version="2025.11",
        source_url="https://example.test/shredos.iso",
        artifact_sha256="a" * 64,
        installed_path=str(installed),
        manifest={"schema_version": 1},
    )
    filesystem_sync = network_boot.DeferredNetworkBootMediaSync(
        media=media,
        final_dir=installed,
        backup_dir=None,
        filesystem_changed=False,
    )

    filesystem_sync.rollback_filesystem()

    assert artifact.read_bytes() == b"verified"


def test_signed_checksum_rejects_wrong_fingerprint(monkeypatch, tmp_path):
    files = []
    for name in ("checksums", "signature", "key"):
        path = tmp_path / name
        path.write_text(name, encoding="utf-8")
        files.append(path)
    monkeypatch.setattr(
        "atlaso.app.services.network_boot.shutil.which",
        lambda command: "/usr/bin/gpg" if command == "gpg" else None,
    )
    results = iter(
        [
            CompletedProcess(["gpg"], 0, "", ""),
            CompletedProcess(
                ["gpg"],
                0,
                "[GNUPG:] VALIDSIG " + ("B" * 40) + " 2026-07-29\n",
                "",
            ),
        ]
    )
    monkeypatch.setattr(
        "atlaso.app.services.network_boot.subprocess.run",
        lambda *_args, **_kwargs: next(results),
    )
    with pytest.raises(ValueError, match="did not match the pinned"):
        verify_signed_checksum(
            files[0],
            files[1],
            files[2],
            fingerprint="A" * 40,
        )


def test_inventory_linux_build_enables_reproducible_mode():
    repository_root = Path(__file__).resolve().parents[1]
    defconfig = (
        repository_root
        / "image"
        / "inventory-linux"
        / "external"
        / "configs"
        / "atlaso_inventory_x86_64_defconfig"
    ).read_text(encoding="utf-8")
    build_script = (
        repository_root / "image" / "inventory-linux" / "build.sh"
    ).read_text(encoding="utf-8")

    assert "BR2_REPRODUCIBLE=y" in defconfig
    assert 'export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-${source_date_epoch}}"' in (
        build_script
    )


def test_installed_media_paths_are_selected_only_from_fixed_environment_root(
    monkeypatch,
    tmp_path,
):
    environment_root = tmp_path / "memtest86plus"
    installed = environment_root / "8.10"
    installed.mkdir(parents=True)
    media = NetworkBootMedia(
        environment_key="memtest86plus",
        version="8.10",
        installed_path=str(installed.resolve()),
    )
    monkeypatch.setitem(
        _MEDIA_ENVIRONMENT_ROOTS,
        "memtest86plus",
        environment_root.resolve(),
    )

    assert _installed_media_directory(media) == installed.resolve()
    replacement = environment_root / ("8.10.sha256-" + ("a" * 12))
    replacement.mkdir()
    media.installed_path = str(replacement.resolve())
    assert _installed_media_directory(media) == replacement.resolve()
    media.installed_path = str((tmp_path / "outside" / "8.10").resolve())
    assert _installed_media_directory(media) is None


def test_media_file_selection_uses_allowlist_without_following_symlinks(tmp_path):
    root = tmp_path / "media"
    nested = root / "live"
    nested.mkdir(parents=True)
    kernel = nested / "vmlinuz"
    kernel.write_bytes(b"kernel")

    assert _allowlisted_media_file(root, "live/vmlinuz", {"live/vmlinuz"}) == (
        kernel.resolve()
    )
    assert _allowlisted_media_file(root, "../vmlinuz", {"../vmlinuz"}) is None

    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    symlink = nested / "outside"
    try:
        symlink.symlink_to(outside)
    except OSError:
        return
    assert _allowlisted_media_file(root, "live/outside", {"live/outside"}) is None


def _write_test_media_cache(
    directory: Path,
    *,
    environment: str,
    version: str,
    content: bytes,
    artifact_sha256: str,
) -> None:
    directory.mkdir(parents=True)
    artifact = directory / "artifact.bin"
    artifact.write_bytes(content)
    (directory / "manifest.json").write_text(
        json.dumps(
            {
                "kind": "atlaso-network-boot-media",
                "schema_version": 1,
                "environment": environment,
                "version": version,
                "sha256": artifact_sha256,
                "artifacts": {
                    "artifact.bin": hashlib.sha256(content).hexdigest(),
                },
            }
        ),
        encoding="utf-8",
    )


def test_interrupted_media_swap_recovery_restores_database_version(
    db_session,
    monkeypatch,
    tmp_path,
):
    media_root = tmp_path / "media"
    environment = "memtest86plus"
    version = "2025.11"
    transaction_id = "a" * 32
    environment_root = media_root / environment
    final_dir = environment_root / version
    backup_dir = environment_root / f".{version}.replacement-{transaction_id}"
    staging_dir = (
        environment_root
        / f".atlaso-{environment}-{transaction_id}-staging"
    )
    old_sha256 = "a" * 64
    _write_test_media_cache(
        final_dir,
        environment=environment,
        version=version,
        content=b"uncommitted replacement",
        artifact_sha256="b" * 64,
    )
    _write_test_media_cache(
        backup_dir,
        environment=environment,
        version=version,
        content=b"committed media",
        artifact_sha256=old_sha256,
    )
    staging_dir.mkdir()
    (staging_dir / "source.img").write_bytes(b"interrupted source artifact")
    record_verified_media(
        db_session,
        environment_key=environment,
        version=version,
        source_url="https://example.test/shredos.iso",
        artifact_sha256=old_sha256,
        installed_path=str(final_dir.resolve()),
        manifest={"schema_version": 1},
    )
    db_session.commit()
    journal = environment_root / f".atlaso-media-sync-{transaction_id}.json"
    journal.write_text(
        json.dumps(
            {
                "environment": environment,
                "staging_directory": staging_dir.name,
                "version": version,
            }
        ),
        encoding="utf-8",
    )
    synced_directories: list[Path] = []
    monkeypatch.setattr(
        network_boot,
        "_fsync_directory",
        lambda directory: synced_directories.append(directory),
    )

    assert network_boot.recover_interrupted_network_boot_media_swaps(
        db_session,
        media_root=media_root,
    ) == 1

    assert (final_dir / "artifact.bin").read_bytes() == b"committed media"
    assert not backup_dir.exists()
    assert not staging_dir.exists()
    assert not journal.exists()
    assert synced_directories == [environment_root, environment_root]


def test_interrupted_media_swap_recovery_finalizes_committed_version(
    db_session,
    tmp_path,
):
    media_root = tmp_path / "media"
    environment = "memtest86plus"
    version = "2025.11"
    transaction_id = "b" * 32
    environment_root = media_root / environment
    final_dir = environment_root / version
    backup_dir = environment_root / f".{version}.replacement-{transaction_id}"
    committed_sha256 = "b" * 64
    _write_test_media_cache(
        final_dir,
        environment=environment,
        version=version,
        content=b"committed replacement",
        artifact_sha256=committed_sha256,
    )
    _write_test_media_cache(
        backup_dir,
        environment=environment,
        version=version,
        content=b"old media",
        artifact_sha256="a" * 64,
    )
    record_verified_media(
        db_session,
        environment_key=environment,
        version=version,
        source_url="https://example.test/shredos.iso",
        artifact_sha256=committed_sha256,
        installed_path=str(final_dir.resolve()),
        manifest={"schema_version": 1},
    )
    db_session.commit()
    journal = environment_root / f".atlaso-media-sync-{transaction_id}.json"
    journal.write_text(
        json.dumps({"environment": environment, "version": version}),
        encoding="utf-8",
    )

    assert network_boot.recover_interrupted_network_boot_media_swaps(
        db_session,
        media_root=media_root,
    ) == 1

    assert (final_dir / "artifact.bin").read_bytes() == b"committed replacement"
    assert not backup_dir.exists()
    assert not journal.exists()


def test_recovery_removes_uncommitted_digest_directory_for_valid_old_row(
    db_session,
    tmp_path,
):
    media_root = tmp_path / "media"
    environment = "memtest86plus"
    version = "2025.11"
    transaction_id = "f" * 32
    environment_root = media_root / environment
    applied_dir = environment_root / version
    replacement_dir = environment_root / (
        f"{version}.sha256-{'b' * 12}-{'c' * 12}"
    )
    _write_test_media_cache(
        applied_dir,
        environment=environment,
        version=version,
        content=b"applied media",
        artifact_sha256="a" * 64,
    )
    _write_test_media_cache(
        replacement_dir,
        environment=environment,
        version=version,
        content=b"uncommitted replacement",
        artifact_sha256="b" * 64,
    )
    record_verified_media(
        db_session,
        environment_key=environment,
        version=version,
        source_url="https://example.test/memtest.zip",
        artifact_sha256="a" * 64,
        installed_path=str(applied_dir.resolve()),
        manifest={"schema_version": 1},
    )
    db_session.commit()
    journal = environment_root / f".atlaso-media-sync-{transaction_id}.json"
    journal.write_text(
        json.dumps(
            {
                "environment": environment,
                "final_directory": replacement_dir.name,
                "version": version,
            }
        ),
        encoding="utf-8",
    )

    assert network_boot.recover_interrupted_network_boot_media_swaps(
        db_session,
        media_root=media_root,
    ) == 1

    assert (applied_dir / "artifact.bin").read_bytes() == b"applied media"
    assert not replacement_dir.exists()
    assert not journal.exists()


def test_interrupted_new_media_install_recovery_removes_uncommitted_version(
    db_session,
    tmp_path,
):
    media_root = tmp_path / "media"
    environment = "memtest86plus"
    version = "2025.12"
    transaction_id = "c" * 32
    environment_root = media_root / environment
    final_dir = environment_root / version
    _write_test_media_cache(
        final_dir,
        environment=environment,
        version=version,
        content=b"uncommitted new media",
        artifact_sha256="c" * 64,
    )
    journal = environment_root / f".atlaso-media-sync-{transaction_id}.json"
    journal.write_text(
        json.dumps({"environment": environment, "version": version}),
        encoding="utf-8",
    )

    assert network_boot.recover_interrupted_network_boot_media_swaps(
        db_session,
        media_root=media_root,
    ) == 1

    assert not final_dir.exists()
    assert not journal.exists()


def test_application_startup_recovers_media_swaps_before_registering_or_serving(
    client,
    monkeypatch,
):
    from starlette.testclient import TestClient

    from atlaso.app import main

    calls: list[str] = []
    original_register = main.register_bundled_inventory_media

    def recover(_db):
        calls.append("recover")
        return 0

    def register(db, *args, **kwargs):
        calls.append("register")
        return original_register(db, *args, **kwargs)

    monkeypatch.setattr(
        main,
        "recover_interrupted_network_boot_media_swaps",
        recover,
    )
    monkeypatch.setattr(main, "register_bundled_inventory_media", register)

    with TestClient(main.create_app()) as restarted_client:
        assert calls[:2] == ["recover", "register"]
        assert restarted_client.get("/openapi.json").status_code == 200


def test_media_swap_recovery_lock_serializes_callers(tmp_path):
    from threading import Event, Thread

    media_root = tmp_path / "media"
    media_root.mkdir()
    first_acquired = Event()
    release_first = Event()
    second_acquired = Event()

    def first_caller():
        with network_boot._MediaSwapRecoveryLock(media_root):
            first_acquired.set()
            assert release_first.wait(timeout=2)

    def second_caller():
        assert first_acquired.wait(timeout=2)
        with network_boot._MediaSwapRecoveryLock(media_root):
            second_acquired.set()

    first = Thread(target=first_caller)
    second = Thread(target=second_caller)
    first.start()
    assert first_acquired.wait(timeout=2)
    second.start()
    assert not second_acquired.wait(timeout=0.1)
    release_first.set()
    first.join(timeout=2)
    second.join(timeout=2)

    assert not first.is_alive()
    assert not second.is_alive()
    assert second_acquired.is_set()


def test_media_recovery_sweeps_only_inactive_prejournal_staging(
    db_session,
    tmp_path,
):
    media_root = tmp_path / "media"
    environment_root = media_root / "shredos"
    environment_root.mkdir(parents=True)
    transaction_id = "d" * 32
    staging = (
        environment_root
        / f".atlaso-shredos-{transaction_id}-prejournal"
    )
    staging.mkdir()

    with network_boot._MediaStagingLease(staging):
        (staging / "source.img").write_bytes(b"in-progress acquisition")
        assert network_boot.recover_interrupted_network_boot_media_swaps(
            db_session,
            media_root=media_root,
        ) == 0
        assert staging.exists()

    assert network_boot.recover_interrupted_network_boot_media_swaps(
        db_session,
        media_root=media_root,
    ) == 0
    assert not staging.exists()


def test_media_staging_lease_serializes_marker_publication_with_recovery(
    monkeypatch,
    tmp_path,
):
    media_root = tmp_path / "media"
    environment_root = media_root / "shredos"
    environment_root.mkdir(parents=True)
    staging = environment_root / f".atlaso-shredos-{'e' * 32}-prejournal"
    staging.mkdir()
    events: list[str] = []
    original_open = network_boot.os.open

    class RecordingLock:
        def __init__(self, root):
            assert root == media_root

        def acquire(self):
            events.append("recovery-lock:acquire")

        def release(self):
            events.append("recovery-lock:release")

    def recording_open(path, flags, mode=0o777):
        if Path(path).name == ".atlaso-staging.lock":
            assert events == ["recovery-lock:acquire"]
            events.append("staging-marker:open")
        return original_open(path, flags, mode)

    monkeypatch.setattr(network_boot, "_MediaSwapRecoveryLock", RecordingLock)
    monkeypatch.setattr(network_boot.os, "open", recording_open)

    with network_boot._MediaStagingLease(staging):
        assert events == [
            "recovery-lock:acquire",
            "staging-marker:open",
            "recovery-lock:release",
        ]


def test_media_sync_fsyncs_tree_and_published_directory_before_database_record(
    db_session,
    monkeypatch,
    tmp_path,
):
    media_root = tmp_path / "media"
    media_root.mkdir()
    content = b"durable replacement"
    digest = hashlib.sha256(content).hexdigest()
    events: list[str] = []
    original_record = network_boot.record_verified_media
    original_commit = db_session.commit
    use_test_shredos_extractor(monkeypatch)

    class RecordingLock:
        def __init__(self, _media_root):
            self.held = False

        def acquire(self):
            self.held = True
            events.append("lock:acquire")

        def release(self):
            assert self.held
            events.append("lock:release")
            self.held = False

    monkeypatch.setattr(
        network_boot,
        "_release_descriptor",
        lambda _key: {
            "version": "2025.11",
            "filename": "shredos.iso",
            "asset_url": "https://example.test/shredos.iso",
            "sha256": digest,
        },
    )

    def fake_download(_self, url, destination, **_kwargs):
        destination.write_bytes(content)
        return url, digest

    def record(db, **kwargs):
        events.append("record")
        return original_record(db, **kwargs)

    def commit():
        events.append("commit")
        return original_commit()

    monkeypatch.setattr(BoundedHttpsDownloader, "download", fake_download)
    monkeypatch.setattr(
        network_boot,
        "_fsync_media_tree",
        lambda _root: events.append("tree"),
    )
    monkeypatch.setattr(
        network_boot,
        "_fsync_directory",
        lambda root: events.append(f"directory:{root.name}"),
    )
    monkeypatch.setattr(network_boot, "_MediaSwapRecoveryLock", RecordingLock)
    monkeypatch.setattr(network_boot, "record_verified_media", record)
    monkeypatch.setattr(db_session, "commit", commit)

    synced = sync_network_boot_media(
        db_session,
        environment_key="shredos",
        media_root=media_root,
    )

    assert synced.version == "2025.11"
    tree_index = events.index("tree")
    lock_indices = [
        index for index, event in enumerate(events)
        if event == "lock:acquire"
    ]
    assert len(lock_indices) == 2
    lock_index = lock_indices[-1]
    record_index = events.index("record")
    commit_index = events.index("commit")
    assert events[0] == "directory:media"
    staging_directory_index = next(
        index for index, event in enumerate(events)
        if event.startswith("directory:.atlaso-shredos-")
    )
    first_release_index = events.index("lock:release")
    assert lock_indices[0] < staging_directory_index < first_release_index
    assert tree_index < lock_index < record_index < commit_index
    assert events[lock_index:record_index].count("directory:shredos") == 2
    assert events[-1] == "lock:release"


def test_media_sync_revalidates_and_repairs_corrupt_cached_artifacts(
    db_session,
    monkeypatch,
    tmp_path,
):
    media_root = tmp_path / "media"
    installed = media_root / "shredos" / "2025.11"
    installed.mkdir(parents=True)
    artifact = installed / "shredos"
    artifact.write_bytes(b"original")
    boot_script = installed / "boot.ipxe"
    boot_script.write_text("#!ipxe\n", encoding="utf-8")
    manifest = {
        "kind": "atlaso-network-boot-media",
        "schema_version": 1,
        "environment": "shredos",
        "version": "2025.11",
        "sha256": "a" * 64,
        "artifacts": {
            "shredos": hashlib.sha256(b"original").hexdigest(),
            "boot.ipxe": hashlib.sha256(b"#!ipxe\n").hexdigest(),
        },
    }
    (installed / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    record_verified_media(
        db_session,
        environment_key="shredos",
        version="2025.11",
        source_url="https://example.test/shredos.iso",
        artifact_sha256="a" * 64,
        installed_path=str(installed.resolve()),
        manifest=manifest,
    )
    db_session.commit()
    artifact.write_bytes(b"corrupt")

    replacement = b"replacement"
    replacement_sha256 = hashlib.sha256(replacement).hexdigest()
    monkeypatch.setattr(
        network_boot,
        "_release_descriptor",
        lambda _key: {
            "version": "2025.11",
            "filename": "shredos.iso",
            "asset_url": "https://example.test/shredos.iso",
            "sha256": replacement_sha256,
        },
    )

    def fake_download(_self, url, destination, **_kwargs):
        destination.write_bytes(replacement)
        return url, replacement_sha256

    monkeypatch.setattr(BoundedHttpsDownloader, "download", fake_download)
    use_test_shredos_extractor(monkeypatch)
    deferred = sync_network_boot_media(
        db_session,
        environment_key="shredos",
        media_root=media_root,
        defer_filesystem_commit=True,
    )

    assert isinstance(deferred, network_boot.DeferredNetworkBootMediaSync)
    assert deferred.media.artifact_sha256 == replacement_sha256
    assert deferred.journal_path is not None
    assert deferred.journal_path.exists()
    assert (installed / "shredos").read_bytes() == replacement
    deferred.rollback_filesystem()
    db_session.rollback()
    assert not deferred.journal_path.exists()
    assert (installed / "shredos").read_bytes() == b"corrupt"

    repaired = sync_network_boot_media(
        db_session,
        environment_key="shredos",
        media_root=media_root,
    )
    assert repaired.artifact_sha256 == replacement_sha256
    assert (installed / "shredos").read_bytes() == replacement


def test_media_sync_replaces_verified_legacy_shredos_image_cache(
    db_session,
    monkeypatch,
    tmp_path,
):
    media_root = tmp_path / "media"
    installed = media_root / "shredos" / "2025.11"
    installed.mkdir(parents=True)
    legacy_image = installed / "shredos.img"
    legacy_image.write_bytes(b"legacy raw image")
    legacy_script = installed / "boot.ipxe"
    legacy_script.write_text(
        "#!ipxe\n"
        "sanboot --no-describe /pxe/media/shredos/2025.11/shredos.img || exit\n",
        encoding="utf-8",
    )
    legacy_manifest = {
        "kind": "atlaso-network-boot-media",
        "schema_version": 1,
        "environment": "shredos",
        "version": "2025.11",
        "sha256": "a" * 64,
        "artifacts": {
            "shredos.img": hashlib.sha256(legacy_image.read_bytes()).hexdigest(),
            "boot.ipxe": hashlib.sha256(legacy_script.read_bytes()).hexdigest(),
        },
    }
    (installed / "manifest.json").write_text(
        json.dumps(legacy_manifest),
        encoding="utf-8",
    )
    existing = record_verified_media(
        db_session,
        environment_key="shredos",
        version="2025.11",
        source_url="https://example.test/shredos.img",
        artifact_sha256="a" * 64,
        installed_path=str(installed.resolve()),
        manifest=legacy_manifest,
    )
    state = db_session.get(NetworkBootEnvironment, "shredos")
    assert state is not None
    state.enabled = True
    state.desired_version = "2025.11"
    state.active_version = "2025.11"
    db_session.commit()
    set_applied_pxe_runtime(
        db_session,
        environments=[
            {
                "key": "shredos",
                "enabled": True,
                "desired_version": "2025.11",
                "installed_path": str(installed.resolve()),
                "artifact_sha256": existing.artifact_sha256,
                "manifest": legacy_manifest,
            }
        ],
    )

    replacement = b"verified ISO"
    replacement_sha256 = hashlib.sha256(replacement).hexdigest()
    monkeypatch.setattr(
        network_boot,
        "_release_descriptor",
        lambda _key: {
            "version": "2025.11",
            "filename": "shredos.iso",
            "asset_url": "https://example.test/shredos.iso",
            "sha256": replacement_sha256,
        },
    )

    def fake_download(_self, url, destination, **_kwargs):
        destination.write_bytes(replacement)
        return url, replacement_sha256

    monkeypatch.setattr(BoundedHttpsDownloader, "download", fake_download)
    use_test_shredos_extractor(monkeypatch)

    media = sync_network_boot_media(
        db_session,
        environment_key="shredos",
        media_root=media_root,
    )
    manifest = json.loads(media.manifest_json)
    replacement_directory = Path(media.installed_path)

    assert re.fullmatch(
        rf"2025\.11\.sha256-{replacement_sha256[:12]}-[0-9a-f]{{12}}",
        replacement_directory.name,
    )
    assert (installed / "shredos.img").read_bytes() == b"legacy raw image"
    assert legacy_script.read_text(encoding="utf-8").startswith(
        "#!ipxe\nsanboot "
    )
    assert (replacement_directory / "shredos").read_bytes() == replacement
    assert (replacement_directory / "boot.ipxe").read_text(encoding="utf-8") == (
        "#!ipxe\n"
        f"kernel /pxe/media/shredos/{replacement_directory.name}/shredos "
        "console=tty3 loglevel=3 || exit\n"
        "boot || exit\n"
    )
    assert sorted(manifest["artifacts"]) == ["boot.ipxe", "shredos"]
    assert manifest["boot"]["script"] == (
        f"/pxe/media/shredos/{replacement_directory.name}/boot.ipxe"
    )

    active = network_boot.active_network_boot_media(
        db_session,
        environment_key="shredos",
    )
    assert active is not None
    assert active.installed_path == str(installed.resolve())
    assert json.loads(active.manifest_json)["artifacts"] == legacy_manifest["artifacts"]

    (replacement_directory / "shredos").write_bytes(b"corrupt before apply")
    repaired_pending = sync_network_boot_media(
        db_session,
        environment_key="shredos",
        media_root=media_root,
    )
    pending_replacement_directory = Path(repaired_pending.installed_path)
    pending_manifest = json.loads(repaired_pending.manifest_json)

    assert pending_replacement_directory != replacement_directory
    assert not replacement_directory.exists()
    assert (pending_replacement_directory / "shredos").read_bytes() == replacement
    active = network_boot.active_network_boot_media(
        db_session,
        environment_key="shredos",
    )
    assert active is not None
    assert active.installed_path == str(installed.resolve())

    media = repaired_pending
    manifest = pending_manifest
    replacement_directory = pending_replacement_directory
    set_applied_pxe_runtime(
        db_session,
        environments=[
            {
                "key": "shredos",
                "enabled": True,
                "desired_version": "2025.11",
                "installed_path": media.installed_path,
                "artifact_sha256": media.artifact_sha256,
                "manifest": manifest,
            }
        ],
    )
    active = network_boot.active_network_boot_media(
        db_session,
        environment_key="shredos",
    )
    assert active is not None
    assert active.installed_path == media.installed_path
    menu = render_network_boot_menu(db_session)
    assert (
        f"/pxe/media/shredos/{replacement_directory.name}/boot.ipxe"
        in menu
    )
    assert "/pxe/media/shredos/2025.11/boot.ipxe" not in menu

    (replacement_directory / "shredos").write_bytes(b"corrupt after apply")
    repaired_again = sync_network_boot_media(
        db_session,
        environment_key="shredos",
        media_root=media_root,
    )
    repeated_directory = Path(repaired_again.installed_path)

    assert repeated_directory != replacement_directory
    assert re.fullmatch(
        rf"2025\.11\.sha256-{replacement_sha256[:12]}-[0-9a-f]{{12}}",
        repeated_directory.name,
    )
    assert (repeated_directory / "shredos").read_bytes() == replacement
    active = network_boot.active_network_boot_media(
        db_session,
        environment_key="shredos",
    )
    assert active is not None
    assert active.installed_path == str(replacement_directory.resolve())


def test_media_sync_verifies_uploaded_artifact_without_downloading_it(
    db_session,
    monkeypatch,
    tmp_path,
):
    uploaded = tmp_path / "uploaded.iso"
    uploaded.write_bytes(b"operator supplied asset")
    digest = hashlib.sha256(uploaded.read_bytes()).hexdigest()
    monkeypatch.setattr(
        network_boot,
        "_release_descriptor",
        lambda _key: {
            "version": "2025.12",
            "filename": "shredos.iso",
            "asset_url": "https://example.test/shredos.iso",
            "sha256": digest,
        },
    )

    def reject_download(*_args, **_kwargs):
        raise AssertionError("The uploaded release asset must not be downloaded again.")

    monkeypatch.setattr(BoundedHttpsDownloader, "download", reject_download)
    use_test_shredos_extractor(monkeypatch)
    media = sync_network_boot_media(
        db_session,
        environment_key="shredos",
        media_root=tmp_path / "media",
        uploaded_artifact=uploaded,
        uploaded_filename="local-copy.iso",
    )
    manifest = json.loads(media.manifest_json)

    assert media.artifact_sha256 == digest
    assert manifest["acquisition"] == "upload"
    assert manifest["uploaded_filename"] == "local-copy.iso"
    assert manifest["boot"]["script"].endswith("/boot.ipxe")
    assert sorted(manifest["artifacts"]) == ["boot.ipxe", "shredos"]


def test_network_boot_upload_path_rejects_untrusted_job_identifiers(tmp_path):
    valid = "job_" + ("a" * 32)
    assert network_boot_upload_path(valid, upload_root=tmp_path) == (
        tmp_path.resolve() / valid / "artifact"
    )
    with pytest.raises(ValueError, match="identifier is invalid"):
        network_boot_upload_path("../../escape", upload_root=tmp_path)


def test_cancelling_pending_media_upload_removes_staged_artifact(
    client,
    db_session,
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(network_boot, "NETWORK_BOOT_UPLOAD_ROOT", tmp_path)
    job = Job(
        id="job_" + ("c" * 32),
        type="pxe-media-sync",
        status=JobStatus.PENDING.value,
        created_by="admin",
        task_config_json=json.dumps(
            {"environment": "inventory", "source": "upload"}
        ),
    )
    upload_path = network_boot_upload_path(job.id)
    upload_path.parent.mkdir(parents=True)
    upload_path.write_bytes(b"staged package")
    db_session.add(job)
    db_session.commit()
    token = create_api_token(client, ["admin:all"])

    response = client.post(
        f"/api/v1/jobs/{job.id}/cancel",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == JobStatus.CANCELLED.value
    assert not upload_path.exists()
    assert not upload_path.parent.exists()


def test_ui_cancelling_pending_media_upload_removes_staged_artifact(
    client,
    db_session,
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(network_boot, "NETWORK_BOOT_UPLOAD_ROOT", tmp_path)
    job = Job(
        id="job_" + ("d" * 32),
        type="pxe-media-sync",
        status=JobStatus.PENDING.value,
        created_by="admin",
        task_config_json=json.dumps(
            {"environment": "inventory", "source": "upload"}
        ),
    )
    upload_path = network_boot_upload_path(job.id)
    upload_path.parent.mkdir(parents=True)
    upload_path.write_bytes(b"staged package")
    db_session.add(job)
    db_session.commit()
    csrf = login_session(client)

    response = client.post(
        f"/tasks/{job.id}/cancel",
        data={"csrf": csrf},
    )

    assert response.status_code == 200, response.text
    assert response.json()["task"]["status"] == JobStatus.CANCELLED.value
    assert not upload_path.exists()
    assert not upload_path.parent.exists()
