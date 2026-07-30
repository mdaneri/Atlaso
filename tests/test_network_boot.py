import hashlib
import json
import time
import zipfile
from collections import deque
from datetime import timedelta
from email.message import Message
from pathlib import Path
from subprocess import CompletedProcess
from urllib.error import URLError
from urllib.request import Request

import pytest
from sqlalchemy import select
from starlette.requests import Request as StarletteRequest

import atlaso.app.services.network_boot as network_boot
import atlaso.app.api.network_boot as network_boot_api
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
    _extract_zip_allowlist,
    _BoundedHttpsRedirectHandler,
    _release_descriptor,
    BoundedHttpsDownloader,
    checksum_for_filename,
    NetworkBootMediaSyncCancelled,
    NETWORK_BOOT_MAX_DISKS,
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
    verify_signed_checksum,
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


def set_applied_pxe_runtime(db_session, *, boot=None, artifacts=None):
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
            "Atlaso GitHub releases",
            "https://github.com/mdaneri/Atlaso/releases/latest",
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

    promotion = client.post(
        f"/api/v1/network-boot/hosts/{host_id}/promote",
        headers=api_headers,
        json={
            "hostname": "esxi-inventory-01",
            "mac_address": "52:54:00:12:34:56",
            "ip_address": "192.0.2.10",
            "kickstart_id": None,
            "installer_iso_path": "",
            "variables": {},
            "enabled": False,
        },
    )
    assert promotion.status_code == 201, promotion.text

    from atlaso.app.database import SessionLocal

    with SessionLocal() as db:
        assert db.get(Job, sync.json()["job_id"]) is not None
        assert db.get(NetworkBootInventoryCommand, command_id) is not None
        assert db.get(EsxiPxeHost, promotion.json()["id"]) is not None
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


def test_inventory_report_is_bounded_and_uses_mac_for_placeholder_uuid():
    payload = inventory_report(dmi_uuid="00000000-0000-0000-0000-000000000000")
    normalized = normalize_inventory_report(payload)
    assert normalized["system"]["dmi_uuid"] == ""
    assert normalized["boot_mac"] == "52:54:00:12:34:56"

    payload["disks"] = [{}] * (NETWORK_BOOT_MAX_DISKS + 1)
    with pytest.raises(ValueError, match="at most 128 disks"):
        normalize_inventory_report(payload)


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
                "shredos-2025.11.img",
                b"uploaded boot media",
                "application/octet-stream",
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
    assert config["filename"] == "shredos-2025.11.img"


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
        source_url="https://example.test/shredos.img",
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
        source_url="https://github.com/PartialVolume/shredos.x86_64/releases/download/example/shredos.img",
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

    assert response.status_code == 200, response.text
    assert response.content == b"kernel"


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


def test_shredos_requires_published_full_image_digest(monkeypatch):
    payload = {
        "tag_name": "v2025.11_31_x86-64_0.42",
        "draft": False,
        "prerelease": False,
        "assets": [
            {
                "name": "shredos-2025.11_31_x86-64_v0.42.img",
                "browser_download_url": "https://github.com/example/shredos.img",
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
    payload["assets"][0]["digest"] = ""
    with pytest.raises(ValueError, match="does not publish"):
        _release_descriptor("shredos")


def test_inventory_linux_resolves_versioned_atlaso_release_package(monkeypatch):
    payload = {
        "draft": False,
        "prerelease": False,
        "assets": [
            {
                "name": "atlaso-inventory-linux-2026.05.1.zip",
                "browser_download_url": "https://github.com/mdaneri/Atlaso/releases/download/v0.9.52/atlaso-inventory-linux-2026.05.1.zip",
                "digest": "sha256:" + ("b" * 64),
            }
        ],
    }
    monkeypatch.setattr(
        "atlaso.app.services.network_boot._fetch_https_text",
        lambda *_args, **_kwargs: json.dumps(payload),
    )
    descriptor = _release_descriptor("inventory")
    assert descriptor["version"] == "2026.05.1"
    assert descriptor["sha256"] == "b" * 64


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
    assert manifest["acquisition"] == "upload"
    assert (Path(media.installed_path) / "rootfs.cpio.gz").read_bytes() == initrd
    assert replacements


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
):
    from atlaso.app import worker

    media = record_verified_media(
        db_session,
        environment_key="shredos",
        version="2025.11",
        source_url="https://example.test/shredos.img",
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

    def cancel_during_sync(*_args, cancelled, **_kwargs):
        job.status = JobStatus.CANCELLED.value
        db_session.add(job)
        db_session.commit()
        assert cancelled() is True
        return media

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


def test_media_sync_revalidates_and_repairs_corrupt_cached_artifacts(
    db_session,
    monkeypatch,
    tmp_path,
):
    media_root = tmp_path / "media"
    installed = media_root / "shredos" / "2025.11"
    installed.mkdir(parents=True)
    artifact = installed / "shredos.img"
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
            "shredos.img": hashlib.sha256(b"original").hexdigest(),
            "boot.ipxe": hashlib.sha256(b"#!ipxe\n").hexdigest(),
        },
    }
    (installed / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    record_verified_media(
        db_session,
        environment_key="shredos",
        version="2025.11",
        source_url="https://example.test/shredos.img",
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
            "filename": "shredos.img",
            "asset_url": "https://example.test/shredos.img",
            "sha256": replacement_sha256,
        },
    )

    def fake_download(_self, url, destination, **_kwargs):
        destination.write_bytes(replacement)
        return url, replacement_sha256

    monkeypatch.setattr(BoundedHttpsDownloader, "download", fake_download)
    repaired = sync_network_boot_media(
        db_session,
        environment_key="shredos",
        media_root=media_root,
    )

    assert repaired.artifact_sha256 == replacement_sha256
    assert (installed / "shredos.img").read_bytes() == replacement


def test_media_sync_verifies_uploaded_artifact_without_downloading_it(
    db_session,
    monkeypatch,
    tmp_path,
):
    uploaded = tmp_path / "uploaded.img"
    uploaded.write_bytes(b"operator supplied asset")
    digest = hashlib.sha256(uploaded.read_bytes()).hexdigest()
    monkeypatch.setattr(
        network_boot,
        "_release_descriptor",
        lambda _key: {
            "version": "2025.12",
            "filename": "shredos.img",
            "asset_url": "https://example.test/shredos.img",
            "sha256": digest,
        },
    )

    def reject_download(*_args, **_kwargs):
        raise AssertionError("The uploaded release asset must not be downloaded again.")

    monkeypatch.setattr(BoundedHttpsDownloader, "download", reject_download)
    media = sync_network_boot_media(
        db_session,
        environment_key="shredos",
        media_root=tmp_path / "media",
        uploaded_artifact=uploaded,
        uploaded_filename="local-copy.img",
    )
    manifest = json.loads(media.manifest_json)

    assert media.artifact_sha256 == digest
    assert manifest["acquisition"] == "upload"
    assert manifest["uploaded_filename"] == "local-copy.img"


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
