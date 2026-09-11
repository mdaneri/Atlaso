"""Verify the default-off console policy survives desired-state UI persistence."""

import json
import re

from sqlalchemy import select

from atlaso.app.database import SessionLocal
from atlaso.app.models import DhcpScope
from atlaso.app.services.esxi_pxe import (
    esxi_pxe_boot_settings,
    render_esxi_pxe_manifest,
)
from tests.routers.ui.helpers import login


def test_console_authorization_default_and_ui_round_trip(client):
    """Save both policy values through the authenticated form without applying them.

    Args:
        client: Application client with the isolated seeded database.
    """
    login(client)
    with SessionLocal() as db:
        assert esxi_pxe_boot_settings(db)["console_authorization_required"] is False
        assert json.loads(render_esxi_pxe_manifest([], []))["boot"]["console_authorization_required"] is False
        scope_id = db.scalar(select(DhcpScope.id).where(DhcpScope.name == "SiteA"))
    for required in (True, False):
        page = client.get("/esxi-pxe")
        csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
        data = {
            "csrf": csrf, "enabled": "on", "hostname": "esxi-pxe.atlaso.internal",
            "dhcp_scope_id": str(scope_id), "http_port": "8080",
            "tftp_root": "/var/lib/atlaso/pxe/tftp",
            "bios_bootfile": "undionly.kpxe", "uefi_bootfile": "snponly.efi",
        }
        if required:
            data["console_authorization_required"] = "on"
        saved = client.post("/esxi-pxe/boot-settings", data=data, follow_redirects=False)
        assert saved.status_code == 303, saved.text
        with SessionLocal() as db:
            boot = esxi_pxe_boot_settings(db)
            assert boot["console_authorization_required"] is required
            assert json.loads(render_esxi_pxe_manifest([], [], boot_settings=boot))["boot"]["console_authorization_required"] is required
        page = client.get("/esxi-pxe")
        switch = re.search(r'<input[^>]+name="console_authorization_required"[^>]*>', page.text)
        assert switch is not None
        assert ("checked" in switch.group()) is required


def test_host_reference_refresh_is_current_and_contains_no_kickstart_source(client):
    """Project current choices through the authenticated, non-cacheable UI flow.

    Args:
        client: Application client with the isolated seeded database.
    """
    from atlaso.app.models import EsxiKickstart

    login(client)
    headers = {"X-Requested-With": "AtlasoHostReferenceRefresh"}
    response = client.get("/ui/management/network-boot", headers=headers)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["console_authorization_required"] is False
    with SessionLocal() as db:
        row = EsxiKickstart(name="refresh-choice", content="fixture source must remain private", content_hash="0" * 64, enabled=False)
        db.add(row)
        db.commit()
        row_id = row.id
    response = client.get("/ui/management/network-boot", headers=headers)
    assert {"id": row_id, "label": "refresh-choice"} in response.json()["kickstarts"]
    assert "fixture source" not in response.text
    with SessionLocal() as db:
        row = db.get(EsxiKickstart, row_id)
        row.name = "renamed-choice"
        db.commit()
    assert {"id": row_id, "label": "renamed-choice"} in client.get("/ui/management/network-boot", headers=headers).json()["kickstarts"]
    with SessionLocal() as db:
        db.delete(db.get(EsxiKickstart, row_id))
        db.commit()
    assert all(item["id"] != row_id for item in client.get("/ui/management/network-boot", headers=headers).json()["kickstarts"])
