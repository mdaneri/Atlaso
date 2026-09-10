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
