"""Test Network Boot and ESXi PXE API v1 transports."""

from tests.routers.api_v1.helpers import create_token


def create_api_token(client, scopes):
    """Return one raw API token with the requested ESXi PXE scopes."""
    return create_token(client, scopes)[0]


def test_esxi_kickstart_api_hides_raw_content_from_read_only_tokens(client):
    """Verify that esxi kickstart api hides raw content from read only tokens.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import EsxiKickstart

    write_token = create_api_token(client, ["read:esxi-pxe", "write:esxi-pxe"])
    created = client.post(
        "/api/v1/esxi-pxe/kickstarts",
        headers={"Authorization": f"Bearer {write_token}"},
        json={
            "name": "Secure ESXi",
            "description": "secret-bearing ks",
            "content": "install --firstdisk\nnetwork --bootproto=dhcp\nrootpw MySecretPassword\nreboot\n%firstboot\n%end\n",
            "enabled": True,
        },
    )

    assert created.status_code == 201, created.text
    kickstart_id = created.json()["id"]
    assert created.json()["content"] and "MySecretPassword" in created.json()["content"]
    with SessionLocal() as db:
        row = db.execute(
            select(EsxiKickstart).where(EsxiKickstart.id == kickstart_id)
        ).scalar_one()
        assert "MySecretPassword" in row.content
        assert row.content_hash

    read_token = create_api_token(client, ["read:esxi-pxe"])
    fetched = client.get(
        f"/api/v1/esxi-pxe/kickstarts/{kickstart_id}",
        headers={"Authorization": f"Bearer {read_token}"},
    )
    preview = client.get(
        f"/api/v1/esxi-pxe/kickstarts/{kickstart_id}/preview",
        headers={"Authorization": f"Bearer {read_token}"},
    )
    download = client.get(
        f"/api/v1/esxi-pxe/kickstarts/{kickstart_id}/download",
        headers={"Authorization": f"Bearer {read_token}"},
    )

    assert fetched.status_code == 200
    assert fetched.json()["content"] is None
    assert "MySecretPassword" not in fetched.text
    assert "rootpw ********" in fetched.json()["redacted_preview"]
    assert preview.status_code == 200
    assert "MySecretPassword" not in preview.text
    assert download.status_code == 403


def test_esxi_custom_variable_api_supports_catalog_management(client):
    """Verify that esxi custom variable api supports catalog management.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    token = create_api_token(client, ["read:esxi-pxe", "write:esxi-pxe"])
    created = client.post(
        "/api/v1/esxi-pxe/custom-variables",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "install_disk",
            "description": "Preferred installation disk",
            "default_value": "firstdisk",
        },
    )
    assert created.status_code == 201, created.text
    assert created.json() == {
        "id": "install_disk",
        "name": "install_disk",
        "description": "Preferred installation disk",
        "default_value": "firstdisk",
    }

    listed = client.get(
        "/api/v1/esxi-pxe/custom-variables",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert listed.status_code == 200
    assert listed.json() == [created.json()]

    kickstart = client.post(
        "/api/v1/esxi-pxe/kickstarts",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "API catalog variable",
            "content": "install --firstdisk={{custom.install_disk}}\nnetwork --bootproto=dhcp\nrootpw --iscrypted placeholder\n",
            "enabled": True,
        },
    )
    assert kickstart.status_code == 201, kickstart.text

    updated = client.put(
        "/api/v1/esxi-pxe/custom-variables/install_disk",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "install_disk",
            "description": "Updated installation disk",
            "default_value": "nvme0",
        },
    )
    assert updated.status_code == 200
    assert updated.json()["default_value"] == "nvme0"

    read_token = create_api_token(client, ["read:esxi-pxe"])
    forbidden = client.post(
        "/api/v1/esxi-pxe/custom-variables",
        headers={"Authorization": f"Bearer {read_token}"},
        json={"name": "forbidden"},
    )
    assert forbidden.status_code == 403

    deleted = client.delete(
        "/api/v1/esxi-pxe/custom-variables/install_disk",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert deleted.status_code == 200
    assert deleted.json() == {"deleted": True}
