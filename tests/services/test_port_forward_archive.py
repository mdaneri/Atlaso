"""Preserve reviewed forwarding intent through archive and desired-state reset."""

from copy import deepcopy

import pytest
from sqlalchemy import select

from atlaso.app.database import SessionLocal
from atlaso.app.models import KmsSettings, PhysicalInterface, PortForward
from atlaso.app.services.settings_archive import (
    _archive_port_forward_listener_claims,
    export_settings_archive,
    factory_reset_desired_state,
    restore_settings_archive,
)
from tests.services.test_port_forwarding import payload


@pytest.mark.parametrize("invalid", [None, "group", "target", "listener"])
@pytest.mark.parametrize("claimed_review", [False, True])
@pytest.mark.parametrize("missing_listener", [False, True])
def test_disabled_archive_rules_validate_available_relationships(client, invalid, claimed_review, missing_listener):
    """Disabled intent cannot bypass validation using enablement or an archived review flag.

    Args:
        client: Isolated initialized appliance.
        invalid: Relationship corrupted while the original listener remains available.
        claimed_review: Untrusted archive flag must not grant relaxed validation.
        missing_listener: Retain an unavailable ingress without relaxing unrelated relationships.
    """
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        address = interface.ip_cidr.split("/")[0]
        db.add(PortForward(**payload(ingress_interface="eth2", listener_address=address)))
        db.commit()
        archive = export_settings_archive(db, actor="test")
        row = archive["data"]["port_forwards"][0]
        row.update(enabled=False, restore_review_required=claimed_review)
        if missing_listener:
            row["ingress_interface"] = "missing_reviewed_adapter"
        if invalid == "group":
            row["source"] = "group:999999"
        elif invalid == "target":
            row["target_address"] = address
        elif invalid == "listener":
            row.update(external_port_start=22, external_port_end=22, target_port_end=13000)
        if invalid:
            with pytest.raises(ValueError, match="port-forward"):
                restore_settings_archive(db, archive)
            db.expire_all()
            saved = db.scalar(select(PortForward))
            assert saved.enabled and saved.source == "any" and saved.external_port_start == 12000
            assert saved.target_address != address
        else:
            restore_settings_archive(db, archive)
            saved = db.scalar(select(PortForward))
            assert saved.enabled is False
            if missing_listener:
                assert saved.ingress_interface == "missing_reviewed_adapter" and saved.restore_review_required


@pytest.mark.parametrize("invalid", [None, "missing_settings", "malformed_forwards"])
def test_legacy_v2_archive_without_port_forwards_restores_empty_collection(client, invalid):
    """Pre-forwarding v2 recovery archives remain valid replacements of desired state.

    Args:
        client: Isolated initialized appliance.
        invalid: Older required sections and explicitly malformed forwarding remain rejected.
    """
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        db.add(PortForward(**payload(ingress_interface="eth2", listener_address=interface.ip_cidr.split("/")[0])))
        db.commit()
        archive = export_settings_archive(db, actor="test")
        assert archive["schema_version"] == 2
        archive["data"].pop("port_forwards")
        if invalid == "missing_settings":
            archive["data"].pop("settings")
        elif invalid == "malformed_forwards":
            archive["data"]["port_forwards"] = None
        original = deepcopy(archive)
        if invalid:
            with pytest.raises(ValueError, match="required data section|must be a list"):
                restore_settings_archive(db, archive)
            assert db.scalar(select(PortForward)) is not None
        else:
            result = restore_settings_archive(db, archive)
            assert result["port_forwards"] == 0
            assert db.scalar(select(PortForward)) is None
            assert export_settings_archive(db, actor="test")["data"]["port_forwards"] == []
        assert archive == original


def test_archive_network_boot_claim_uses_restored_dhcp_selection(client):
    """Custom PXE ports follow the archived DHCP binding, not the legacy fallback.

    Args:
        client: Isolated initialized appliance.
    """
    with SessionLocal() as db:
        archive = export_settings_archive(db, actor="test")
    data = archive["data"]
    scope = data["dhcp_scopes"][0]
    scope["enabled"] = True
    scope["interface_name"] = "eth2"
    values = {
        "esxi_pxe.boot.enabled": "true", "esxi_pxe.boot.http_port": "18081",
        "esxi_pxe.boot.dhcp_scope_ids": "1", "esxi_pxe.boot.listen_interface": "eth9",
    }
    data["settings"] = [row for row in data["settings"] if row["key"] not in values]
    data["settings"].extend({"key": key, "value": value} for key, value in values.items())
    claims = _archive_port_forward_listener_claims(data)
    assert any(claim.interface == "eth2" and claim.protocol == "tcp" and claim.start == 18081 for claim in claims)
    assert not any(claim.interface == "eth9" and claim.start == 18081 for claim in claims)


@pytest.mark.parametrize(("protocol", "port"), [
    ("tcp", 22), ("tcp", 80), ("tcp", 443), ("udp", 53), ("udp", 69), ("tcp", 2049),
])
def test_archive_rejects_reserved_listener_before_replacing_desired_state(client, protocol, port):
    """Always-reserved endpoints cannot be introduced through archive restore.

    Args:
        client: Isolated initialized appliance.
        protocol: Reserved transport.
        port: Reserved service endpoint.
    """
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        db.add(PortForward(**payload(ingress_interface="eth2", listener_address=interface.ip_cidr.split("/")[0])))
        db.commit()
        archive = export_settings_archive(db, actor="test")
        archive["data"]["port_forwards"][0].update(
            protocol=protocol, external_port_start=port, external_port_end=port, target_port_end=13000,
        )
        with pytest.raises(ValueError, match="port-forward.*collides"):
            restore_settings_archive(db, archive)
        db.expire_all()
        assert db.scalar(select(PortForward)).external_port_start == 12000


@pytest.mark.parametrize("archived_enabled", [False, True])
def test_archive_listener_claims_use_archived_service_settings(client, archived_enabled):
    """Restore admission follows candidate services rather than destination settings.

    Args:
        client: Isolated initialized appliance.
        archived_enabled: Whether the archived custom service owns the mapping.
    """
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        db.add(PortForward(**payload(ingress_interface="eth2", listener_address=interface.ip_cidr.split("/")[0])))
        db.commit()
        archive = export_settings_archive(db, actor="test")
        archive["data"]["kms_settings"][0].update(enabled=archived_enabled, port=12000,
                                                   listen_interface="eth2", listen_address=interface.ip_cidr.split("/")[0])
        current = db.scalar(select(KmsSettings))
        current.enabled = not archived_enabled
        current.port = 12000
        current.listen_interface = "eth2"
        current.listen_address = interface.ip_cidr.split("/")[0]
        db.commit()
        if archived_enabled:
            with pytest.raises(ValueError, match="port-forward.*collides"):
                restore_settings_archive(db, archive)
            db.expire_all()
            assert db.scalar(select(KmsSettings)).enabled is False
        else:
            restore_settings_archive(db, archive)
            assert db.scalar(select(KmsSettings)).enabled is False
            assert db.scalar(select(PortForward)).enabled is True


def test_archive_retains_exact_mapping_and_disables_unavailable_listener(client):
    """An unavailable archived binding must never be replaced by a broader ingress.

    Args:
        client: Isolated application fixture that initializes archive dependencies.
    """
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        assert interface is not None
        db.add(PortForward(**payload(ingress_interface="eth2", listener_address=interface.ip_cidr.split("/")[0])))
        db.commit()
        archive = export_settings_archive(db, actor="test")
        original = archive["data"]["port_forwards"][0]
        assert "id" not in original and "packets" not in original and "bytes" not in original
        restore_settings_archive(db, archive)
        restored = db.scalar(select(PortForward))
        assert restored.enabled and restored.target_port_start == 13000
        assert restored.ingress_interface == "eth2"
        missing = deepcopy(archive)
        missing["data"]["port_forwards"][0]["ingress_interface"] = "missing_reviewed_adapter"
        restore_settings_archive(db, missing)
        restored = db.scalar(select(PortForward))
        assert restored.ingress_interface == "missing_reviewed_adapter"
        assert restored.listener_address == original["listener_address"]
        assert not restored.enabled and restored.restore_review_required
        assert restored.target_address == original["target_address"]
        invalid = deepcopy(archive)
        invalid["data"]["port_forwards"][0]["target_port_end"] = 13003
        with pytest.raises(ValueError, match="port-forward"):
            restore_settings_archive(db, invalid)
        assert db.scalar(select(PortForward)).ingress_interface == "missing_reviewed_adapter"
        counts = factory_reset_desired_state(db)
        assert counts["port_forwards"] == 0
        assert db.scalar(select(PortForward)) is None
