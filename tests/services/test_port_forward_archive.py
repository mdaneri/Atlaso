"""Preserve reviewed forwarding intent through archive and desired-state reset."""

from copy import deepcopy

import pytest
from sqlalchemy import select

from atlaso.app.database import SessionLocal
from atlaso.app.models import PhysicalInterface, PortForward
from atlaso.app.services.settings_archive import (
    export_settings_archive,
    factory_reset_desired_state,
    restore_settings_archive,
)
from tests.services.test_port_forwarding import payload


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
