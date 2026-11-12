"""Keep derived terminal addresses inside the protected management handoff."""

import json

import pytest
from sqlalchemy import select

from atlaso.app import ui
from atlaso.app.database import SessionLocal
from atlaso.app.models import ApplianceSettings, CaSettings, PhysicalInterface


@pytest.mark.parametrize("independent_edit", [None, "root_ssh", "terminal_enabled", "terminal_interfaces", "other_address"])
def test_ca_handoff_admits_only_management_derived_terminal_addresses(client, independent_edit):
    """Use real previews, rotation detection and execution-plan consent admission.

    Args:
        client: Initialize the isolated application database.
        independent_edit: Optional pending change outside the management address.
    """
    with SessionLocal() as db:
        settings = db.scalar(select(ApplianceSettings))
        settings.management_https_enabled = True
        settings.web_terminal_enabled = True
        settings.web_terminal_interfaces_json = '["eth0", "eth2"]'
        db.scalar(select(CaSettings)).enabled = True
        management = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        management.ipv4_method = "static"
        management.ip_cidr = "192.168.49.20/24"
        management.host_ip_cidr = None
        other = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        other.ip_cidr = "192.168.87.32/24"
        db.commit()
        assert ui.ensure_ca_state(db) == []
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        baselines = ui.load_appliance_apply_baselines(db)
        # Retain a distinct applied leaf so real rotation detection selects Settings.
        applied_ca = json.loads(baselines["ca"]["config_preview"])
        leaf = next(row for row in applied_ca["certificates"] if row["managed_owner"] == "appliance:https")
        leaf["fingerprint"] = "previous-applied-management-leaf"
        baselines["ca"]["config_preview"] = json.dumps(applied_ca)
        ui.save_appliance_apply_baselines(db, baselines)
        db.commit()

        management.ip_cidr = "192.168.49.21/24"
        if independent_edit == "root_ssh":
            settings.root_ssh_enabled = not settings.root_ssh_enabled
        elif independent_edit == "terminal_enabled":
            settings.web_terminal_enabled = False
        elif independent_edit == "terminal_interfaces":
            settings.web_terminal_interfaces_json = '["eth0"]'
        elif independent_edit == "other_address":
            other.ip_cidr = "192.168.87.33/24"
        db.commit()
        current_units = ui.appliance_apply_units(db)
        by_id = {unit["id"]: unit for unit in current_units}
        assert by_id["network"]["management_handoff_required"]
        preview = by_id["appliance_settings"]["config_preview"]
        assert "appliance_settings" in ui.rotated_ca_certificate_consumers(by_id["ca"], baselines["ca"])
        if independent_edit is not None:
            assert not ui.management_address_only_appliance_settings_change(preview, baselines["appliance_settings"])
            with pytest.raises(ui.ApplianceApplyPlanError) as denied:
                ui.appliance_apply_execution_plan(db, current_units, {"network", "ca"}, enforce_consent=True)
            assert denied.value.public_detail == "Select the changed listener units before applying rotated CA certificates."
            return
        before = json.loads(baselines["appliance_settings"]["config_preview"])
        after = json.loads(preview)
        assert before["web_terminal_addresses"] == ["192.168.49.20", "192.168.87.32"]
        assert after["web_terminal_addresses"] == ["192.168.49.21", "192.168.87.32"]
        plan = ui.appliance_apply_execution_plan(db, current_units, {"network", "ca"}, enforce_consent=True)
        assert ui.management_address_only_appliance_settings_change(preview, baselines["appliance_settings"])
        assert "network" in plan["selected_ids"] and "ca" in plan["selected_ids"]
