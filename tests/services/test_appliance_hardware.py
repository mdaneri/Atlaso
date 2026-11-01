"""Verify read-only hardware observations preserve unknown and empty evidence."""

import json
from types import SimpleNamespace

from atlaso.app.adapters.system import AdapterResult
from atlaso.app.services import appliance_hardware, guest_tools


def test_hardware_observation_keeps_failures_separate_from_empty(monkeypatch):
    """A failed disk command must not masquerade as a successful empty inventory.

    Args:
        monkeypatch: Native observation replacements.
    """
    monkeypatch.setattr(appliance_hardware.platform, "system", lambda: "Linux")
    monkeypatch.setattr(appliance_hardware, "_text", lambda path: "")

    def failed(*args, **kwargs):
        """Simulate a missing inventory tool.

        Args:
            *args: Native observation arguments.
            **kwargs: Native observation options.
        """
        raise FileNotFoundError("missing")

    monkeypatch.setattr(appliance_hardware.subprocess, "run", failed)
    monkeypatch.setattr(appliance_hardware, "observed_interfaces", lambda: [])
    result = appliance_hardware.hardware_inventory()
    assert result["disks_state"] == "unknown"
    assert result["disks"] == []
    assert result["interfaces_state"] == "available"
    assert result["interfaces"] == []


def test_hardware_includes_os_and_removable_devices_without_storage_admission(monkeypatch):
    """Hardware browsing includes devices regardless of ESX Storage eligibility.

    Args:
        monkeypatch: Native command observation replacements.
    """
    monkeypatch.setattr(appliance_hardware.platform, "system", lambda: "Linux")
    monkeypatch.setattr(appliance_hardware, "_text", lambda path: "")
    disks = {"blockdevices": [
        {"path": "/dev/sda", "type": "disk", "model": "OS disk", "size": 1000},
        {"path": "/dev/sr0", "type": "rom", "model": "Installer", "tran": "usb", "size": 2000},
    ]}
    monkeypatch.setattr(appliance_hardware.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(stdout=json.dumps(disks)))
    monkeypatch.setattr(appliance_hardware, "observed_interfaces", lambda: [])
    result = appliance_hardware.hardware_inventory()
    assert result["disks_state"] == "available"
    assert [row["device_path"] for row in result["disks"]] == ["/dev/sda", "/dev/sr0"]


def test_guest_tools_invalid_or_failed_observation_remains_unknown():
    """Neither an empty success response nor an absent helper proves missing tools."""
    for code, stdout in [(0, ""), (0, "{}"), (1, '{"state":"missing"}')]:
        result = guest_tools.guest_tools_observation(AdapterResult(
            command=["atlaso-helper"], returncode=code, stdout=stdout, stderr="", dry_run=False,
        ))
        assert result["state"] == "unknown"
        assert result["available"] is False
