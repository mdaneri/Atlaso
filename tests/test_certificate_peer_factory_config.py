"""Pure validation and rendering tests for the receipt-bound peer factory."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from scripts.interop.certificate_peer_factory_config import render_vmx, validate_spec

_PATH = str(Path(__file__).resolve())
_DIGEST = "a" * 64


def _spec(**overrides: object) -> dict[str, object]:
    """Build a valid factory specification with selected test overrides.

    Args:
        **overrides: Specification fields replaced for the validation case.
    """
    spec: dict[str, object] = {
        "schema": 1,
        "trust_model": "trusted-host",
        "repository": "mdaneri/Atlaso",
        "pr": 1118,
        "task_id": "019d4c8f_ca_peer-01",
        "source_commit": "f" * 40,
        "server_cidr": "192.168.77.1/24",
        "lease_address": "192.168.77.10",
        "management_addresses": ["192.168.77.10", "192.168.77.30", "192.168.77.40"],
        "management_vmnet": "vmnet9",
        "peer_user": "alpine",
        "peer_hostname": "certificate-peer",
        "appliance_intent": {"path": _PATH, "sha256": _DIGEST},
        "appliance_ownership": {"path": _PATH, "sha256": _DIGEST},
        "appliance_installed_boot": {"path": _PATH, "sha256": _DIGEST},
        "peer_source_preparation": {"path": _PATH, "sha256": _DIGEST},
        "appliance_vmx": _PATH,
        "peer_public_key_path": _PATH,
        "peer_vmdk_sha256": "b" * 64,
        "peer_public_key_sha256": "c" * 64,
        "appliance_mac": "00:50:56:2a:11:22",
    }
    spec.update(overrides)
    return spec


def _render(**overrides: object) -> str:
    """Render a peer VMX from the valid fixture and supplied overrides.

    Args:
        **overrides: VMX identity or specification fields for the case.
    """
    spec = _spec(**overrides.pop("spec", {}))  # type: ignore[arg-type]  # Test helper accepts spec overrides.
    return render_vmx(
        spec,
        name=str(overrides.pop("name", "Atlaso-PR-1118-certificate-peer")),
        segment_id=str(overrides.pop("segment_id", "52 00 00 00 00 00 00 02-00 00 00 00 00 00 00 02")),
        cleanup_identity=str(overrides.pop("cleanup_identity", "d" * 32)),
        macs=overrides.pop("macs", ("00:50:56:2a:11:33", "00:50:56:2a:11:44")),  # type: ignore[arg-type]  # Invalid values are the test subject.
    )


def test_validate_spec_accepts_trusted_host_inputs_and_returns_a_copy() -> None:
    source = _spec(collision_suffix="run-2")
    original = copy.deepcopy(source)

    validated = validate_spec(source)

    assert validated == source
    assert validated is not source
    assert validated["appliance_intent"] is not source["appliance_intent"]
    assert source == original


def test_validate_spec_accepts_the_smallest_supported_subnet() -> None:
    validated = validate_spec(
        _spec(
            server_cidr="192.168.77.1/29",
            lease_address="192.168.77.2",
            management_addresses=["192.168.77.2", "192.168.77.3", "192.168.77.4"],
        )
    )

    assert validated["server_cidr"] == "192.168.77.1/29"
    assert validated["lease_address"] == "192.168.77.2"


def test_render_vmx_builds_offline_peer_with_receipt_identity_and_serial_log() -> None:
    text = _render(spec={"collision_suffix": "run-2"}, name="Atlaso-PR-1118-certificate-peer-run-2")
    assignments = dict(line.split(" = ", 1) for line in text.splitlines() if " = " in line)

    assert assignments[".encoding"] == '"UTF-8"'
    assert assignments["firmware"] == '"efi"'
    assert assignments["virtualHW.version"] == '"21"'
    assert assignments["numvcpus"] == '"1"'
    assert assignments["memsize"] == '"1024"'
    assert assignments["guestOS"] == '"other5xlinux-64"'
    assert assignments["sata0:0.fileName"] == '"Atlaso-PR-1118-certificate-peer-run-2.vmdk"'
    assert assignments["sata0:1.fileName"] == '"Atlaso-PR-1118-certificate-peer-run-2-seed.iso"'
    assert assignments["serial0.fileType"] == '"file"'
    assert assignments["serial0.fileName"] == '"Atlaso-PR-1118-certificate-peer-run-2-serial.log"'
    assert assignments["serial0.startConnected"] == '"TRUE"'
    assert assignments["serial0.append"] == '"TRUE"'
    assert assignments["guestinfo.atlaso.test_vm_cleanup_identity"] == f'"{"d" * 32}"'
    assert assignments["ethernet0.connectionType"] == '"custom"'
    assert assignments["ethernet0.vnet"] == '"vmnet9"'
    assert assignments["ethernet0.virtualDev"] == '"e1000"'
    assert assignments["ethernet0.addressType"] == '"static"'
    assert assignments["ethernet0.address"] == '"00:50:56:2a:11:33"'
    assert assignments["ethernet1.connectionType"] == '"pvn"'
    assert assignments["ethernet1.pvnID"] == '"52 00 00 00 00 00 00 02-00 00 00 00 00 00 00 02"'
    assert assignments["ethernet1.virtualDev"] == '"e1000"'
    assert assignments["ethernet1.addressType"] == '"static"'
    assert assignments["ethernet1.address"] == '"00:50:56:2a:11:44"'
    assert assignments["tools.syncTime"] == '"FALSE"'
    assert all(assignments[f"ethernet{index}.present"] == '"TRUE"' for index in range(2))
    assert all(assignments[f"ethernet{index}.startConnected"] == '"TRUE"' for index in range(2))
    assert not any(key.startswith(("vnc.", "checkpoint.", "suspend.", "autostart.")) for key in assignments)
    assert not any(key in assignments for key in ("guestinfo.atlaso.password", "guestinfo.atlaso.private_key"))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema", True),
        ("schema", 2),
        ("trust_model", "independent-control"),
        ("repository", "someone/else"),
        ("pr", True),
        ("pr", 0),
        ("task_id", "bad/task"),
        ("source_commit", "F" * 40),
        ("server_cidr", "192.168.77.0/24"),
        ("server_cidr", "192.168.77.1/23"),
        ("server_cidr", "169.254.1.1/24"),
        ("server_cidr", "8.8.8.1/24"),
        ("lease_address", "192.168.77.1"),
        ("lease_address", "192.168.77.0"),
        ("lease_address", "192.168.77.255"),
        ("lease_address", "192.168.78.10"),
        ("management_addresses", ["192.168.77.10", "192.168.77.30"]),
        ("management_addresses", ["192.168.77.10", "192.168.77.10", "192.168.77.40"]),
        ("management_addresses", ["192.168.77.1", "192.168.77.10", "192.168.77.40"]),
        ("management_addresses", ["192.168.77.0", "192.168.77.10", "192.168.77.40"]),
        ("management_addresses", ["192.168.77.10", "192.168.77.30", "192.168.78.40"]),
        ("management_vmnet", "vmnet0"),
        ("management_vmnet", "vmnet09"),
        ("peer_user", "bad user"),
        ("peer_hostname", "bad.hostname"),
        ("collision_suffix", "-bad"),
        ("appliance_vmx", "relative\u002fvmx"),
        ("peer_public_key_path", "relative-key.pub"),
        ("peer_vmdk_sha256", "A" * 64),
        ("peer_public_key_sha256", "x" * 64),
        ("appliance_mac", "01:50:56:2a:11:22"),
    ],
)
def test_validate_spec_rejects_invalid_fields(field: str, value: object) -> None:
    """Reject a factory specification field with an invalid value.

    Args:
        field: Specification key under validation.
        value: Invalid value assigned to that key.
    """
    with pytest.raises(ValueError):
        validate_spec(_spec(**{field: value}))


def test_validate_spec_rejects_unexpected_top_level_and_reference_fields() -> None:
    with pytest.raises(ValueError, match="Unexpected specification fields"):
        validate_spec(_spec(extra="ignored"))

    with pytest.raises(ValueError, match="exactly path and sha256"):
        validate_spec(_spec(appliance_intent={"path": _PATH, "sha256": _DIGEST, "extra": "ignored"}))


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"name": "Atlaso-PR-1118-certificate-peer\"\nserial0.present = \"FALSE"}, "canonical PR-owned"),
        ({"name": "Atlaso-PR-1119-certificate-peer"}, "canonical PR-owned"),
        ({"segment_id": "52 \"\nfoo = \"bar"}, "VMware private LAN"),
        ({"cleanup_identity": "../" + "a" * 29}, "cleanup_identity"),
        ({"macs": ("01:50:56:2a:11:33", "00:50:56:2a:11:44")}, "unicast"),
        ({"macs": ("00:50:56:2a:11:33", "00:50:56:2a:11:33")}, "distinct"),
        ({"macs": ("00:50:56:2a:11:22", "00:50:56:2a:11:44")}, "distinct"),
        ({"macs": ("00:50:56:2a:11:33", "00:50:56:2a:11:44\"\nserial0.append = \"FALSE")}, "six exact"),
    ],
)
def test_render_vmx_refuses_injection_and_identity_mismatch(kwargs: dict[str, object], message: str) -> None:
    """Refuse VMX injection and mismatches between VM and receipt identity.

    Args:
        kwargs: Rendering overrides that introduce the invalid input.
        message: Expected validation message pattern.
    """
    with pytest.raises(ValueError, match=message):
        _render(**kwargs)
