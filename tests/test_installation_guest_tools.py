"""Verify offline ISO guest-tools retention, authenticity and package boundaries."""

import hashlib
import json
import stat
from pathlib import Path

import pytest

from scripts import verify_virtualization_guest_wheel
from scripts.installation import build, guest_tools


def payload(root):
    """Create a complete synthetic closure with exact inventory coverage.

    Args:
        root: Absent task-local payload destination.
    """
    root.mkdir(parents=True)
    (root / "compatibility.json").write_text(json.dumps(guest_tools.COMPATIBILITY))
    lines = []
    for profile, agent in guest_tools.PROFILES.items():
        directory = root / profile
        directory.mkdir()
        for name in (agent, "systemd"):
            package = directory / (name + ".rpm")
            package.write_bytes((profile + ":" + name).encode())
            lines.append(hashlib.sha256(package.read_bytes()).hexdigest() + "  " + profile + "/" + package.name)
    (root / "SHA256SUMS").write_text("\n".join(lines) + "\n")
    return root


@pytest.mark.parametrize("defect", [None, "tamper", "extra", "missing", "compatibility", "duplicate", "traversal"])
def test_exact_payload_inventory_rejects_invalid_media(tmp_path, defect):
    """Every provider and package byte must agree with the bounded inventory.

    Args:
        tmp_path: Isolated payload tree.
        defect: Independent invalid media condition.
    """
    root = payload(tmp_path / "payload")
    if defect == "tamper":
        (root / "qemu/atlaso-qemu-guest-agent.rpm").write_bytes(b"changed")
    elif defect == "extra":
        (root / "unexpected").write_bytes(b"extra")
    elif defect == "missing":
        (root / "hyperv/hyper-v.rpm").unlink()
    elif defect == "compatibility":
        (root / "compatibility.json").write_text('{"release":"6.0"}')
    elif defect in {"duplicate", "traversal"}:
        manifest = root / "SHA256SUMS"
        manifest.write_text(manifest.read_text() + (manifest.read_text().splitlines()[0] if defect == "duplicate" else "a" * 64 + "  qemu/../escape.rpm") + "\n")
    if defect:
        with pytest.raises(ValueError):
            guest_tools.payload_inventory(root)
    else:
        assert len(guest_tools.payload_inventory(root)) == 6


def test_staging_retains_all_providers_is_idempotent_and_preserves_conflicts(tmp_path):
    """Staging copies bytes without a package manager or guest-service operation.

    Args:
        tmp_path: Isolated media and appliance staging roots.
    """
    source = payload(tmp_path / "media")
    destination = tmp_path / "protected"
    guest_tools.copy_payload(source, destination)
    expected = guest_tools.payload_inventory(source)
    assert guest_tools.payload_inventory(destination) == expected
    original = (destination / "qemu/atlaso-qemu-guest-agent.rpm").stat()
    guest_tools.copy_payload(source, destination)
    assert (destination / "qemu/atlaso-qemu-guest-agent.rpm").stat().st_mtime_ns == original.st_mtime_ns
    (destination / "qemu/atlaso-qemu-guest-agent.rpm").write_bytes(b"preserve conflicting state")
    with pytest.raises(ValueError):
        guest_tools.copy_payload(source, destination)
    assert (destination / "qemu/atlaso-qemu-guest-agent.rpm").read_bytes() == b"preserve conflicting state"


def test_candidate_separates_guest_tools_from_automatic_install_repository(tmp_path):
    """The unsigned local QEMU RPM must never enter Photon's GPG-enforced repository.

    Args:
        tmp_path: Isolated captured input and candidate roots.
    """
    source = tmp_path / "source"
    (source / "scripts/installation").mkdir(parents=True)
    (source / "scripts/installation/guest_tools.py").write_text("# supported source fixture")
    rpms, software, powercli, output = [tmp_path / name for name in ("rpms", "software", "powercli", "output")]
    for directory in (rpms, software, powercli, output):
        directory.mkdir()
    (rpms / "python3.rpm").write_bytes(b"signed Photon fixture")
    with pytest.raises(FileNotFoundError):
        build.copy_installation_inputs(software, rpms, powercli, output, source)
    payload(rpms / "guest-tools")
    build.copy_installation_inputs(software, rpms, powercli, output, source)
    assert {path.name for path in (output / "rpms").iterdir()} == {"python3.rpm"}
    assert guest_tools.payload_inventory(output / "guest-tools") == guest_tools.payload_inventory(rpms / "guest-tools")


@pytest.mark.parametrize("defect", [None, "unsigned_photon", "qemu_integrity", "qemu_arch", "qemu_version", "qemu_scripts", "qemu_files", "qemu_unit", "dependencies"])
def test_candidate_verification_checks_photon_trust_qemu_contract_and_closures(tmp_path, monkeypatch, defect):
    """Only the pinned Atlaso agent may use media trust; Photon signatures stay mandatory.

    Args:
        tmp_path: Synthetic candidate and independent RPM-state roots.
        monkeypatch: Native RPM inspection replacements, never a package manager mutation.
        defect: Independent package trust, compatibility or closure failure.
    """
    root = payload(tmp_path / "payload")
    source = tmp_path / "source"
    keys = source / "image/common/photon-rpm-gpg"
    keys.mkdir(parents=True)
    (keys / "VMWARE-RPM-GPG-KEY-test").write_text("public fixture")
    agents = source / "image/common/guest-agents"
    agents.mkdir()
    (agents / "atlaso-qemu-guest-agent.spec").write_text("Version: 10.2.2\n")
    unit = agents / "qemu-guest-agent.service"
    unit.write_text("trusted unit fixture")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    transactions = []
    signatures = []
    admitted_names = []

    def run(command, *, cwd=None):
        """Emulate bounded RPM metadata and signature/transaction probes.

        Args:
            command: Exact fixed-tool argument vector.
            cwd: Profile directory used for the RPM transaction manifest.
        """
        if "--test" in command:
            assert all(flag in command for flag in ("--noscripts", "--notriggers", "--noplugins"))
            transactions.append(cwd.name)
            if defect == "dependencies":
                raise SystemExit("unsatisfied dependency")
            return ""
        if command[0] == "rpmkeys":
            package_name = Path(command[-1]).stem
            signatures.append(package_name)
            if package_name == "atlaso-qemu-guest-agent":
                return "NOT OK" if defect == "qemu_integrity" else "digests OK"
            return "digests OK" if defect == "unsigned_photon" else "digests signatures OK"
        if "-qp" not in command:
            return ""
        name = Path(command[-1]).stem
        if any(flag in command for flag in ("--scripts", "--triggers", "--filetriggers")):
            return "unapproved script" if defect == "qemu_scripts" else ""
        if "ATLASOALGO" in command[-2]:
            unit_hash = "f" * 64 if defect == "qemu_unit" else hashlib.sha256(unit.read_bytes()).hexdigest()
            executable = "/usr/bin/foreign" if defect == "qemu_files" else "/usr/bin/qemu-ga"
            return ("ATLASOALGO\t8\n"
                    + f"ATLASOFILE\t{executable}\t{stat.S_IFREG | 0o755}\t{'a' * 64}\troot\troot\n"
                    + f"ATLASOFILE\t/usr/lib/systemd/system/qemu-guest-agent.service\t{stat.S_IFREG | 0o644}\t{unit_hash}\troot\troot\n")
        version, architecture = "0:1.0-1.ph5", "x86_64"
        if name == "atlaso-qemu-guest-agent":
            version = "0:9.0-1.ph5" if defect == "qemu_version" else "0:10.2.2-1.ph5"
            architecture = "aarch64" if defect == "qemu_arch" else "x86_64"
        return f"ATLASO\t{name}\t{version}\t{architecture}\n"

    monkeypatch.setattr(verify_virtualization_guest_wheel, "_run_runtime_tool", run)
    monkeypatch.setattr(verify_virtualization_guest_wheel, "_photon_repository_inventory", lambda: {})
    monkeypatch.setattr(verify_virtualization_guest_wheel, "_require_admitted_runtime_package", lambda package, *args: admitted_names.append(package.stem))
    if defect:
        with pytest.raises((ValueError, SystemExit)):
            build.verify_guest_tools(root, source, scratch)
    else:
        build.verify_guest_tools(root, source, scratch)
        assert transactions == ["vmware", "hyperv", "qemu"]
        assert "atlaso-qemu-guest-agent" in signatures
        assert "atlaso-qemu-guest-agent" not in admitted_names
        assert {"open-vm-tools", "hyper-v", "systemd"} <= set(signatures)
