"""Focused contract tests for OVA-native Proxmox and KVM import helpers."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
KVM_HELPER = ROOT / "scripts/virtualization/templates/import-atlaso-kvm.sh"
PROXMOX_HELPER = ROOT / "scripts/virtualization/templates/import-atlaso-proxmox.sh"
LINUX_SMOKE = ROOT / "scripts/virtualization/smoke-ova-linux.sh"


@pytest.mark.parametrize("path", (KVM_HELPER, PROXMOX_HELPER, LINUX_SMOKE))
def test_import_helpers_are_valid_posix_shell(path: Path) -> None:
    """Both versioned release helpers remain parseable without executing host mutation.

    Args:
        path: Helper script selected by parametrization.
    """

    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is unavailable")
    result = subprocess.run(
        [bash, "-n", path.relative_to(ROOT).as_posix()],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_kvm_imports_the_unchanged_ova_and_normalizes_exact_contract() -> None:
    """KVM consumes one OVA and creates only missing fileless data disks."""

    script = KVM_HELPER.read_text(encoding="utf-8")

    assert '-i ova "$ova_path"' in script
    assert '-o libvirt' in script
    assert '--network "Atlaso Management Network:$management_network"' in script
    assert '--network "Atlaso Services Network:$service_network"' in script
    assert 'python3 "$validator" "$ova_path"' in script
    assert 'python3 "$normalizer"' in script
    assert 'if [ "$disk_count" -lt 3 ]' in script
    assert 'if [ "$disk_count" -lt 4 ]' in script
    assert script.count("virsh vol-create-as") == 2
    assert "536870912000 --allocation 0 --format qcow2" in script
    assert 'if [ "$disk_count" -lt 2 ] || [ "$disk_count" -gt 4 ]' in script
    assert 'virsh domstate "$name"' in script
    assert 'virsh undefine "$name" --nvram' in script
    assert "--remove-all-storage" not in script
    assert 'virsh vol-pool "$disk_path"' in script
    assert '"$name"-*' in script
    assert 'virsh vol-delete --pool "$pool" "$volume_name"' in script
    assert 'virsh vol-list "$pool" --name' in script
    assert "photon-os.qcow2" not in script
    assert script.count('rm -rf -- "$validation_root"') == 2


def test_proxmox_imports_the_unchanged_ova_and_rejects_conflicting_disks() -> None:
    """Proxmox normalizes OVMF/SCSI topology without rewriting the source OVA."""

    script = PROXMOX_HELPER.read_text(encoding="utf-8")

    assert 'qm importovf "$vmid" "$ovf_path" "$storage" --format qcow2' in script
    assert 'python3 "$validator" "$ova_path"' in script
    assert '"$validation_root/contract.json"' in script
    assert 'ovf_path="$validation_root/extracted/$ovf_name"' in script
    assert "--bios ovmf" in script
    assert "pre-enrolled-keys=0" in script
    assert "--scsihw virtio-scsi-pci" in script
    assert "iothread=1" not in script
    assert "--agent enabled=1" in script
    assert 'if [ "$disk_count" -lt 3 ]' in script
    assert 'if [ "$disk_count" -lt 4 ]' in script
    assert 'if [ "$disk_count" -lt 2 ] || [ "$disk_count" -gt 4 ]' in script
    assert script.count("$storage:500") == 2
    assert 'qm destroy "$vmid" --purge 1 --destroy-unreferenced-disks 1' in script
    assert "photon-os.qcow2" not in script
    assert script.count('rm -rf -- "$validation_root"') == 2


def test_linux_smoke_imports_reboots_validates_and_bounds_cleanup() -> None:
    """Linux target smoke owns one absent VM and verifies the full guest contract twice."""

    script = LINUX_SMOKE.read_text(encoding="utf-8")
    assert 'provider must be proxmox or kvm' in script.lower()
    assert 'qm status "$identifier"' in script
    assert 'virsh dominfo "$identifier"' in script
    assert 'owned=1' in script
    kvm_import = script.index('"$template_root/import-atlaso-kvm.sh"')
    kvm_owned = script.index("owned=1", kvm_import)
    disk_inventory = script.index('virsh domblklist "$identifier"', kvm_import)
    assert kvm_import < kvm_owned < disk_inventory
    assert 'qm destroy "$identifier" --purge 1 --destroy-unreferenced-disks 1' in script
    assert 'virsh vol-delete --pool "$storage" "$volume"' in script
    assert 'grep -qx "platform=qemu" /var/lib/atlaso/guest-agent.applied' in script
    assert 'test ! -e /var/lib/atlaso/first-boot-packages' in script
    assert 'systemctl is-active --quiet qemu-guest-agent.service' in script
    assert 'systemctl is-active --quiet atlaso-worker.service' in script
    assert 'https://$address/openapi.json' in script
    assert "qga_exec 'systemctl reboot'" in script
    assert script.count("validate_guest") == 3
