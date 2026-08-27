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
RELEASE_WORKFLOW = ROOT / ".github/workflows/release.yml"


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
    assert 'atlaso-kvm-domain-${name}.lock' in script
    assert 'atlaso-kvm-pool-${pool}-${name}.lock' in script
    assert script.index('flock -n 8') < script.index('flock -n 9')
    assert 'KVM import rollback did not reach its cleanup postcondition' in script
    assert 'Rollback retained a volume in the locked $pool/$name namespace' in script
    cleanup = script.split("cleanup() {", 1)[1].split("trap cleanup", 1)[0]
    absence_proof = cleanup.index('domain_names=$(virsh list --all --name')
    guarded_delete = cleanup.index('if [ "$created" -eq 1 ] && [ "$domain_absent" -eq 1 ]')
    volume_delete = cleanup.index('virsh vol-delete')
    assert absence_proof < guarded_delete < volume_delete
    assert "exact domain absence could not be proved" in cleanup
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
    lock = script.index('flock -n 9')
    preflight = script.index("vmids=$(qm list")
    mutation = script.index('qm importovf "$vmid"')
    assert lock < preflight < mutation
    assert 'exec 9>"$lock_path"' in script
    assert "Proxmox import rollback did not reach its cleanup postcondition" in script
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
    cleanup = script.split("cleanup() {", 1)[1].split("qga_ping() {", 1)[0]
    domain_postcondition = cleanup.index('domain_absent=1')
    guarded_volumes = cleanup.index('if [ "$domain_absent" -eq 1 ] && [ -f "$disk_volume_list" ]')
    volume_delete = cleanup.index('virsh vol-delete --pool "$storage" "$volume"')
    assert domain_postcondition < guarded_volumes < volume_delete
    assert 'cleanup_failed=1' in script
    assert 'exit "$exit_status"' in script
    assert 'vmids=$(qm list' in script
    assert 'domains=$(virsh list --all --name' in script
    assert 'volumes=$(virsh vol-list --pool "$storage" --name' in script
    assert "inventory could not prove cleanup" in script
    assert '|| true' not in script.split('cleanup() {', 1)[1].split('qga_ping() {', 1)[0]
    assert (
        'grep -qx "platform=qemu" '
        "/var/lib/atlaso-privileged/guest-agent/guest-agent.applied"
    ) in script
    assert 'test ! -e /var/lib/atlaso/first-boot-packages' in script
    assert 'systemctl is-active --quiet qemu-guest-agent.service' in script
    assert 'systemctl is-active --quiet atlaso-worker.service' in script
    assert 'https://$address/openapi.json' in script
    assert "qga_exec 'systemctl reboot'" in script
    assert script.count("validate_guest") == 3


def test_release_image_build_uses_only_disposable_credentials() -> None:
    """The public template build cannot receive a protected reusable credential."""

    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    build_job = workflow.split("  vmware_ova_build:\n", 1)[1].split("  vmware_ova_smoke:\n", 1)[0]
    assert "secrets.ATLASO_PACKER_SSH_PASSWORD" not in build_job
    assert "secrets.ATLASO_BOOTSTRAP_ADMIN_PASSWORD" not in build_job
    assert "RandomNumberGenerator]::GetBytes(32)" in build_job
    assert "$sshText = $null" in build_job
    assert "$adminText = $null" in build_job
    smoke_job = workflow.split("  vmware_ova_smoke:\n", 1)[1].split("  proxmox_ova_smoke:\n", 1)[0]
    assert "secrets.ATLASO_BOOTSTRAP_ADMIN_PASSWORD" not in smoke_job
    assert "RandomNumberGenerator]::GetBytes(32)" in smoke_job
    assert "$passwordText = $null" in smoke_job
