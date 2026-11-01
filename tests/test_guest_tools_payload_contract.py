"""Keep operator maintenance payloads separate from one-shot first-boot access."""

from pathlib import Path


def test_verified_guest_tools_closures_are_retained_and_checksum_covered():
    """The durable maintenance root contains only three provider RPM closures.

    The first-boot selector owns a separate temporary tree. Its cleanup must not
    erase the package evidence reserved for later administrator-approved work.
    """
    provision = Path("image/common/scripts/provision-atlaso.sh").read_text(encoding="utf-8")
    selector = Path("scripts/appliance/atlaso-select-guest-agent").read_text(encoding="utf-8")
    maintenance = provision.split("stage_guest_agent_packages() {", 1)[1].split(
        "\n}\n\nwrite_third_party_notices()", 1,
    )[0]

    assert 'maintenance_staging="$ATLASO_PRIVILEGED_STATE/guest-tools"' in maintenance
    for provider in ("vmware", "hyperv", "qemu"):
        assert f'"$maintenance_staging/{provider}"' in maintenance
    assert "--downloaddir \"$maintenance_staging/vmware\" --alldeps open-vm-tools" in maintenance
    assert "--downloaddir \"$maintenance_staging/hyperv\" --alldeps hyper-v" in maintenance
    assert "--downloaddir \"$maintenance_staging/qemu\" --alldeps glib systemd" in maintenance
    assert '"$QEMU_GUEST_AGENT_RPM" "$maintenance_staging/qemu/' in maintenance
    assert "find vmware hyperv qemu -type f -name '*.rpm'" in maintenance
    assert "sha256sum >SHA256SUMS" in maintenance
    assert "/var/lib/atlaso/first-boot-packages" in selector
    assert 'maintenance_staging' not in selector
    assert 'rm -rf "$STAGING_DIRECTORY" "$RUNTIME_DIRECTORY"' in selector


def test_installation_media_builds_maintenance_payload_without_selecting_agent():
    """ISO image builds package verified options while physical defaults stay agent-free."""
    provision = Path("image/common/scripts/provision-atlaso.sh").read_text(encoding="utf-8")
    builder = provision.split('if [ -n "$QEMU_GUEST_AGENT_BUILDER" ]; then', 1)[1].split(
        "\nstage_guest_agent_packages", 1,
    )[0]
    maintenance = provision.split("stage_guest_agent_packages() {", 1)[1].split(
        "\n}\n\nwrite_third_party_notices()", 1,
    )[0]

    assert 'sh "$QEMU_GUEST_AGENT_BUILDER" "$QEMU_GUEST_AGENT_OUTPUT"' in builder
    assert '"$QEMU_GUEST_AGENT_RPM"' in maintenance
    assert 'if [ "$ATLASO_GUEST_PLATFORM" = "none" ]; then' in maintenance
    physical = maintenance.split('if [ "$ATLASO_GUEST_PLATFORM" = "none" ]; then', 1)[1].split(
        "  fi", 1,
    )[0]
    assert 'maintenance_staging="$ATLASO_PRIVILEGED_STATE/guest-tools"' in maintenance
    assert 'return' in physical
    assert 'install --downloadonly' in maintenance
    assert 'rpm -Uvh' not in maintenance
