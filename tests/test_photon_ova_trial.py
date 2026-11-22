"""Check the trial OVA's release shape and its pinned upstream boundary."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from scripts.virtualization import build_photon_ova, prepare_photon_ovf
from scripts.virtualization.validate_ova import OVF, RASD, validate_ova

NS = {"ovf": OVF, "rasd": RASD}


def test_package_preserves_disk_roles_and_runtime_properties(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Validate the archive layout and deployment contract.

    Args:
        tmp_path: Temporary directory for package and validator output.
        monkeypatch: Fixture to record disk admission calls.
    """
    output = tmp_path / "package"
    output.mkdir()
    for name in prepare_photon_ovf.VMDK_NAMES:
        (output / name).write_bytes(name.encode("ascii"))
    checked = []

    def check_disk(path: Path, size: int) -> None:
        """Record the requested disk admission.

        Args:
            path: Payload passed to disk validation.
            size: Expected virtual capacity in bytes.
        """
        checked.append((path.name, size))

    monkeypatch.setattr(prepare_photon_ovf, "require_stream_vmdk", check_disk)
    ova = prepare_photon_ovf.package(output, "1.0.0", "a" * 40, {"photon": {"build": "5.0"}}, tmp_path / "first")
    assert checked == [("atlaso-photon.vmdk", 40 * 1024**3), ("atlaso-system.vmdk", 20 * 1024**3)]
    validate_ova(ova, extraction_directory=tmp_path / "second")

    with tarfile.open(ova) as archive:
        assert archive.getnames() == [
            "atlaso.ovf", "atlaso.mf", "atlaso-photon.vmdk", "atlaso-system.vmdk", "atlaso-provenance.json",
        ]
    tree = ET.parse(output / "atlaso.ovf")
    assert tree.find(".//ovf:VirtualHardwareSection", NS).get(f"{{{OVF}}}transport") == "com.vmware.guestInfo"
    assert tree.findall(".//rasd:ResourceSubType", NS)[0].text == "VirtualSCSI"
    assert [entry.text for entry in tree.findall(".//rasd:ResourceSubType", NS)[1:]] == ["VmxNet3", "VmxNet3"]
    props = {
        element.attrib[f"{{{OVF}}}key"]: element.attrib
        for element in tree.findall(".//ovf:ProductSection/ovf:Property", NS)
    }
    assert set(props) == {
        "cidr", "gateway", "ipv6_enabled", "ipv6_cidr", "ipv6_gateway", "dns_servers",
        "fqdn", "admin_password", "root_password", "root_ssh_enabled",
    }
    for key in ("admin_password", "root_password"):
        assert props[key][f"{{{OVF}}}type"] == "password"
        assert props[key][f"{{{OVF}}}required"] == "true"
        assert props[key][f"{{{OVF}}}qualifiers"] == "MinLen(12)"
        assert f"{{{OVF}}}value" not in props[key]
    assert props["fqdn"][f"{{{OVF}}}required"] == "true"
    provenance = json.loads((output / "atlaso-provenance.json").read_text())
    assert provenance["source_commit"] == "a" * 40
    assert provenance["trial_build"]["photon"]["build"] == "5.0"
    assert "software_release_source" not in provenance


def test_upstream_digest_is_checked_before_reading_the_tar(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify an invalid digest stops before tar parsing.

    Args:
        tmp_path: Temporary directory for the upstream fixture.
        monkeypatch: Fixture to admit the test file length.
    """
    path = tmp_path / "bad.ova"
    path.write_bytes(b"not a tar file")
    monkeypatch.setattr(build_photon_ova, "PHOTON_BYTES", path.stat().st_size)
    with pytest.raises(ValueError, match="pinned archive"):
        build_photon_ova.extract_photon(path, tmp_path / "disk.vmdk")


@pytest.mark.parametrize("kind", ("traversal", "link", "duplicate"))
def test_upstream_member_inventory_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    """Reject an unsafe member before writing the payload.

    Args:
        tmp_path: Temporary directory for the upstream fixture.
        monkeypatch: Fixture to admit its length and checksum.
        kind: Unsafe member shape to exercise.
    """
    path = tmp_path / "bad.ova"
    name = "../photon-ova.ovf" if kind == "traversal" else "photon-ova.ovf"
    with tarfile.open(path, "w") as archive:
        member = tarfile.TarInfo(name)
        if kind == "link":
            member.type = tarfile.SYMTYPE
            member.linkname = "escaped"
            archive.addfile(member)
        else:
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
            if kind == "duplicate":
                archive.addfile(member, io.BytesIO(b"x"))
    monkeypatch.setattr(build_photon_ova, "PHOTON_BYTES", path.stat().st_size)
    monkeypatch.setattr(build_photon_ova, "PHOTON_SHA512", hashlib.sha512(path.read_bytes()).hexdigest())
    target = tmp_path / "disk.vmdk"
    with pytest.raises(ValueError, match="Unexpected or unsafe member"):
        build_photon_ova.extract_photon(path, target)
    assert not target.exists()


def test_build_sources_use_the_persistent_seed_directory() -> None:
    """Keep the staged sources and their cleanup bound to the same directory."""
    script = (build_photon_ova.ASSETS / "provision.sh").read_text(encoding="utf-8").splitlines()
    assert f"build={build_photon_ova.SEED}" in script
    assert 'export ATLASO_SRC="$build/source"' in script
    assert 'chmod 0711 "$build"' in script
    assert 'install -d -m 0755 "$ATLASO_SRC"' in script
    assert 'rm -rf "$build"' in script


def test_trial_restores_grub_before_installing_appliance_branding() -> None:
    """The shared provisioner needs the inherited graphical theme declaration."""
    script = (build_photon_ova.ASSETS / "provision.sh").read_text(encoding="utf-8")
    restore_menu = script.index('"$build/grub.cfg" > /boot/grub2/grub.cfg')
    provision_appliance = script.index('sh "$ATLASO_SRC/image/common/scripts/provision-atlaso.sh"')
    assert restore_menu < provision_appliance
