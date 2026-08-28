"""Focused tests for the canonical multi-hypervisor OVA contract."""

from __future__ import annotations

import hashlib
import json
import tarfile
from io import BytesIO
from pathlib import Path

import pytest

from scripts.virtualization import validate_ova as validator


OVFTOOL_FIXTURE = Path("tests/fixtures/virtualization/ovftool-secure-boot-disabled.ovf")


def _ovf() -> bytes:
    """Return the supported OVF Tool-shaped four-disk Atlaso fixture."""

    return OVFTOOL_FIXTURE.read_bytes()


def _members(*, manifest_mismatch: bool = False, provenance_mismatch: bool = False) -> dict[str, bytes]:
    """Return one valid canonical OVA member set with optional corruption.

    Args:
        manifest_mismatch: Whether to corrupt one manifest hash.
        provenance_mismatch: Whether to corrupt one provenance payload hash.
    """

    members = {
        "atlaso.ovf": _ovf(),
        "photon.vmdk": b"photon-payload",
        "system.vmdk": b"system-payload",
    }
    provenance = {
        "schema_version": 1,
        "kind": "atlaso-vmware-ova-provenance",
        "product_version": "0.9.216",
        "source_commit": "a" * 40,
        "machine": validator.EXPECTED_MACHINE,
        "payloads": [
            {
                "role": "photon_os",
                "scsi_slot": 0,
                "file": "photon.vmdk",
                "virtual_size_bytes": 40 * 1024**3,
                "sha256": hashlib.sha256(members["photon.vmdk"]).hexdigest(),
            },
            {
                "role": "atlaso_system",
                "scsi_slot": 1,
                "file": "system.vmdk",
                "virtual_size_bytes": 20 * 1024**3,
                "sha256": "0" * 64 if provenance_mismatch else hashlib.sha256(members["system.vmdk"]).hexdigest(),
            },
        ],
    }
    members["atlaso-provenance.json"] = (json.dumps(provenance, sort_keys=True) + "\n").encode()
    lines = []
    for name in sorted(members):
        digest = hashlib.sha256(members[name]).hexdigest()
        if manifest_mismatch and name == "atlaso.ovf":
            digest = "f" * 64
        lines.append(f"SHA256({name})= {digest}\n")
    members["atlaso.mf"] = "".join(lines).encode()
    return members


def _write_ova(path: Path, members: dict[str, bytes]) -> None:
    """Write one deterministic flat OVA fixture.

    Args:
        path: OVA fixture destination.
        members: Flat archive members by name.
    """

    with tarfile.open(path, mode="w") as archive:
        for name in ("atlaso.ovf", "atlaso.mf", "atlaso-provenance.json", "photon.vmdk", "system.vmdk"):
            content = members[name]
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o600
            info.mtime = 0
            archive.addfile(info, BytesIO(content))


def test_validates_and_extracts_canonical_ova(tmp_path: Path) -> None:
    """A valid OVA returns the source, version, machine, and payload role contract.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    ova_path = tmp_path / "atlaso.ova"
    _write_ova(ova_path, _members())

    result = validator.validate_ova(ova_path, extraction_directory=tmp_path / "extracted")

    assert result["product_version"] == "0.9.216"
    assert result["source_commit"] == "a" * 40
    assert "ssh_host_ed25519_public_key" not in result
    assert result["machine"] == validator.EXPECTED_MACHINE
    assert [payload["role"] for payload in result["payloads"]] == ["photon_os", "atlaso_system"]


@pytest.mark.parametrize(
    ("replacement", "message"),
    [
        (b'<vmw:Config ovf:required="false" vmw:key="uefi.secureBoot.enabled" vmw:value="false" />', None),
        (
            b'<vmw:Config ovf:required="false" vmw:key="bootOptions.efiSecureBootEnabled" vmw:value="false" />\n'
            b'      <vmw:Config ovf:required="false" vmw:key="uefi.secureBoot.enabled" vmw:value="false" />',
            None,
        ),
        (b"", "explicitly disable Secure Boot"),
        (
            b'<vmw:Config ovf:required="false" vmw:key="bootOptions.efiSecureBootEnabled" vmw:value="true" />',
            "Secure Boot must be disabled",
        ),
        (
            b'<vmw:Config ovf:required="false" vmw:key="bootOptions.efiSecureBootEnabled" vmw:value="disabled" />',
            "Secure Boot must be disabled",
        ),
        (
            b'<vmw:Config ovf:required="false" vmw:key="bootOptions.efiSecureBootEnabled" vmw:value="false" />\n'
            b'      <vmw:Config ovf:required="false" vmw:key="uefi.secureBoot.enabled" vmw:value="true" />',
            "Secure Boot must be disabled",
        ),
    ],
)
def test_secure_boot_declarations_fail_closed(
    tmp_path: Path,
    replacement: bytes,
    message: str | None,
) -> None:
    """OVF Tool and legacy declarations are accepted only when explicitly and consistently false.

    Args:
        tmp_path: Temporary directory provided by pytest.
        replacement: Secure Boot declaration bytes replacing the OVF Tool-shaped declaration.
        message: Expected rejection diagnostic, or ``None`` for an accepted declaration.
    """

    declaration = (
        b'<vmw:Config ovf:required="false" vmw:key="bootOptions.efiSecureBootEnabled" vmw:value="false" />'
    )
    ovf_path = tmp_path / "atlaso.ovf"
    ovf_path.write_bytes(_ovf().replace(declaration, replacement, 1))

    if message is None:
        assert validator.validate_ovf(ovf_path)["machine"] == validator.EXPECTED_MACHINE
    else:
        with pytest.raises(validator.OvaValidationError, match=message):
            validator.validate_ovf(ovf_path)


@pytest.mark.parametrize(
    ("members", "message"),
    [
        (_members(manifest_mismatch=True), "manifest verification failed"),
        (_members(provenance_mismatch=True), "does not bind the payload"),
    ],
)
def test_rejects_checksum_or_provenance_mismatch(
    tmp_path: Path,
    members: dict[str, bytes],
    message: str,
) -> None:
    """Manifest and provenance hashes are independent fail-closed boundaries.

    Args:
        tmp_path: Temporary directory provided by pytest.
        members: Corrupted OVA member set.
        message: Expected rejection diagnostic.
    """

    ova_path = tmp_path / "atlaso.ova"
    _write_ova(ova_path, members)

    with pytest.raises(validator.OvaValidationError, match=message):
        validator.validate_ova(ova_path, extraction_directory=tmp_path / "extracted")


def test_provenance_does_not_bind_a_cloned_ssh_host_key(tmp_path: Path) -> None:
    """The canonical artifact never carries a reusable template host identity.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    members = _members()
    ova_path = tmp_path / "atlaso.ova"
    _write_ova(ova_path, members)

    result = validator.validate_ova(ova_path, extraction_directory=tmp_path / "extracted")
    provenance = json.loads((tmp_path / "extracted/atlaso-provenance.json").read_text(encoding="utf-8"))
    assert "ssh_host_ed25519_public_key" not in result
    assert "ssh_host_ed25519_public_key" not in provenance


def test_rejects_reordered_disk_role(tmp_path: Path) -> None:
    """A payload moved away from its fixed SCSI role cannot be converted.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    members = _members()
    members["atlaso.ovf"] = members["atlaso.ovf"].replace(
        b'<rasd:AddressOnParent>1</rasd:AddressOnParent>',
        b'<rasd:AddressOnParent>2</rasd:AddressOnParent>',
        1,
    )
    members = {**members, "atlaso.mf": _members()["atlaso.mf"]}
    # Rebuild the manifest so this test reaches the topology boundary.
    covered = {name: content for name, content in members.items() if name != "atlaso.mf"}
    members["atlaso.mf"] = "".join(
        f"SHA256({name})= {hashlib.sha256(content).hexdigest()}\n" for name, content in sorted(covered.items())
    ).encode()
    ova_path = tmp_path / "atlaso.ova"
    _write_ova(ova_path, members)

    with pytest.raises(validator.OvaValidationError, match="duplicate or invalid role binding"):
        validator.validate_ova(ova_path, extraction_directory=tmp_path / "extracted")


def test_rejects_reordered_or_ambiguous_network_roles(tmp_path: Path) -> None:
    """The two imported NICs must retain management then services identity.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    members = _members()
    members["atlaso.ovf"] = members["atlaso.ovf"].replace(
        b"<rasd:Connection>Atlaso Services Network</rasd:Connection>",
        b"<rasd:Connection>Atlaso Management Network</rasd:Connection>",
        1,
    )
    covered = {name: content for name, content in members.items() if name != "atlaso.mf"}
    members["atlaso.mf"] = "".join(
        f"SHA256({name})= {hashlib.sha256(content).hexdigest()}\n" for name, content in sorted(covered.items())
    ).encode()
    ova_path = tmp_path / "atlaso.ova"
    _write_ova(ova_path, members)

    with pytest.raises(validator.OvaValidationError, match="network roles"):
        validator.validate_ova(ova_path, extraction_directory=tmp_path / "extracted")


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        (
            b'<File ovf:id="file1" ovf:href="system.vmdk" />',
            b'<File ovf:id="file0" ovf:href="system.vmdk" />',
            "uniquely identified flat payload files",
        ),
        (
            b'<File ovf:id="file1" ovf:href="system.vmdk" />',
            b'<File ovf:id="file1" ovf:href="../system.vmdk" />',
            "uniquely identified flat payload files",
        ),
        (
            b'<Disk ovf:diskId="atlaso-backups"',
            b'<Disk ovf:diskId="atlaso-depot"',
            "uniquely identified disk definitions",
        ),
    ],
)
def test_rejects_duplicate_or_external_ovf_identifiers(
    tmp_path: Path,
    old: bytes,
    new: bytes,
    message: str,
) -> None:
    """OVF identifiers cannot hide duplicates or refer outside the verified archive.

    Args:
        tmp_path: Temporary directory provided by pytest.
        old: Fixture bytes to replace.
        new: Unsafe replacement bytes.
        message: Expected rejection diagnostic.
    """

    members = _members()
    members["atlaso.ovf"] = members["atlaso.ovf"].replace(old, new, 1)
    covered = {name: content for name, content in members.items() if name != "atlaso.mf"}
    members["atlaso.mf"] = "".join(
        f"SHA256({name})= {hashlib.sha256(content).hexdigest()}\n" for name, content in sorted(covered.items())
    ).encode()
    ova_path = tmp_path / "atlaso.ova"
    _write_ova(ova_path, members)

    with pytest.raises(validator.OvaValidationError, match=message):
        validator.validate_ova(ova_path, extraction_directory=tmp_path / "extracted")


def test_rejects_payload_reference_not_carried_by_ova(tmp_path: Path) -> None:
    """Every payload role must resolve to one of the two manifest-verified VMDKs.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    members = _members()
    members["atlaso.ovf"] = members["atlaso.ovf"].replace(
        b'<File ovf:id="file1" ovf:href="system.vmdk" />',
        b'<File ovf:id="file1" ovf:href="unused.vmdk" />',
        1,
    )
    covered = {name: content for name, content in members.items() if name != "atlaso.mf"}
    members["atlaso.mf"] = "".join(
        f"SHA256({name})= {hashlib.sha256(content).hexdigest()}\n" for name, content in sorted(covered.items())
    ).encode()
    ova_path = tmp_path / "atlaso.ova"
    _write_ova(ova_path, members)

    with pytest.raises(validator.OvaValidationError, match="two VMDKs carried by the OVA"):
        validator.validate_ova(ova_path, extraction_directory=tmp_path / "extracted")


def test_rejects_archive_traversal_without_writing_outside_destination(tmp_path: Path) -> None:
    """Flat-member validation rejects traversal before any escaped write occurs.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    ova_path = tmp_path / "atlaso.ova"
    with tarfile.open(ova_path, mode="w") as archive:
        content = b"unsafe"
        info = tarfile.TarInfo("../escape")
        info.size = len(content)
        archive.addfile(info, BytesIO(content))

    with pytest.raises(validator.OvaValidationError, match="exactly five|unsafe path"):
        validator.validate_ova(ova_path, extraction_directory=tmp_path / "extracted")
    assert not (tmp_path / "escape").exists()


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        (
            b'<vmw:Config ovf:required="false" vmw:key="bootOptions.efiSecureBootEnabled" vmw:value="false" />',
            b"",
            "explicitly disable Secure Boot",
        ),
        (
            b"<rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits>",
            b"<rasd:AllocationUnits>byte</rasd:AllocationUnits>",
            "4096 MiB",
        ),
        (
            b"<rasd:Parent>5</rasd:Parent>",
            b"<rasd:Parent>6</rasd:Parent>",
            "invalid role binding",
        ),
    ],
)
def test_rejects_implicit_or_conflicting_machine_topology(
    tmp_path: Path,
    old: bytes,
    new: bytes,
    message: str,
) -> None:
    """Firmware, memory units, and disk controller bindings are explicit parts of the contract.

    Args:
        tmp_path: Temporary directory provided by pytest.
        old: Fixture bytes to replace.
        new: Unsafe replacement bytes.
        message: Expected rejection diagnostic.
    """

    members = _members()
    members["atlaso.ovf"] = members["atlaso.ovf"].replace(old, new, 1)
    covered = {name: content for name, content in members.items() if name != "atlaso.mf"}
    members["atlaso.mf"] = "".join(
        f"SHA256({name})= {hashlib.sha256(content).hexdigest()}\n" for name, content in sorted(covered.items())
    ).encode()
    ova_path = tmp_path / "atlaso.ova"
    _write_ova(ova_path, members)

    with pytest.raises(validator.OvaValidationError, match=message):
        validator.validate_ova(ova_path, extraction_directory=tmp_path / "extracted")


def test_rejects_symlinked_ova_before_extraction(tmp_path: Path) -> None:
    """Consumers cannot redirect the validated OVA source through a symbolic link.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    source = tmp_path / "source.ova"
    _write_ova(source, _members())
    link = tmp_path / "link.ova"
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("symbolic links are unavailable")

    with pytest.raises(validator.OvaValidationError, match="not a symlink"):
        validator.validate_ova(link, extraction_directory=tmp_path / "extracted")
