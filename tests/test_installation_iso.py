"""Tests for pinned Photon installer ISO remastering."""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pycdlib
import pytest

from scripts import build_installation_iso
from scripts.installation import build as installation_build
from scripts.installation import iso as installation_iso


def test_pinned_command_file_matches_path_and_descriptor_modes(tmp_path: Path) -> None:
    """Keep Windows suffix-derived execute bits from invalidating unchanged files.

    Args:
        tmp_path: Temporary directory for this test's filesystem fixtures.
    """
    path = tmp_path / "GuestDiskExpansion_WindowsGuest.bat"
    path.write_bytes(b"@echo off\r\n")
    pinned = installation_iso._open_pinned(path)
    try:
        installation_iso._verify_pinned(pinned)
    finally:
        pinned.stream.close()
        pinned.stream = None
    installation_iso._verify_pinned(pinned)


@pytest.mark.parametrize("platform", ["nt", "posix"])
def test_mode_comparison_preserves_file_type_and_read_only_changes(monkeypatch, platform):
    """Normalize only synthetic Windows execute bits, keeping real mode changes.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        platform: Operating-system mode semantics exercised by the case.
    """
    monkeypatch.setattr(installation_iso, "os", SimpleNamespace(name=platform))
    mode = installation_iso._stable_mode
    assert (mode(stat.S_IFREG | 0o777) == mode(stat.S_IFREG | 0o666)) is (platform == "nt")
    assert mode(stat.S_IFREG | 0o666) != mode(stat.S_IFREG | 0o444)
    assert mode(stat.S_IFREG | 0o666) != mode(stat.S_IFDIR | 0o666)


def _cpio_entry(name: str, data: bytes, mode: int, ino: int) -> bytes:
    """
    Args:
        name: Archive member name supplied to the fixture helper.
        data: Input bytes whose checksum is calculated.
        mode: File mode assigned to the synthetic archive entry.
        ino: Synthetic archive inode number.
    """
    encoded_name = name.encode("utf-8") + b"\x00"
    fields = (ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded_name), 0)
    result = bytearray(b"070701" + b"".join(f"{value:08x}".encode("ascii") for value in fields))
    result.extend(encoded_name)
    result.extend(b"\x00" * ((-len(result)) & 3))
    result.extend(data)
    result.extend(b"\x00" * ((-len(result)) & 3))
    return bytes(result)


def _initrd(*, unshare: bool = True) -> tuple[bytes, bytes]:
    """
    Args:
        unshare: Whether the required unshare utility is available to the case.
    """
    photon_installer = b"pinned Photon installer 2.2"
    entries = [
        ("usr", b"", stat.S_IFDIR | 0o755),
        ("usr/bin", b"", stat.S_IFDIR | 0o755),
        ("usr/lib", b"", stat.S_IFDIR | 0o755),
        ("usr/lib/python3.11", b"", stat.S_IFDIR | 0o755),
        ("usr/lib/python3.11/site-packages/cryptography/__init__.py", b"", stat.S_IFREG | 0o644),
        ("usr/lib/python3.11/site-packages/cryptography/hazmat/primitives/asymmetric/ed25519.py", b"", stat.S_IFREG | 0o644),
        (
            "usr/lib/python3.11/site-packages/photon_installer/installer.py",
            photon_installer,
            stat.S_IFREG | 0o644,
        ),
    ]
    if unshare:
        entries.append(("usr/bin/unshare", b"unshare", stat.S_IFREG | 0o755))
    archive = bytearray()
    for index, (name, data, mode) in enumerate(entries, start=1):
        archive.extend(_cpio_entry(name, data, mode, index))
    archive.extend(_cpio_entry("TRAILER!!!", b"", 0, len(entries) + 1))
    return gzip.compress(bytes(archive), mtime=0), photon_installer


def _add_iso_file(iso: pycdlib.PyCdlib, path: str, name: str, data: bytes) -> None:
    """
    Args:
        iso: ISO fixture being inspected or modified.
        path: Path to the fixture or file being tested.
        name: Archive member name supplied to the fixture helper.
        data: Input bytes whose checksum is calculated.
    """
    iso.add_fp(io.BytesIO(data), len(data), iso_path=path, rr_name=name)


def _source_iso(path: Path, *, unshare: bool = True) -> tuple[str, bytes]:
    """
    Args:
        path: Path to the fixture or file being tested.
        unshare: Whether the required unshare utility is available to the case.
    """
    initrd, photon_installer = _initrd(unshare=unshare)
    image = pycdlib.PyCdlib()
    image.new(interchange_level=3, rock_ridge="1.09", vol_ident="PHOTON")
    for path_name, rr_name in (
        ("/BOOT", "boot"),
        ("/BOOT/GRUB2", "grub2"),
        ("/EFI", "efi"),
        ("/EFI/BOOT", "boot"),
        ("/ISOLINUX", "isolinux"),
    ):
        image.add_directory(iso_path=path_name, rr_name=rr_name)
    _add_iso_file(image, "/BOOT/GRUB2/GRUB.CFG;1", "grub.cfg", b"set timeout=10\n")
    _add_iso_file(image, "/EFI/BOOT/GRUB.CFG;1", "grub.cfg", b"set timeout=10\n")
    _add_iso_file(image, "/ISOLINUX/INITRD.IMG;1", "initrd.img", initrd)
    _add_iso_file(image, "/ISOLINUX/VMLINUZ;1", "vmlinuz", b"kernel")
    _add_iso_file(image, "/EFI/BOOT/EFIBOOT.IMG;1", "efiboot.img", b"EFI boot image")
    image.add_eltorito("/EFI/BOOT/EFIBOOT.IMG;1", efi=True)
    image.write(str(path))
    image.close()
    return hashlib.sha512(path.read_bytes()).hexdigest(), photon_installer


def _payload(root: Path) -> None:
    """
    Args:
        root: Root directory containing the fixture payload.
    """
    (root / "source/scripts/installation").mkdir(parents=True)
    (root / "payload-manifest.json").write_bytes(b"{}\n")
    (root / "payload-manifest.json.sig").write_bytes(b"signature\n")
    (root / "source/scripts/installation/installer.py").write_bytes(b"print('installer')\n")
    (root / "long directory name").mkdir()
    (root / "long directory name/a payload with spaces.bin").write_bytes(b"offline payload")


def _extract(iso: pycdlib.PyCdlib, *, rr_path: str) -> bytes:
    """
    Args:
        iso: ISO fixture being inspected or modified.
        rr_path: Rock Ridge path to extract from the ISO fixture.
    """
    result = io.BytesIO()
    iso.get_file_from_iso_fp(result, rr_path=rr_path)
    return result.getvalue()


def _prepared_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, unshare: bool = True):
    """
    Args:
        tmp_path: Temporary directory for this test's filesystem fixtures.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        unshare: Whether the required unshare utility is available to the case.
    """
    source = tmp_path / "photon.iso"
    source_hash, photon_installer = _source_iso(source, unshare=unshare)
    monkeypatch.setattr(installation_iso, "SOURCE_ISO_SHA512", source_hash)
    monkeypatch.setattr(installation_iso, "PHOTON_INSTALLER_SHA256", hashlib.sha256(photon_installer).hexdigest())
    payload = tmp_path / "payload"
    payload.mkdir()
    _payload(payload)
    trust = tmp_path / "trust.pem"
    trust.write_text("-----BEGIN PUBLIC KEY-----\npublic\n", encoding="ascii")
    return source, payload, trust


def test_remaster_preserves_efi_boot_and_embeds_interactive_offline_installer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Args:
        tmp_path: Temporary directory for this test's filesystem fixtures.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    source, payload, trust = _prepared_inputs(tmp_path, monkeypatch)
    output = tmp_path / "atlaso.iso"

    installation_iso.build_iso(source, payload, output, trust_key=trust)

    remastered = pycdlib.PyCdlib()
    remastered.open(str(output))
    try:
        assert remastered.pvd.volume_identifier == installation_iso.VOLUME_IDENTIFIER
        if remastered.joliet_vd is not None:
            assert remastered.joliet_vd.volume_identifier == installation_iso.VOLUME_IDENTIFIER
        assert remastered.get_record(iso_path="/BOOT.CAT;1")
        assert _extract(remastered, rr_path="/efi/boot/efiboot.img") == b"EFI boot image"
        assert _extract(remastered, rr_path="/boot/grub2/grub.cfg") == installation_iso._GRUB_CONFIG.encode()
        assert _extract(remastered, rr_path="/efi/boot/grub.cfg") == installation_iso._GRUB_CONFIG.encode()
        assert b"ks=" not in installation_iso._GRUB_CONFIG.encode()
        assert b"root=/dev/ram0" in installation_iso._GRUB_CONFIG.encode()
        assert b"photon.media=cdrom" in installation_iso._GRUB_CONFIG.encode()
        assert "timeout=-1" in installation_iso._GRUB_CONFIG

        initrd = gzip.decompress(_extract(remastered, rr_path="/isolinux/initrd.img"))
        entries, _magic, _padding = installation_iso._parse_newc(initrd)
        by_name = {entry.name: entry for entry in entries}
        assert by_name[installation_iso.BOOT_LAUNCHER_PATH].mode & 0o777 == 0o755
        assert b"unshare --net --" in installation_iso._cpio_data(by_name[installation_iso.BOOT_LAUNCHER_PATH].raw, b"070701")
        launcher = installation_iso._cpio_data(by_name[installation_iso.BOOT_LAUNCHER_PATH].raw, b"070701")
        assert b"/sys/devices/virtual/tty/console/active" in launcher
        assert b"ttyS" in launcher
        assert b"stty rows 25 cols 80" in launcher
        assert _extract(remastered, rr_path="/atlaso/payload-manifest.json") == b"{}\n"
        assert _extract(remastered, rr_path="/atlaso/payload-manifest.json.sig") == b"signature\n"
        assert _extract(remastered, rr_path="/atlaso/long directory name/a payload with spaces.bin") == b"offline payload"
    finally:
        remastered.close()


def test_rejects_unpinned_source_before_creating_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Args:
        tmp_path: Temporary directory for this test's filesystem fixtures.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    source, payload, trust = _prepared_inputs(tmp_path, monkeypatch)
    monkeypatch.setattr(installation_iso, "SOURCE_ISO_SHA512", "0" * 128)
    output = tmp_path / "atlaso.iso"

    with pytest.raises(ValueError, match="pinned Photon image"):
        installation_iso.build_iso(source, payload, output, trust_key=trust)

    assert not output.exists()


@pytest.mark.parametrize("serial_console", [False, True])
def test_development_image_records_the_requested_console_in_both_boot_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, serial_console: bool,
) -> None:
    """Manual images boot locally; serial testing is an explicit separate mode.

    Args:
        tmp_path: Temporary directory for isolated remaster inputs.
        monkeypatch: Fixture replacing only synthetic input admission.
        serial_console: Whether the automated serial mode is selected.
    """
    source, payload, trust = _prepared_inputs(tmp_path, monkeypatch)
    output = tmp_path / "development.iso"
    installation_iso.build_iso(
        source, payload, output, trust_key=trust, development=True,
        **({"serial_console": True} if serial_console else {}),
    )
    image = pycdlib.PyCdlib()
    image.open(str(output))
    try:
        expected_console = b"console=ttyS0,115200n8" if serial_console else b"console=tty0"
        for path in ("/boot/grub2/grub.cfg", "/efi/boot/grub.cfg"):
            grub = _extract(image, rr_path=path)
            assert grub.count(b"console=") == 1
            assert expected_console in grub
            assert b"set timeout=5" in grub
            assert b"DEVELOPMENT ONLY - Install Atlaso offline" in grub
            assert b"ks=" not in grub
        initrd = gzip.decompress(_extract(image, rr_path="/isolinux/initrd.img"))
        entries, magic, _padding = installation_iso._parse_newc(initrd)
        by_name = {entry.name: entry for entry in entries}
        assert installation_iso._cpio_data(by_name[installation_iso.BOOT_LAUNCHER_PATH].raw, magic) == installation_iso._LAUNCHER
        assert "etc/atlaso-installer/development" in by_name
    finally:
        image.close()


def test_production_image_rejects_development_serial_selection_before_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The development console option cannot change production boot behavior.

    Args:
        tmp_path: Temporary directory for isolated inputs and absent output.
        monkeypatch: Fixture replacing synthetic input admission.
    """
    source, payload, trust = _prepared_inputs(tmp_path, monkeypatch)
    output = tmp_path / "production.iso"
    with pytest.raises(ValueError, match="restricted to development"):
        installation_iso.build_iso(source, payload, output, trust_key=trust, serial_console=True)
    assert not output.exists()


def test_rejects_photon_installer_version_mismatch_before_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Args:
        tmp_path: Temporary directory for this test's filesystem fixtures.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    source, payload, trust = _prepared_inputs(tmp_path, monkeypatch)
    monkeypatch.setattr(installation_iso, "PHOTON_INSTALLER_SHA256", "0" * 64)
    output = tmp_path / "atlaso.iso"

    with pytest.raises(ValueError, match="pinned 2.2 version"):
        installation_iso.build_iso(source, payload, output, trust_key=trust)

    assert not output.exists()


def test_requires_unshare_in_initrd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Args:
        tmp_path: Temporary directory for this test's filesystem fixtures.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    source, payload, trust = _prepared_inputs(tmp_path, monkeypatch, unshare=False)
    output = tmp_path / "atlaso.iso"

    with pytest.raises(ValueError, match="unshare"):
        installation_iso.build_iso(source, payload, output, trust_key=trust)

    assert not output.exists()


def test_rejects_existing_output_without_replacing_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Args:
        tmp_path: Temporary directory for this test's filesystem fixtures.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    source, payload, trust = _prepared_inputs(tmp_path, monkeypatch)
    output = tmp_path / "atlaso.iso"
    output.write_bytes(b"keep")

    with pytest.raises(FileExistsError):
        installation_iso.build_iso(source, payload, output, trust_key=trust)

    assert output.read_bytes() == b"keep"


def test_rejects_insufficient_capacity_before_opening_inputs_or_spooling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Args:
        tmp_path: Temporary directory for this test's filesystem fixtures.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    source, payload, trust = _prepared_inputs(tmp_path, monkeypatch)
    output = tmp_path / "atlaso.iso"

    monkeypatch.setattr(installation_iso.shutil, "disk_usage", lambda _path: SimpleNamespace(free=1))
    monkeypatch.setattr(
        installation_iso,
        "_open_pinned",
        lambda *_args, **_kwargs: pytest.fail("capacity preflight must run before opening input files"),
    )
    monkeypatch.setattr(
        installation_iso.tempfile,
        "TemporaryFile",
        lambda *_args, **_kwargs: pytest.fail("capacity preflight must run before creating the payload spool"),
    )

    with pytest.raises(ValueError, match="insufficient capacity"):
        installation_iso.build_iso(source, payload, output, trust_key=trust)

    assert not output.exists()
    assert not list(tmp_path.glob("tmp*"))


def test_rejects_payload_hardlinks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Args:
        tmp_path: Temporary directory for this test's filesystem fixtures.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    source, payload, trust = _prepared_inputs(tmp_path, monkeypatch)
    alias = payload / "payload-alias"
    os.link(payload / "payload-manifest.json", alias)

    with pytest.raises(ValueError, match="hard-linked"):
        installation_iso.build_iso(source, payload, tmp_path / "atlaso.iso", trust_key=trust)


def test_rejects_output_inside_payload_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Args:
        tmp_path: Temporary directory for this test's filesystem fixtures.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    source, payload, trust = _prepared_inputs(tmp_path, monkeypatch)
    output = payload / "atlaso.iso"

    with pytest.raises(ValueError, match="outside the payload root"):
        installation_iso.build_iso(source, payload, output, trust_key=trust)

    assert not output.exists()


def test_rejects_short_iso_name_collisions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Args:
        tmp_path: Temporary directory for this test's filesystem fixtures.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    source, payload, trust = _prepared_inputs(tmp_path, monkeypatch)
    monkeypatch.setattr(installation_iso, "_iso_component", lambda _relative: "AAAAAAAA")
    output = tmp_path / "atlaso.iso"

    with pytest.raises(ValueError, match="name collision"):
        installation_iso.build_iso(source, payload, output, trust_key=trust)

    assert not output.exists()


def test_payload_remaster_scales_to_many_files_with_bounded_open_handles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Args:
        tmp_path: Temporary directory for this test's filesystem fixtures.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    source, payload, trust = _prepared_inputs(tmp_path, monkeypatch)
    expected = {}
    for index in range(1205):
        relative = f"rpm-inputs/package-{index:04}.rpm"
        path = payload / relative
        path.parent.mkdir(exist_ok=True)
        content = f"synthetic package {index}\n".encode()
        path.write_bytes(content)
        expected[relative] = content

    original_open = installation_iso._open_pinned
    opened_streams = []
    max_live_streams = 0

    def tracked_open(*args, **kwargs):
        """
        Args:
            *args: Args used by this test case.
            **kwargs: Additional subprocess options received by the test double.
        """
        nonlocal max_live_streams
        item = original_open(*args, **kwargs)
        opened_streams.append(item.stream)
        max_live_streams = max(max_live_streams, sum(not stream.closed for stream in opened_streams))
        return item

    monkeypatch.setattr(installation_iso, "_open_pinned", tracked_open)
    output = tmp_path / "large-payload.iso"
    installation_iso.build_iso(source, payload, output, trust_key=trust)

    assert len(opened_streams) == len(expected) + 6
    assert max_live_streams <= 3
    remastered = pycdlib.PyCdlib()
    remastered.open(str(output))
    try:
        for relative in ("rpm-inputs/package-0000.rpm", "rpm-inputs/package-0602.rpm", "rpm-inputs/package-1204.rpm"):
            assert _extract(remastered, rr_path=f"/atlaso/{relative}") == expected[relative]
    finally:
        remastered.close()


def test_rejects_unsafe_cpio_paths() -> None:
    malicious = _cpio_entry("../outside", b"bad", stat.S_IFREG | 0o644, 1)
    archive = malicious + _cpio_entry("TRAILER!!!", b"", 0, 2)

    with pytest.raises(ValueError, match="unsafe path"):
        installation_iso._parse_newc(archive)


def test_rejects_truncated_cpio_header() -> None:
    with pytest.raises(ValueError, match="header is truncated"):
        installation_iso._parse_newc(b"070701")


def test_accepts_original_cpio_root_directory_entry() -> None:
    archive = _cpio_entry(".", b"", stat.S_IFDIR | 0o755, 1)
    archive += _cpio_entry("TRAILER!!!", b"", 0, 2)

    entries, magic, _padding = installation_iso._parse_newc(archive)

    assert magic == b"070701"
    assert entries[0].name == "."
    assert stat.S_ISDIR(entries[0].mode)


def _mock_installation_rpm_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    filenames: tuple[str, ...] = (
        "dracut-109-2.ph5.x86_64.rpm",
        "initramfs-2.0-9.ph5.x86_64.rpm",
        "linux-6.12.113-5.ph5.x86_64.rpm",
        "python3-3.14.8-1.ph5.x86_64.rpm",
    ),
) -> tuple[Path, Path, Path, list[tuple[list[str], Path | None]]]:
    """Create a synthetic signed-RPM verification boundary for transaction checks.

    Args:
        tmp_path: Pytest-owned fixture directory.
        monkeypatch: Pytest fixture for replacing external RPM verification.
        filenames: RPM basenames and identities included in the synthetic transaction.

    Returns:
        RPM, source, and scratch directories plus recorded RPM-tool calls.
    """
    from scripts import verify_virtualization_guest_wheel

    root = tmp_path / "rpms with spaces"
    root.mkdir()
    source = tmp_path / "source"
    key_directory = source / "image/common/photon-rpm-gpg"
    key_directory.mkdir(parents=True)
    (key_directory / "VMWARE-RPM-GPG-KEY-current").write_text("public fixture key", encoding="ascii")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    identities = {}
    for filename in filenames:
        package = root / filename
        package.write_bytes(filename.encode("ascii"))
        name = filename.split("-", 1)[0]
        version = "3.14.8-1" if name == "python3" else "1-1"
        identities[filename] = (name, version, "x86_64")

    commands: list[tuple[list[str], Path | None]] = []

    def run_runtime_tool(arguments: list[str], *, cwd: Path | None = None) -> str:
        """Record and emulate RPM verification without invoking host tools.

        Args:
            arguments: RPM tool argument vector supplied by the build validator.
            cwd: Optional working directory passed to the bounded runtime tool.

        Returns:
            Synthetic RPM output for the requested operation.
        """
        commands.append((arguments, cwd))
        if arguments[0] == "rpmkeys":
            return f"{Path(arguments[-1]).name}: digests signatures OK"
        if arguments[0] == "rpm" and "-qp" in arguments:
            name, version, architecture = identities[Path(arguments[-1]).name]
            return f"ATLASO\t{name}\t{version}\t{architecture}\n"
        if arguments[0] == "rpm" and "--test" in arguments:
            manifest = Path(arguments[-1])
            if not any(name.startswith("dracut-") for name in manifest.read_text(encoding="ascii").splitlines()):
                raise SystemExit("transaction has missing dependency dracut >= 059-3 required by initramfs")
        return ""

    monkeypatch.setattr(verify_virtualization_guest_wheel, "_run_runtime_tool", run_runtime_tool)
    monkeypatch.setattr(verify_virtualization_guest_wheel, "_photon_repository_inventory", lambda: set())
    monkeypatch.setattr(
        verify_virtualization_guest_wheel,
        "_require_admitted_runtime_package",
        lambda *_args: None,
    )
    monkeypatch.setattr(
        installation_build,
        "package_selection",
        lambda _source: ["initramfs", "linux", "python3"],
    )
    return root, source, scratch, commands


def test_rpm_validation_checks_full_signed_transaction_in_isolated_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Validate the complete candidate transaction without consulting the host RPM database.

    Args:
        tmp_path: Pytest-owned fixture directory.
        monkeypatch: Pytest fixture for replacing external RPM verification.
    """
    root, source, scratch, commands = _mock_installation_rpm_transaction(tmp_path, monkeypatch)

    records = installation_build.verify_rpms(root, source, scratch)

    transaction_calls = [(arguments, cwd) for arguments, cwd in commands if "--test" in arguments]
    assert len(transaction_calls) == 1
    arguments, cwd = transaction_calls[0]
    database = (scratch / "rpmdb").resolve()
    manifest = (scratch / "rpm-transaction.manifest").resolve()
    assert arguments == [
        "rpm",
        "--dbpath",
        str(database),
        "--test",
        "--noscripts",
        "--notriggers",
        "--noplugins",
        "-U",
        str(manifest),
    ]
    assert cwd == root.resolve()
    assert "--nodeps" not in arguments
    assert manifest.read_text(encoding="ascii") == "".join(
        f"{name}\n" for name in sorted(path.name for path in root.glob("*.rpm"))
    )
    assert {record["name"] for record in records} == {"dracut", "initramfs", "linux", "python3"}
    assert commands.index(transaction_calls[0]) == len(commands) - 1


def test_rpm_validation_rejects_missing_transitive_dependency(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail when a signed candidate omits a dependency of an explicitly selected RPM.

    Args:
        tmp_path: Pytest-owned fixture directory.
        monkeypatch: Pytest fixture for replacing external RPM verification.
    """
    root, source, scratch, commands = _mock_installation_rpm_transaction(
        tmp_path,
        monkeypatch,
        filenames=(
            "initramfs-2.0-9.ph5.x86_64.rpm",
            "linux-6.12.113-5.ph5.x86_64.rpm",
            "python3-3.14.8-1.ph5.x86_64.rpm",
        ),
    )
    assert {path.name.split("-", 1)[0] for path in root.glob("*.rpm")} == {
        "initramfs",
        "linux",
        "python3",
    }

    with pytest.raises(SystemExit, match="missing dependency dracut"):
        installation_build.verify_rpms(root, source, scratch)

    transaction_calls = [arguments for arguments, _cwd in commands if "--test" in arguments]
    assert len(transaction_calls) == 1
    assert (scratch / "rpm-transaction.manifest").read_text(encoding="ascii").splitlines() == sorted(
        path.name for path in root.glob("*.rpm")
    )


def test_finalizer_rejects_missing_transaction_dependency_before_signer_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keep a missing RPM dependency from reaching the finalizer signing-key loader.

    Args:
        tmp_path: Pytest-owned fixture directory.
        monkeypatch: Pytest fixture for replacing the candidate validator and signer loader.
    """
    root, source, rpm_scratch, _commands = _mock_installation_rpm_transaction(
        tmp_path,
        monkeypatch,
        filenames=(
            "initramfs-2.0-9.ph5.x86_64.rpm",
            "linux-6.12.113-5.ph5.x86_64.rpm",
            "python3-3.14.8-1.ph5.x86_64.rpm",
        ),
    )
    output = tmp_path / "final-output"
    output.mkdir()
    scratch = tmp_path / "final-scratch"
    scratch.mkdir()
    signer_calls: list[Path] = []

    def reject_candidate(
        _candidate: Path,
        *,
        repository: Path,
        commit: str,
        version: str,
        trust_key: Path,
        scratch: Path,
    ):
        """Run RPM validation at the finalizer candidate boundary.

        Args:
            _candidate: Candidate path supplied to the validator.
            repository: Trusted repository checkout supplied to the validator.
            commit: Source commit supplied to the validator.
            version: Software version supplied to the validator.
            trust_key: Public trust key supplied to the validator.
            scratch: Candidate validation scratch path.
        """
        return installation_build.verify_rpms(root, source, rpm_scratch)

    def load_signing_key(path: Path):
        """Record unexpected signing-key access without loading a real key.

        Args:
            path: Signing-key path supplied by the finalizer.
        """
        signer_calls.append(path)
        raise AssertionError("signing-key loader must not run after transaction failure")

    monkeypatch.setattr(build_installation_iso, "validate_candidate", reject_candidate)
    monkeypatch.setattr("scripts.build_virtualization_artifact_index._load_signing_key", load_signing_key)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "build_installation_iso.py",
            "finalize",
            "--commit",
            "a" * 40,
            "--version",
            "0.9.453",
            "--payload",
            str(tmp_path / "candidate"),
            "--source-iso",
            str(tmp_path / "missing-photon.iso"),
            "--output",
            str(output),
            "--scratch",
            str(scratch),
            "--signing-key",
            str(tmp_path / "missing-signing-key.pem"),
        ],
    )

    with pytest.raises(SystemExit, match="missing dependency dracut"):
        build_installation_iso.main()

    assert signer_calls == []


def test_rpm_validation_rejects_unsafe_transaction_manifest_basename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reject an unsafe RPM filename before initializing or invoking RPM tooling.

    Args:
        tmp_path: Pytest-owned fixture directory.
        monkeypatch: Pytest fixture for replacing external RPM verification.
    """
    root, source, scratch, commands = _mock_installation_rpm_transaction(
        tmp_path, monkeypatch, filenames=("python3 unsafe.rpm",)
    )

    with pytest.raises(ValueError):
        installation_build.verify_rpms(root, source, scratch)

    assert commands == []
    assert not (scratch / "rpmdb").exists()
