"""Tests for pinned Photon installer ISO remastering."""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pycdlib
import pytest

from scripts.installation import iso as installation_iso


def _cpio_entry(name: str, data: bytes, mode: int, ino: int) -> bytes:
    encoded_name = name.encode("utf-8") + b"\x00"
    fields = (ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded_name), 0)
    result = bytearray(b"070701" + b"".join(f"{value:08x}".encode("ascii") for value in fields))
    result.extend(encoded_name)
    result.extend(b"\x00" * ((-len(result)) & 3))
    result.extend(data)
    result.extend(b"\x00" * ((-len(result)) & 3))
    return bytes(result)


def _initrd(*, unshare: bool = True) -> tuple[bytes, bytes]:
    photon_installer = b"pinned Photon installer 2.2"
    entries = [
        ("usr", b"", stat.S_IFDIR | 0o755),
        ("usr/bin", b"", stat.S_IFDIR | 0o755),
        ("usr/lib", b"", stat.S_IFDIR | 0o755),
        ("usr/lib/python3.11", b"", stat.S_IFDIR | 0o755),
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
    iso.add_fp(io.BytesIO(data), len(data), iso_path=path, rr_name=name)


def _source_iso(path: Path, *, unshare: bool = True) -> tuple[str, bytes]:
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
    (root / "source/scripts/installation").mkdir(parents=True)
    (root / "payload-manifest.json").write_bytes(b"{}\n")
    (root / "payload-manifest.json.sig").write_bytes(b"signature\n")
    (root / "source/scripts/installation/installer.py").write_bytes(b"print('installer')\n")
    (root / "long directory name").mkdir()
    (root / "long directory name/a payload with spaces.bin").write_bytes(b"offline payload")


def _extract(iso: pycdlib.PyCdlib, *, rr_path: str) -> bytes:
    result = io.BytesIO()
    iso.get_file_from_iso_fp(result, rr_path=rr_path)
    return result.getvalue()


def _prepared_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, unshare: bool = True):
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
    source, payload, trust = _prepared_inputs(tmp_path, monkeypatch)
    monkeypatch.setattr(installation_iso, "SOURCE_ISO_SHA512", "0" * 128)
    output = tmp_path / "atlaso.iso"

    with pytest.raises(ValueError, match="pinned Photon image"):
        installation_iso.build_iso(source, payload, output, trust_key=trust)

    assert not output.exists()


def test_rejects_photon_installer_version_mismatch_before_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, payload, trust = _prepared_inputs(tmp_path, monkeypatch)
    monkeypatch.setattr(installation_iso, "PHOTON_INSTALLER_SHA256", "0" * 64)
    output = tmp_path / "atlaso.iso"

    with pytest.raises(ValueError, match="pinned 2.2 version"):
        installation_iso.build_iso(source, payload, output, trust_key=trust)

    assert not output.exists()


def test_requires_unshare_in_initrd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, payload, trust = _prepared_inputs(tmp_path, monkeypatch, unshare=False)
    output = tmp_path / "atlaso.iso"

    with pytest.raises(ValueError, match="unshare"):
        installation_iso.build_iso(source, payload, output, trust_key=trust)

    assert not output.exists()


def test_rejects_existing_output_without_replacing_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, payload, trust = _prepared_inputs(tmp_path, monkeypatch)
    output = tmp_path / "atlaso.iso"
    output.write_bytes(b"keep")

    with pytest.raises(FileExistsError):
        installation_iso.build_iso(source, payload, output, trust_key=trust)

    assert output.read_bytes() == b"keep"


def test_rejects_insufficient_capacity_before_opening_inputs_or_spooling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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
    source, payload, trust = _prepared_inputs(tmp_path, monkeypatch)
    alias = payload / "payload-alias"
    os.link(payload / "payload-manifest.json", alias)

    with pytest.raises(ValueError, match="hard-linked"):
        installation_iso.build_iso(source, payload, tmp_path / "atlaso.iso", trust_key=trust)


def test_rejects_output_inside_payload_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, payload, trust = _prepared_inputs(tmp_path, monkeypatch)
    output = payload / "atlaso.iso"

    with pytest.raises(ValueError, match="outside the payload root"):
        installation_iso.build_iso(source, payload, output, trust_key=trust)

    assert not output.exists()


def test_rejects_short_iso_name_collisions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, payload, trust = _prepared_inputs(tmp_path, monkeypatch)
    monkeypatch.setattr(installation_iso, "_iso_component", lambda _relative: "AAAAAAAA")
    output = tmp_path / "atlaso.iso"

    with pytest.raises(ValueError, match="name collision"):
        installation_iso.build_iso(source, payload, output, trust_key=trust)

    assert not output.exists()


def test_payload_remaster_scales_to_many_files_with_bounded_open_handles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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
