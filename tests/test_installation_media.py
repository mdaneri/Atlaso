"""USB/optical discovery, mount binding and physical source exclusion."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.installation import disks, media


def device(number, *, label=media.LABEL, fstype="iso9660", path="/dev/arbitrary"):
    """Build discovery input without encoding an enumeration assumption.

    Args:
        number: Kernel device number.
        label: Filesystem label.
        fstype: Filesystem type.
        path: Current kernel name.
    """
    return {"maj:min": number, "label": label, "fstype": fstype, "path": path}


def test_discovery_deduplicates_only_same_physical_origin(monkeypatch):
    """A hybrid disk and zero-offset partition are one medium; other disks are not.

    Args:
        monkeypatch: Isolated read-only sysfs provider.
    """
    locations = {"8:0": (Path("/physical/usb-a"), "8:0", "31", "0"),
                 "8:1": (Path("/physical/usb-a"), "8:0", "31", "0"),
                 "8:2": (Path("/physical/usb-a"), "8:0", "31", "2048"),
                 "8:16": (Path("/physical/usb-b"), "8:16", "32", "0")}
    monkeypatch.setattr(media, "block_location", locations.__getitem__)
    inventory = {"blockdevices": [device("8:0"), device("8:1")]}
    assert media.select_media(inventory)["maj:min"] == "8:0"
    for extra in ("8:2", "8:16"):
        with pytest.raises(ValueError, match="exactly one"):
            media.select_media({"blockdevices": [*inventory["blockdevices"], device(extra)]})


@pytest.mark.parametrize("records", [[], [device("8:0", fstype="vfat")], [device("8:0", label="PHOTON")]])
def test_missing_or_wrong_media_refuses_without_mount(monkeypatch, records):
    """No guessed label, extracted filesystem or network fallback is admitted.

    Args:
        monkeypatch: Detect accidental commands.
        records: Invalid discovery inventory.
    """
    monkeypatch.setattr(media.subprocess, "run", lambda *_a, **_k: pytest.fail("unexpected mutation"))
    with pytest.raises(ValueError, match="exactly one"):
        media.select_media({"blockdevices": records})


def test_mount_capture_binds_partition_to_disk_and_detects_replacement(monkeypatch, tmp_path):
    """Mounted partition and physical disk sequence are both invariant before writes.

    Args:
        monkeypatch: Replace only kernel read-only observations.
        tmp_path: Isolated filesystem used to stand in for mounted content.
    """
    payload = tmp_path / "atlaso"
    payload.mkdir()
    root = str(tmp_path.resolve())
    record = f"90 12 8:1 / {root} ro,nosuid,nodev,noexec - iso9660 /dev/renamed ro\n"
    original = Path.read_text

    def read_text(path, *args, **kwargs):
        """Return fixture mountinfo while retaining ordinary fixture reads.

        Args:
            path: Kernel or fixture path.
            *args: Text reader positional options.
            **kwargs: Text reader keyword options.
        """
        return record if str(path).replace("\\", "/") == "/proc/self/mountinfo" else original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read_text)
    monkeypatch.setattr(media.os, "major", lambda _dev: 8, raising=False)
    monkeypatch.setattr(media.os, "minor", lambda _dev: 1, raising=False)
    location = [Path("/physical/controller/usb-storage"), "8:0", "31", "0"]
    monkeypatch.setattr(media, "block_location", lambda _number: tuple(location))
    source = media.SourceMedia.capture(payload.resolve())
    assert source.backing == "8:0"
    source.validate()
    location[2] = "32"
    with pytest.raises(ValueError, match="identity changed"):
        source.validate()
    location[2] = "31"
    record = record.replace(" ro,", " rw,")
    with pytest.raises(ValueError, match="read-only"):
        source.validate()


def test_source_disk_and_other_usb_disks_never_become_targets():
    """Protect underlying physical identity even with absent mount/label metadata."""
    def disk(path, number, transport):
        """Build an otherwise eligible unmounted disk.

        Args:
            path: Arbitrary current enumeration.
            number: Physical kernel identity.
            transport: Observed native transport.
        """
        return {"path": path, "maj:min": number, "type": "disk", "ro": False,
                "size": 64 * 1024**3, "tran": transport}

    inventory = {"blockdevices": [disk("/dev/changed", "8:0", None),
                                   disk("/dev/not-source", "8:16", "usb"),
                                   disk("/dev/nvme0n1", "259:0", "nvme")]}
    eligible = disks.eligible_disks(inventory, swaps=set(), held=set(), source="8:0")
    assert set(eligible) == {"/dev/nvme0n1"}


def test_mount_refuses_replaced_device_before_native_mount(monkeypatch, tmp_path):
    """A reused path cannot replace the enumerated block device.

    Args:
        monkeypatch: Isolated device discovery and stat.
        tmp_path: Empty mountpoint.
    """
    monkeypatch.setattr(media, "select_media", lambda _inventory: device("8:1"))
    monkeypatch.setattr(media.subprocess, "check_output", lambda *_a, **_k: "{}")
    original = media.os.stat
    monkeypatch.setattr(media.os, "stat", lambda path, **kwargs:
                        SimpleNamespace(st_mode=0, st_rdev=0) if path == "/dev/arbitrary" else original(path, **kwargs))
    monkeypatch.setattr(media.subprocess, "run", lambda *_a, **_k: pytest.fail("unexpected mount"))
    with pytest.raises(ValueError, match="identity changed"):
        media.mount_media(tmp_path.resolve())


def test_partition_backing_resolution_uses_sysfs_not_device_names(monkeypatch, tmp_path):
    """An arbitrary partition name resolves only through its kernel parent.

    Args:
        monkeypatch: Redirect the kernel's device-number link observation.
        tmp_path: Synthetic physical sysfs tree.
    """
    disk = tmp_path / "controller" / "physical-disk"
    partition = disk / "arbitrary-partition"
    partition.mkdir(parents=True)
    (disk / "slaves").mkdir()
    (disk / "dev").write_text("259:12")
    (disk / "diskseq").write_text("89")
    (partition / "partition").write_text("1")
    (partition / "start").write_text("2048")
    original = Path.resolve

    def resolve(path, *args, **kwargs):
        """Supply exactly one kernel link, retaining all ordinary path checks.

        Args:
            path: Device-number link or fixture path.
            *args: Resolver positional options.
            **kwargs: Resolver keyword options.
        """
        return partition if str(path).replace("\\", "/") == "/sys/dev/block/259:13" else original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", resolve)
    assert media.block_location("259:13") == (disk, "259:12", "89", "2048")
    (disk / "slaves" / "mapper").touch()
    with pytest.raises(ValueError, match="plain physical"):
        media.block_location("259:13")
