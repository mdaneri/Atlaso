"""Tests for consent-bound Photon installation disk selection."""

from __future__ import annotations

import pytest

from scripts.installation import disks


def _device(
    path: str,
    *,
    size: int = 128 * 1024**3,
    device_type: str = "disk",
    read_only: bool = False,
    major_minor: str = "8:0",
    mountpoints: list[str | None] | None = None,
    children: list[dict] | None = None,
) -> dict:
    """Build one lsblk-compatible device record.

Args:
    path: Path to the fixture or file being tested.
    size: Disk capacity recorded in the inventory fixture.
    device_type: Block-device type recorded in the inventory fixture.
    read_only: Whether the fixture device is marked read-only.
    major_minor: Linux major and minor device identity reported by lsblk.
    mountpoints: Mount points reported for the fixture device.
    children: Child block devices reported by the fixture.
"""
    return {
        "path": path,
        "type": device_type,
        "ro": read_only,
        "size": size,
        "model": "Test storage",
        "serial": f"serial-{path.rsplit('/', 1)[-1]}",
        "wwn": None,
        "maj:min": major_minor,
        "mountpoints": mountpoints or [],
        "children": children or [],
    }


def _config() -> dict:
    """Build an EFI plan with a separate custom data disk."""
    return {
        "arch": "x86_64",
        "bootmode": "efi",
        "disk": "/dev/nvme0n1",
        "partitions": [
            {"disk": "/dev/nvme0n1", "mountpoint": "/", "filesystem": "ext4"},
            {"disk": "/dev/nvme0n1", "mountpoint": "/boot/efi", "filesystem": "vfat"},
            {"disk": "/dev/sdb", "mountpoint": "/mnt/atlaso-vcf-backups", "filesystem": "xfs"},
        ],
    }


def _identity(path: str, *, serial: str | None = None) -> dict:
    """Build the exact identity projection captured from eligible inventory.

Args:
    path: Path to the fixture or file being tested.
    serial: Disk serial identity included in the fixture.
"""
    return {
        "path": path,
        "size": 128 * 1024**3,
        "serial": serial or f"serial-{path.rsplit('/', 1)[-1]}",
        "wwn": None,
        "maj:min": "8:0",
        "model": "Test storage",
    }


def test_eligible_disks_excludes_boot_media_and_every_busy_device() -> None:
    """Exclude media disks through mounted children, swap, holders, RO and loop devices."""
    inventory = {
        "blockdevices": [
            _device(
                "/dev/sda",
                children=[_device("/dev/sda1", device_type="part", mountpoints=["/run/media/iso"])],
            ),
            _device("/dev/sdb", children=[_device("/dev/sdb1", device_type="part")]),
            _device("/dev/sdc"),
            _device("/dev/sdd", read_only=True),
            _device("/dev/loop0"),
            _device("/dev/nvme0n1", children=[_device("/dev/nvme0n1p1", device_type="part")]),
        ]
    }

    eligible = disks.eligible_disks(
        inventory,
        swaps={"/dev/sdb1"},
        held={"/dev/sdc"},
    )

    assert set(eligible) == {"/dev/nvme0n1"}


def test_eligible_disks_reuses_photon_supported_device_majors() -> None:
    """Exclude major-2 floppies while admitting supported small, SCSI and NVMe disks."""
    inventory = {
        "blockdevices": [
            _device("/dev/fd0", size=1_474_560, major_minor="2:0"),
            _device("/dev/unusual-block", size=1_474_560, major_minor="2:1"),
            _device("/dev/sda", major_minor="8:0"),
            _device("/dev/sdb", size=4 * 1024**3, major_minor="8:16"),
            _device("/dev/nvme0n1", major_minor="259:0"),
        ]
    }

    eligible = disks.eligible_disks(inventory, swaps=set(), held=set())

    assert set(eligible) == {"/dev/sda", "/dev/sdb", "/dev/nvme0n1"}
    assert eligible["/dev/sdb"]["size"] == 4 * 1024**3


def test_selected_disks_includes_default_boot_disk_and_custom_data_disk() -> None:
    """Consent covers the whole default disk and every custom partition disk."""
    config = _config()

    assert disks.selected_disks(config) == ["/dev/nvme0n1", "/dev/sdb"]


def test_revalidate_accepts_unchanged_consent_for_root_efi_and_custom_mounts() -> None:
    """Accept a multi-disk plan only when its full selected device set is unchanged."""
    config = _config()
    consent = {path: _identity(path) for path in disks.selected_disks(config)}

    assert disks.revalidate_disks(config, consent, dict(consent)) is None


@pytest.mark.parametrize("target", ["/boot/grub2", "/boot/grub2/themes", "/boot/efi/EFI", "/boot/kernel"])
def test_revalidate_refuses_split_bootloader_filesystems(monkeypatch, target):
    """Refuse layouts the native EFI bootstrap cannot search before disk work.

    Args:
        monkeypatch: Detect unexpected native commands.
        target: Unsupported nested boot mount.
    """
    config = _config()
    config["partitions"].append({"disk": "/dev/nvme0n1", "mountpoint": target, "filesystem": "ext4"})
    consent = {path: _identity(path) for path in disks.selected_disks(config)}
    monkeypatch.setattr(disks.subprocess, "run", lambda *_args, **_kwargs: pytest.fail("boot refusal must precede native work"))
    monkeypatch.setattr(disks.subprocess, "check_output", lambda *_args, **_kwargs: pytest.fail("boot refusal must precede native work"))
    with pytest.raises(ValueError, match="Use /boot"):
        disks.revalidate_disks(config, consent, dict(consent))


@pytest.mark.parametrize("target", [
    "/opt/atlaso/.venv", "/opt/atlaso/.venv/bin", "/opt/atlaso/current", "/opt/atlaso/current/.venv",
    "/usr/local/bin/atlaso-vault", "/usr/local/bin/atlaso-vault/bin",
    "/usr/bin/atlaso-vault", "/usr/bin/atlaso-vault/bin",
    "/etc/systemd/system-generators/systemd-ssh-generator",
    "/etc/systemd/system-generators/systemd-ssh-generator/bin",
])
def test_revalidate_refuses_atlaso_symlink_mounts_before_native_work(monkeypatch, target):
    """Reject a forged plan even when UI validation was bypassed.

    Args:
        monkeypatch: Detect accidental native commands before refusal.
        target: Provisioning-owned link or a path beneath it.
    """
    config = _config()
    config["partitions"][2]["mountpoint"] = target
    consent = {path: _identity(path) for path in disks.selected_disks(config)}
    monkeypatch.setattr(disks.subprocess, "run", lambda *_args, **_kwargs: pytest.fail("refusal must precede native work"))
    monkeypatch.setattr(disks.subprocess, "check_output", lambda *_args, **_kwargs: pytest.fail("refusal must precede native work"))
    with pytest.raises(ValueError, match="Atlaso symlink"):
        disks.revalidate_disks(config, consent, dict(consent))


@pytest.mark.parametrize("target", [
    "/opt/atlaso", "/opt/atlaso/releases", "/opt/atlaso/current-data", "/opt/atlaso/.venv-data",
    "/usr/local/bin", "/usr/bin", "/etc/systemd/system-generators",
])
def test_revalidate_keeps_atlaso_symlink_parent_and_sibling_mounts(target):
    """Keep real directory mounts compatible with the generated links.

    Args:
        target: Supported parent or distinct sibling directory.
    """
    config = _config()
    config["partitions"][2]["mountpoint"] = target
    consent = {path: _identity(path) for path in disks.selected_disks(config)}
    disks.revalidate_disks(config, consent, dict(consent))


@pytest.mark.parametrize("target", ["/mnt/my data", "/mnt/my\tdata", "/mnt/my\ndata", r"/mnt/my\040data",
                                   r"/mnt/my\data", "/mnt/my\u00a0data", "/mnt/my\x7fdata"])
def test_revalidate_refuses_fstab_field_changes_before_native_work(monkeypatch, target):
    """Refuse malformed or escape-decoded mounts at the independent write gate.

    Args:
        monkeypatch: Detect any accidental native command.
        target: Custom mount text that cannot survive native fstab serialization.
    """
    config = _config()
    config["partitions"][2]["mountpoint"] = target
    consent = {path: _identity(path) for path in disks.selected_disks(config)}
    monkeypatch.setattr(disks.subprocess, "run", lambda *_args, **_kwargs: pytest.fail("refusal must precede native work"))
    monkeypatch.setattr(disks.subprocess, "check_output", lambda *_args, **_kwargs: pytest.fail("refusal must precede native work"))
    with pytest.raises(ValueError, match="No spaces"):
        disks.revalidate_disks(config, consent, dict(consent))


@pytest.mark.parametrize(
    ("root_filesystem", "boot_filesystem", "accepted"),
    [
        pytest.param("ext4", None, True, id="ext4-root-is-boot-filesystem"),
        pytest.param("xfs", None, False, id="xfs-root-without-separate-boot"),
        pytest.param("btrfs", None, False, id="btrfs-root-without-separate-boot"),
        pytest.param("xfs", "ext4", True, id="xfs-root-with-ext4-boot"),
        pytest.param("btrfs", "ext4", True, id="btrfs-root-with-ext4-boot"),
        pytest.param("ext4", "xfs", False, id="xfs-boot"),
        pytest.param("ext4", "btrfs", False, id="btrfs-boot"),
        pytest.param("ext4", "vfat", False, id="vfat-boot"),
        pytest.param("vfat", "ext4", False, id="vfat-root"),
        pytest.param("swap", "ext4", False, id="swap-root"),
    ],
)
def test_revalidate_requires_ext4_effective_boot_filesystem(
    monkeypatch: pytest.MonkeyPatch, root_filesystem: str, boot_filesystem: str | None, accepted: bool
) -> None:
    """Require an ext4 boot filesystem before confirmation.

    Args:
        monkeypatch: Detect any unexpected native command during validation.
        root_filesystem: Root filesystem used by the candidate layout.
        boot_filesystem: Optional separate boot filesystem.
        accepted: Whether the boot-readable layout should pass validation.
    """
    config = _config()
    config["partitions"][0]["filesystem"] = root_filesystem
    if boot_filesystem is not None:
        config["partitions"].append(
            {"disk": "/dev/nvme0n1", "mountpoint": "/boot", "filesystem": boot_filesystem}
        )
    consent = {path: _identity(path) for path in disks.selected_disks(config)}

    if not accepted:
        monkeypatch.setattr(disks.subprocess, "run", lambda *args, **kwargs: pytest.fail("layout validation must not start native work"))
        monkeypatch.setattr(disks.subprocess, "check_output", lambda *args, **kwargs: pytest.fail("layout validation must not probe or mutate devices"))
        with pytest.raises(ValueError, match="root filesystem|boot filesystem"):
            disks.revalidate_disks(config, consent, dict(consent))
    else:
        assert disks.revalidate_disks(config, consent, dict(consent)) is None


@pytest.mark.parametrize("data_filesystem", ["ext4", "xfs", "btrfs", "vfat", "swap"])
def test_revalidate_preserves_supported_nonboot_filesystems(data_filesystem: str) -> None:
    """Keep supported data filesystems when root supplies ext4 boot files.

    Args:
        data_filesystem: Filesystem selected for a separate nonboot partition.
    """
    config = _config()
    data_partition = config["partitions"][2]
    data_partition["filesystem"] = data_filesystem
    if data_filesystem == "swap":
        data_partition["mountpoint"] = None
    consent = {path: _identity(path) for path in disks.selected_disks(config)}

    assert disks.revalidate_disks(config, consent, dict(consent)) is None


@pytest.mark.parametrize(
    ("consent_change", "inventory_change"),
    [
        pytest.param("none", "identity", id="device-identity-changed"),
        pytest.param("none", "missing", id="selected-device-disappeared"),
        pytest.param("missing", "none", id="consent-omitted-selected-disk"),
        pytest.param("extra", "none", id="consent-added-unselected-disk"),
    ],
)
def test_revalidate_cancels_changed_identity_or_selected_set_before_native_work(
    monkeypatch: pytest.MonkeyPatch, consent_change: str, inventory_change: str
) -> None:
    """Stop before native mutations when disk identity or the consent set changes.

Args:
    monkeypatch: Pytest fixture for replacing controlled dependencies.
    consent_change: Consent identity change applied by the parameterized case.
    inventory_change: Current inventory change applied by the parameterized case.
"""
    config = _config()
    selected = disks.selected_disks(config)
    consent = {path: _identity(path) for path in selected}
    current = dict(consent)
    if consent_change == "missing":
        consent.pop("/dev/sdb")
    elif consent_change == "extra":
        consent["/dev/sdc"] = _identity("/dev/sdc")
    if inventory_change == "identity":
        current["/dev/sdb"] = _identity("/dev/sdb", serial="replacement-device")
    elif inventory_change == "missing":
        current.pop("/dev/sdb")

    monkeypatch.setattr(disks.subprocess, "run", lambda *args, **kwargs: pytest.fail("revalidation must not start native work"))
    monkeypatch.setattr(disks.subprocess, "check_output", lambda *args, **kwargs: pytest.fail("revalidation must not probe or mutate devices"))

    with pytest.raises(ValueError, match="confirmed plan|identity or availability changed"):
        disks.revalidate_disks(config, consent, current)


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        pytest.param("bootmode", "legacy", "x86-64 UEFI", id="non-efi-plan"),
        pytest.param("arch", "aarch64", "x86-64 UEFI", id="non-x86-64-plan"),
    ],
)
def test_revalidate_rejects_unsupported_boot_or_architecture(key: str, value: str, message: str) -> None:
    """Keep the admitted installation target x86-64 UEFI.

Args:
    key: Configuration key selected by the parameterized case.
    value: Value supplied to the test case.
    message: Expected validation message or prompt text.
"""
    config = _config()
    config[key] = value
    consent = {path: _identity(path) for path in disks.selected_disks(config)}

    with pytest.raises(ValueError, match=message):
        disks.revalidate_disks(config, consent, dict(consent))


@pytest.mark.parametrize(
    ("target", "message"),
    [
        pytest.param("relative/path", "not canonical", id="relative-path"),
        pytest.param("/mnt/../data", "not canonical", id="path-traversal"),
        pytest.param("/proc/atlaso", "reserved", id="reserved-proc-child"),
        pytest.param("/mnt/atlaso-install/media", "reserved", id="installer-media-child"),
    ],
)
def test_revalidate_rejects_noncanonical_or_reserved_mounts(target: str, message: str) -> None:
    """Refuse unsafe custom mount targets in the confirmed layout.

Args:
    target: Destination root or target under test.
    message: Expected validation message or prompt text.
"""
    config = _config()
    config["partitions"][2]["mountpoint"] = target
    consent = {path: _identity(path) for path in disks.selected_disks(config)}

    with pytest.raises(ValueError, match=message):
        disks.revalidate_disks(config, consent, dict(consent))
