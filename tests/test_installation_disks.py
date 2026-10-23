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
    mountpoints: list[str | None] | None = None,
    children: list[dict] | None = None,
) -> dict:
    """Build one lsblk-compatible device record.

Args:
    path: Path to the fixture or file being tested.
    size: Disk capacity recorded in the inventory fixture.
    device_type: Block-device type recorded in the inventory fixture.
    read_only: Whether the fixture device is marked read-only.
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
        "maj:min": "8:0",
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


def test_selected_disks_includes_default_boot_disk_and_custom_data_disk() -> None:
    """Consent covers the whole default disk and every custom partition disk."""
    config = _config()

    assert disks.selected_disks(config) == ["/dev/nvme0n1", "/dev/sdb"]


def test_revalidate_accepts_unchanged_consent_for_root_efi_and_custom_mounts() -> None:
    """Accept a multi-disk plan only when its full selected device set is unchanged."""
    config = _config()
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
