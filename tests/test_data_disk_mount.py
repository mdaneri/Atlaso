"""Behavior tests for fail-closed first-boot data-disk selection."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

MOUNT_SCRIPT = Path("scripts/appliance/atlaso-mount-data-disks")
EXPECTED_SIZE = 536_870_912_000


def _disk(
    path: Path,
    tuple_value: str,
    *,
    size: int = EXPECTED_SIZE,
    filesystem: str = "",
    label: str = "",
    uuid: str = "",
    scsi_host: int = 1,
) -> dict[str, object]:
    """Build one fake whole-disk record.

    Args:
        path: Fake block-device path.
        tuple_value: Guest-visible SCSI channel, target, and LUN tuple.
        size: Reported disk capacity in bytes.
        filesystem: Whole-disk filesystem type, when present.
        label: Whole-disk filesystem label, when present.
        uuid: Whole-disk filesystem UUID, when present.
        scsi_host: Linux SCSI host/controller number for the fake device.

    Returns:
        Mutable disk state consumed by the fake command harness.
    """
    return {
        "path": str(path),
        "tuple": tuple_value,
        "size": size,
        "filesystem": filesystem,
        "label": label,
        "uuid": uuid,
        "scsi_host": scsi_host,
        "partitions": False,
        "read_only": False,
    }


def _run_mount_script(
    tmp_path: Path,
    disks: list[dict[str, object]],
    *,
    depot_tuple: str,
    backup_tuple: str,
    mounts: dict[str, str] | None = None,
    mount_sources: dict[str, str] | None = None,
    mount_options: dict[str, str] | None = None,
    fstab: str = "",
    esx_allowlist: str = "",
) -> tuple[subprocess.CompletedProcess[str], list[list[str]]]:
    """Execute the appliance mount script against fake block-device commands.

    Args:
        tmp_path: Isolated filesystem root for the behavior scenario.
        disks: Fake whole-disk records exposed to the mount script.
        depot_tuple: Trusted depot SCSI identity from image policy.
        backup_tuple: Trusted backup SCSI identity from image policy.
        mounts: Initial mapping from mountpoints to fake disk paths.
        mount_sources: Fake fstab mount selections keyed by mountpoint.
        mount_options: Fake mount options keyed by mountpoint.
        fstab: Initial fake fstab content.
        esx_allowlist: Initial root-owned managed ESX Storage disk claims.

    Returns:
        Completed shell process and recorded ``mkfs.ext4`` argument lists.
    """
    if os.name == "nt" or shutil.which("sh") is None:
        pytest.skip("the appliance shell behavior harness requires a native POSIX shell")

    dev_root = tmp_path / "dev"
    by_id_root = dev_root / "disk" / "by-id"
    sys_root = tmp_path / "sys" / "class" / "block"
    scsi_generic_sys_root = tmp_path / "sys" / "class" / "scsi_generic"
    scsi_generic_device_root = dev_root / "scsi-generic"
    bsg_sys_root = tmp_path / "sys" / "class" / "bsg"
    bsg_device_root = dev_root / "bsg"
    raw_device_root = dev_root / "raw"
    fake_bin = tmp_path / "bin"
    by_id_root.mkdir(parents=True)
    sys_root.mkdir(parents=True)
    scsi_generic_sys_root.mkdir(parents=True)
    scsi_generic_device_root.mkdir(parents=True)
    bsg_sys_root.mkdir(parents=True)
    bsg_device_root.mkdir(parents=True)
    raw_device_root.mkdir(parents=True)
    fake_bin.mkdir()

    root_partition = dev_root / "sda1"
    root_partition.touch()
    for disk_index, disk in enumerate(disks):
        path = Path(str(disk["path"]))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
        if disk.get("partitions"):
            Path(f"{path}1").touch()
        block_root = sys_root / path.name
        (block_root / "holders").mkdir(parents=True)
        if disk.get("holders"):
            (block_root / "holders" / "dm-test").touch()
        scsi_device = tmp_path / "scsi" / f"{disk['scsi_host']}:{disk['tuple']}"
        scsi_device.mkdir(parents=True, exist_ok=True)
        (block_root / "device").symlink_to(scsi_device, target_is_directory=True)
        generic_name = f"sg{disk_index}"
        generic_path = scsi_generic_device_root / generic_name
        generic_path.touch()
        generic_sys_root = scsi_generic_sys_root / generic_name
        generic_sys_root.mkdir()
        (generic_sys_root / "device").symlink_to(scsi_device, target_is_directory=True)
        disk["scsi_generic_path"] = str(generic_path)
        bsg_name = f"{disk['scsi_host']}:{disk['tuple']}"
        bsg_path = bsg_device_root / bsg_name
        bsg_path.touch()
        bsg_sys_device_root = bsg_sys_root / bsg_name
        bsg_sys_device_root.mkdir(exist_ok=True)
        bsg_device_link = bsg_sys_device_root / "device"
        if not bsg_device_link.exists():
            bsg_device_link.symlink_to(scsi_device, target_is_directory=True)
        disk["bsg_path"] = str(bsg_path)
        raw_path = raw_device_root / f"raw{disk_index + 1}"
        raw_path.touch()
        disk["raw_path"] = str(raw_path)
        if path.name != "sda":
            (by_id_root / f"atlaso-path-test-{path.name}").symlink_to(path)

    state_path = tmp_path / "state.json"
    state_path.write_text(
        json.dumps(
            {
                "disks": disks,
                "mounts": mounts or {},
                "mount_sources": mount_sources or {},
                "mount_options": mount_options or {},
            }
        ),
        encoding="utf-8",
    )
    mkfs_log = tmp_path / "mkfs.jsonl"
    fstab_path = tmp_path / "fstab"
    fstab_path.write_text(fstab, encoding="utf-8")
    esx_allowlist_path = tmp_path / "esx-storage-disks.conf"
    esx_allowlist_path.write_text(esx_allowlist, encoding="utf-8")
    fake_command = fake_bin / "atlaso-fake-command"
    fake_command.write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import json
            import os
            import sys
            from pathlib import Path

            command = Path(sys.argv[0]).name
            args = sys.argv[1:]
            state_path = Path(os.environ["ATLASO_TEST_STATE"])
            state = json.loads(state_path.read_text(encoding="utf-8"))
            disks = state["disks"]
            mounts = state["mounts"]
            mount_sources = state["mount_sources"]
            mount_options = state["mount_options"]

            def disk_for(value):
                resolved = str(Path(value).resolve())
                disk = next((disk for disk in disks if str(Path(disk["path"]).resolve()) == resolved), None)
                if disk:
                    return disk
                parent = next(
                    (
                        disk
                        for disk in disks
                        if disk.get("partitions") and str(Path(f'{disk["path"]}1').resolve()) == resolved
                    ),
                    None,
                )
                if not parent:
                    return None
                return {
                    "path": f'{parent["path"]}1',
                    "filesystem": parent.get("partition_filesystem", ""),
                    "label": parent.get("partition_label", ""),
                    "uuid": parent.get("partition_uuid", ""),
                }

            if command == "findmnt":
                if args == ["-n", "-o", "SOURCE", "/"]:
                    print(os.environ["ATLASO_TEST_ROOT_PARTITION"])
                    raise SystemExit(0)
                if (
                    len(args) == 5
                    and args[:2] == ["-rn", "-S"]
                    and args[3:] == ["-o", "TARGET"]
                ) or (
                    len(args) == 6
                    and args[:3] == ["-rn", "--raw", "-S"]
                    and args[4:] == ["-o", "TARGET"]
                ):
                    disk = disk_for(args[3] if "--raw" in args else args[2])
                    for target, source in mounts.items():
                        if disk and disk_for(source) is disk:
                            print(
                                target.replace("\\\\", "\\\\x5c").replace(" ", "\\\\x20")
                                if "--raw" in args
                                else target
                            )
                    raise SystemExit(0)
                if len(args) == 5 and args[:2] == ["-rn", "-M"] and args[3:] == ["-o", "UUID"]:
                    source = mounts.get(args[2])
                    disk = disk_for(source) if source else None
                    if disk and disk["uuid"]:
                        print(disk["uuid"])
                        raise SystemExit(0)
                    raise SystemExit(1)
                if len(args) == 5 and args[:2] == ["-rn", "-M"] and args[3:] == ["-o", "SOURCE"]:
                    source = mounts.get(args[2])
                    if source:
                        print(source)
                        raise SystemExit(0)
                    raise SystemExit(1)
                if len(args) == 5 and args[:2] == ["-rn", "-M"] and args[3:] == ["-o", "OPTIONS"]:
                    if args[2] in mounts:
                        print(mount_options.get(args[2], "rw,relatime"))
                        raise SystemExit(0)
                    raise SystemExit(1)
                raise SystemExit(1)
            if command == "lsblk":
                if args[:3] == ["-dn", "-o", "PATH,TYPE"]:
                    for disk in disks:
                        print(f'{disk["path"]} disk')
                    raise SystemExit(0)
                if args[:3] == ["-nr", "-o", "PATH,TYPE"]:
                    for disk in disks:
                        print(f'{disk["path"]} disk')
                        if disk["partitions"]:
                            print(f'{disk["path"]}1 part')
                    raise SystemExit(0)
                value = args[-1]
                disk = disk_for(value)
                if args[:2] == ["-no", "PKNAME"]:
                    print("sda")
                elif args[:3] == ["-dn", "-o", "TYPE"]:
                    print("disk")
                elif args[:3] == ["-bdn", "-o", "SIZE"]:
                    print(disk["size"])
                elif args[:3] == ["-dn", "-o", "RO"]:
                    print("1" if disk["read_only"] else "0")
                elif args[:3] == ["-nr", "-o", "TYPE"]:
                    print("disk")
                    if disk["partitions"]:
                        print("part")
                else:
                    raise SystemExit(2)
                raise SystemExit(0)
            if command == "blkid":
                if args[:1] == ["-L"]:
                    match = next((disk for disk in disks if disk["label"] == args[1]), None)
                    if match:
                        print(match["path"])
                        raise SystemExit(0)
                    raise SystemExit(2)
                disk = disk_for(args[-1])
                field = args[args.index("-s") + 1]
                values = {"TYPE": disk["filesystem"], "UUID": disk["uuid"], "LABEL": disk["label"]}
                value = values[field]
                if value:
                    print(value)
                    raise SystemExit(0)
                raise SystemExit(2)
            if command == "mkfs.ext4":
                disk = disk_for(args[-1])
                label = args[args.index("-L") + 1]
                disk.update(filesystem="ext4", label=label, uuid=f"uuid-{label.lower()}")
                state_path.write_text(json.dumps(state), encoding="utf-8")
                with Path(os.environ["ATLASO_TEST_MKFS_LOG"]).open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(args) + "\\n")
                raise SystemExit(0)
            if command == "mount":
                target = args[0]
                label = "ATLASO_DEPOT" if target.endswith("offline-depot") else "ATLASO_BKUP"
                selected_source = mount_sources.get(target)
                if not selected_source:
                    selected_source = next(disk["path"] for disk in disks if disk["label"] == label)
                mounts[target] = selected_source
                state_path.write_text(json.dumps(state), encoding="utf-8")
                raise SystemExit(0)
            if command == "raw":
                disk = next((disk for disk in disks if disk.get("raw_path") == args[-1]), None)
                if args[:1] == ["-q"] and disk:
                    print(f'{args[-1]}: bound to major 0, minor 0')
                    raise SystemExit(0)
                raise SystemExit(1)
            if command in {"install", "chown", "chmod", "logger"}:
                raise SystemExit(0)
            raise SystemExit(2)
            """
        ),
        encoding="utf-8",
    )
    fake_command.chmod(0o755)
    for command in ["findmnt", "lsblk", "blkid", "mkfs.ext4", "install", "mount", "chown", "chmod", "logger", "raw"]:
        (fake_bin / command).symlink_to(fake_command)

    policy_path = tmp_path / "data-disks.conf"
    policy_path.write_text(
        "\n".join(
            [
                f"ATLASO_DATA_DISK_SIZE_BYTES={EXPECTED_SIZE}",
                f"ATLASO_DEPOT_SCSI_TUPLE={depot_tuple}",
                f"ATLASO_BACKUP_SCSI_TUPLE={backup_tuple}",
                f"ATLASO_SYSTEM_SCSI_TUPLE={'0:1:0' if depot_tuple == '0:2:0' else ''}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
            "ATLASO_DATA_DISK_POLICY_PATH": str(policy_path),
            "ATLASO_DATA_DISK_BY_ID_ROOT": str(by_id_root),
            "ATLASO_DATA_DISK_SYS_BLOCK_ROOT": str(sys_root),
            "ATLASO_DATA_DISK_SCSI_GENERIC_DEVICE_ROOT": str(scsi_generic_device_root),
            "ATLASO_DATA_DISK_SCSI_GENERIC_SYS_ROOT": str(scsi_generic_sys_root),
            "ATLASO_DATA_DISK_BSG_DEVICE_ROOT": str(bsg_device_root),
            "ATLASO_DATA_DISK_BSG_SYS_ROOT": str(bsg_sys_root),
            "ATLASO_DATA_DISK_RAW_DEVICE_ROOT": str(raw_device_root),
            "ATLASO_DATA_DISK_FSTAB_PATH": str(fstab_path),
            "ATLASO_ESX_STORAGE_ALLOWLIST_PATH": str(esx_allowlist_path),
            "ATLASO_TEST_STATE": str(state_path),
            "ATLASO_TEST_ROOT_PARTITION": str(root_partition),
            "ATLASO_TEST_MKFS_LOG": str(mkfs_log),
        }
    )
    open_handles = [Path(str(disk["path"])).open("rb") for disk in disks if disk.get("open_raw")]
    open_handles.extend(
        Path(str(disk["scsi_generic_path"])).open("rb") for disk in disks if disk.get("open_scsi_generic")
    )
    open_handles.extend(Path(str(disk["bsg_path"])).open("rb") for disk in disks if disk.get("open_bsg"))
    open_handles.extend(Path(str(disk["raw_path"])).open("rb") for disk in disks if disk.get("open_bound_raw"))
    try:
        completed = subprocess.run(
            ["sh", str(MOUNT_SCRIPT.resolve())],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
    finally:
        for handle in open_handles:
            handle.close()
    calls = [json.loads(line) for line in mkfs_log.read_text(encoding="utf-8").splitlines()] if mkfs_log.exists() else []
    return completed, calls


def _vmware_disks(tmp_path: Path) -> list[dict[str, object]]:
    """Build the expected four-disk VMware topology.

    Args:
        tmp_path: Isolated filesystem root for fake block devices.

    Returns:
        Photon, system-content, depot, and backup disk records.
    """
    dev = tmp_path / "dev"
    return [
        _disk(dev / "sda", "0:0:0", size=64 * 1024**3, filesystem="ext4", label="PHOTON_ROOT"),
        _disk(dev / "sdb", "0:1:0", size=16 * 1024**3, filesystem="ext4", label="ATLASO_SYSTEM"),
        _disk(dev / "sdc", "0:2:0"),
        _disk(dev / "sdd", "0:3:0"),
    ]


def test_vmware_first_boot_formats_only_fixed_identity_disks(tmp_path: Path):
    """Format only the fixed VMware depot and backup identities.

    Args:
        tmp_path: Pytest-provided isolated filesystem root.
    """
    completed, calls = _run_mount_script(
        tmp_path,
        _vmware_disks(tmp_path),
        depot_tuple="0:2:0",
        backup_tuple="0:3:0",
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert [call[call.index("-L") + 1] for call in calls] == ["ATLASO_DEPOT", "ATLASO_BKUP"]
    assert [Path(call[-1]).name for call in calls] == ["sdc", "sdd"]
    assert all("atlaso-path-test-" not in call[-1] for call in calls)


def test_hyperv_first_boot_uses_fixed_controller_locations(tmp_path: Path):
    """Use the fixed Hyper-V controller locations for both data disks.

    Args:
        tmp_path: Pytest-provided isolated filesystem root.
    """
    dev = tmp_path / "dev"
    disks = [
        _disk(dev / "sda", "0:0:0", size=64 * 1024**3, filesystem="ext4", label="PHOTON_ROOT"),
        _disk(dev / "sdb", "0:0:1"),
        _disk(dev / "sdc", "0:0:2"),
    ]

    completed, calls = _run_mount_script(
        tmp_path,
        disks,
        depot_tuple="0:0:1",
        backup_tuple="0:0:2",
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert len(calls) == 2


@pytest.mark.parametrize(
    "scenario",
    [
        "extra",
        "extra_formatted",
        "identity",
        "controller",
        "ambiguous",
        "undersized",
        "oversized",
        "reordered",
        "partition_label",
        "read_only",
        "in_use",
        "raw_open",
        "scsi_generic_open",
        "bsg_open",
        "bound_raw_open",
        "mounted_elsewhere",
        "destination_occupied",
    ],
)
def test_first_boot_fails_before_mkfs_for_unsafe_topology(tmp_path: Path, scenario: str):
    """Reject unsafe disk topology before the first formatting command.

    Args:
        tmp_path: Pytest-provided isolated filesystem root.
        scenario: Unsafe topology mutation to apply to the VMware baseline.
    """
    disks = _vmware_disks(tmp_path)
    if scenario == "extra":
        disks.append(_disk(tmp_path / "dev" / "sde", "0:4:0"))
    elif scenario == "extra_formatted":
        disks.append(
            _disk(
                tmp_path / "dev" / "sde",
                "0:4:0",
                filesystem="ext4",
                label="UNRELATED",
                uuid="unrelated-uuid",
            )
        )
    elif scenario == "identity":
        disks[2]["tuple"] = "0:4:0"
    elif scenario == "controller":
        disks[2]["scsi_host"] = 2
    elif scenario == "ambiguous":
        disks.append(_disk(tmp_path / "dev" / "sde", "0:2:0"))
    elif scenario == "undersized":
        disks[2]["size"] = EXPECTED_SIZE - 1
    elif scenario == "oversized":
        disks[2]["size"] = EXPECTED_SIZE + 1
    elif scenario == "reordered":
        disks[2].update(filesystem="ext4", label="ATLASO_BKUP", uuid="backup-on-depot")
        disks[3].update(filesystem="ext4", label="ATLASO_DEPOT", uuid="depot-on-backup")
    elif scenario == "partition_label":
        disks[1].update(
            partitions=True,
            partition_filesystem="ext4",
            partition_label="ATLASO_DEPOT",
            partition_uuid="foreign-depot",
        )
    elif scenario == "read_only":
        disks[2]["read_only"] = True
    elif scenario == "in_use":
        disks[2]["holders"] = True
    elif scenario == "raw_open":
        disks[2]["open_raw"] = True
    elif scenario == "scsi_generic_open":
        disks[2]["open_scsi_generic"] = True
    elif scenario == "bsg_open":
        disks[2]["open_bsg"] = True
    elif scenario == "bound_raw_open":
        disks[2]["open_bound_raw"] = True
    elif scenario == "mounted_elsewhere":
        disks[2].update(filesystem="ext4", label="ATLASO_DEPOT", uuid="mounted-depot")
    else:
        disks[1]["uuid"] = "system-uuid"

    mounts = None
    if scenario == "mounted_elsewhere":
        mounts = {"/mnt/unexpected": str(disks[2]["path"])}
    elif scenario == "destination_occupied":
        mounts = {"/mnt/atlaso-vcf-offline-depot": str(disks[1]["path"])}

    completed, calls = _run_mount_script(
        tmp_path,
        disks,
        depot_tuple="0:2:0",
        backup_tuple="0:3:0",
        mounts=mounts,
    )

    assert completed.returncode != 0
    assert "safety check failed" in completed.stdout + completed.stderr
    assert calls == []


def test_labeled_identity_disks_are_idempotent(tmp_path: Path):
    """Keep correctly labeled disks mounted without reformatting.

    Args:
        tmp_path: Pytest-provided isolated filesystem root.
    """
    disks = _vmware_disks(tmp_path)
    disks[2].update(filesystem="ext4", label="ATLASO_DEPOT", uuid="depot-uuid")
    disks[3].update(filesystem="ext4", label="ATLASO_BKUP", uuid="backup-uuid")

    completed, calls = _run_mount_script(
        tmp_path,
        disks,
        depot_tuple="0:2:0",
        backup_tuple="0:3:0",
        mounts={
            "/mnt/atlaso-vcf-offline-depot": str(disks[2]["path"]),
            "/mnt/atlaso-vcf-backups": str(disks[3]["path"]),
        },
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert calls == []


def test_mount_rejects_duplicate_uuid_source_outside_fixed_identity(tmp_path: Path):
    """Reject a UUID-selected mount when it resolves to a different fixed-topology disk.

    Args:
        tmp_path: Pytest-provided isolated filesystem root.
    """
    disks = _vmware_disks(tmp_path)
    disks[1]["uuid"] = "depot-uuid"
    disks[2].update(filesystem="ext4", label="ATLASO_DEPOT", uuid="depot-uuid")
    disks[3].update(filesystem="ext4", label="ATLASO_BKUP", uuid="backup-uuid")
    depot_mount = "/mnt/atlaso-vcf-offline-depot"

    completed, calls = _run_mount_script(
        tmp_path,
        disks,
        depot_tuple="0:2:0",
        backup_tuple="0:3:0",
        mount_sources={depot_mount: str(disks[1]["path"])},
    )

    assert completed.returncode != 0
    assert "mounted from a block device outside the trusted ATLASO_DEPOT identity" in (
        completed.stdout + completed.stderr
    )
    assert calls == []


def test_initialized_appliance_allows_only_managed_esx_storage_disk(tmp_path: Path):
    """Allow a positively identified managed ESX Storage disk after initialization.

    Args:
        tmp_path: Pytest-provided isolated filesystem root.
    """
    disks = _vmware_disks(tmp_path)
    disks[2].update(filesystem="ext4", label="ATLASO_DEPOT", uuid="depot-uuid")
    disks[3].update(filesystem="ext4", label="ATLASO_BKUP", uuid="backup-uuid")
    esx_disk = _disk(
        tmp_path / "dev" / "sde",
        "0:4:0",
        filesystem="ext4",
        label="lf-0123456789ab",
        uuid="esx-uuid",
    )
    disks.append(esx_disk)
    esx_mount = "/mnt/atlaso-esx-storage/datastore"
    mounts = {
        "/mnt/atlaso-vcf-offline-depot": str(disks[2]["path"]),
        "/mnt/atlaso-vcf-backups": str(disks[3]["path"]),
        esx_mount: str(esx_disk["path"]),
    }
    fstab = "\n".join(
        [
            "# BEGIN ATLASO ESX STORAGE",
            f"UUID=esx-uuid {esx_mount} ext4 defaults,nofail,x-systemd.device-timeout=30 0 2",
            "# END ATLASO ESX STORAGE",
            "",
        ]
    )
    stable_id = tmp_path / "dev" / "disk" / "by-id" / "atlaso-path-test-sde"
    allowlist = f"esx-uuid\t{stable_id}\t{esx_mount}\tblank_disk\n"

    completed, calls = _run_mount_script(
        tmp_path,
        disks,
        depot_tuple="0:2:0",
        backup_tuple="0:3:0",
        mounts=mounts,
        fstab=fstab,
        esx_allowlist=allowlist,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert calls == []


def test_initialized_appliance_mounts_managed_esx_storage_before_preflight(tmp_path: Path):
    """Mount and verify a claimed managed disk without relying on systemd fstab timing.

    Args:
        tmp_path: Pytest-provided isolated filesystem root.
    """
    disks = _vmware_disks(tmp_path)
    disks[2].update(filesystem="ext4", label="ATLASO_DEPOT", uuid="depot-uuid")
    disks[3].update(filesystem="ext4", label="ATLASO_BKUP", uuid="backup-uuid")
    esx_disk = _disk(
        tmp_path / "dev" / "sde",
        "0:4:0",
        filesystem="ext4",
        label="lf-0123456789ab",
        uuid="esx-uuid",
    )
    disks.append(esx_disk)
    esx_mount = "/mnt/atlaso-esx-storage/datastore"
    fstab = "\n".join(
        [
            "# BEGIN ATLASO ESX STORAGE",
            f"UUID=esx-uuid {esx_mount} ext4 defaults,nofail,x-systemd.device-timeout=30 0 2",
            "# END ATLASO ESX STORAGE",
            "",
        ]
    )
    stable_id = tmp_path / "dev" / "disk" / "by-id" / "atlaso-path-test-sde"
    allowlist = f"esx-uuid\t{stable_id}\t{esx_mount}\tblank_disk\n"

    completed, calls = _run_mount_script(
        tmp_path,
        disks,
        depot_tuple="0:2:0",
        backup_tuple="0:3:0",
        mounts={
            "/mnt/atlaso-vcf-offline-depot": str(disks[2]["path"]),
            "/mnt/atlaso-vcf-backups": str(disks[3]["path"]),
        },
        mount_sources={esx_mount: str(esx_disk["path"])},
        fstab=fstab,
        esx_allowlist=allowlist,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert calls == []


def test_initialized_appliance_rejects_formatted_esx_disk_with_wrong_claim(tmp_path: Path):
    """Reject an lf-labeled disk whose stable identity differs from its applied claim.

    Args:
        tmp_path: Pytest-provided isolated filesystem root.
    """
    disks = _vmware_disks(tmp_path)
    disks[2].update(filesystem="ext4", label="ATLASO_DEPOT", uuid="depot-uuid")
    disks[3].update(filesystem="ext4", label="ATLASO_BKUP", uuid="backup-uuid")
    esx_disk = _disk(
        tmp_path / "dev" / "sde",
        "0:4:0",
        filesystem="ext4",
        label="lf-0123456789ab",
        uuid="esx-uuid",
    )
    disks.append(esx_disk)
    esx_mount = "/mnt/atlaso-esx-storage/datastore"
    fstab = "\n".join(
        [
            "# BEGIN ATLASO ESX STORAGE",
            f"UUID=esx-uuid {esx_mount} ext4 defaults,nofail,x-systemd.device-timeout=30 0 2",
            "# END ATLASO ESX STORAGE",
            "",
        ]
    )
    wrong_id = tmp_path / "dev" / "disk" / "by-id" / "atlaso-path-test-sdb"

    completed, calls = _run_mount_script(
        tmp_path,
        disks,
        depot_tuple="0:2:0",
        backup_tuple="0:3:0",
        mounts={
            "/mnt/atlaso-vcf-offline-depot": str(disks[2]["path"]),
            "/mnt/atlaso-vcf-backups": str(disks[3]["path"]),
            esx_mount: str(esx_disk["path"]),
        },
        fstab=fstab,
        esx_allowlist=f"esx-uuid\t{wrong_id}\t{esx_mount}\n",
    )

    assert completed.returncode != 0
    assert "unexpected whole disk" in completed.stdout + completed.stderr
    assert calls == []


def test_initialized_appliance_rejects_relabelled_formatted_esx_disk(tmp_path: Path):
    """Reject a typed formatted-disk claim after its Atlaso label is replaced.

    Args:
        tmp_path: Pytest-provided isolated filesystem root.
    """
    disks = _vmware_disks(tmp_path)
    disks[2].update(filesystem="ext4", label="ATLASO_DEPOT", uuid="depot-uuid")
    disks[3].update(filesystem="ext4", label="ATLASO_BKUP", uuid="backup-uuid")
    esx_disk = _disk(
        tmp_path / "dev" / "sde",
        "0:4:0",
        filesystem="ext4",
        label="operator-relabelled",
        uuid="esx-uuid",
    )
    disks.append(esx_disk)
    esx_mount = "/mnt/atlaso-esx-storage/datastore"
    stable_id = tmp_path / "dev" / "disk" / "by-id" / "atlaso-path-test-sde"
    fstab = "\n".join(
        [
            "# BEGIN ATLASO ESX STORAGE",
            f"UUID=esx-uuid {esx_mount} ext4 defaults,nofail,x-systemd.device-timeout=30 0 2",
            "# END ATLASO ESX STORAGE",
            "",
        ]
    )

    completed, calls = _run_mount_script(
        tmp_path,
        disks,
        depot_tuple="0:2:0",
        backup_tuple="0:3:0",
        mounts={
            "/mnt/atlaso-vcf-offline-depot": str(disks[2]["path"]),
            "/mnt/atlaso-vcf-backups": str(disks[3]["path"]),
            esx_mount: str(esx_disk["path"]),
        },
        fstab=fstab,
        esx_allowlist=f"esx-uuid\t{stable_id}\t{esx_mount}\tblank_disk\n",
    )

    assert completed.returncode != 0
    assert "unexpected whole disk" in completed.stdout + completed.stderr
    assert calls == []


@pytest.mark.parametrize(
    ("esx_mount_options", "fstab_options", "accepted"),
    [
        ("rw,relatime", "defaults", True),
        ("ro,relatime", "defaults", False),
        ("rw,relatime", "defaults,ro", False),
    ],
)
def test_initialized_appliance_requires_writable_claimed_mounted_ext4_whole_disk(
    tmp_path: Path, esx_mount_options: str, fstab_options: str, accepted: bool
):
    """Require a stable UUID-persisted mounted ext4 disk to remain writable.

    Args:
        tmp_path: Pytest-provided isolated filesystem root.
        esx_mount_options: Mount options returned for the claimed ESX Storage path.
        fstab_options: Persistent mount options configured for the claimed path.
        accepted: Whether boot validation should accept the mount options.
    """
    disks = _vmware_disks(tmp_path)
    disks[2].update(filesystem="ext4", label="ATLASO_DEPOT", uuid="depot-uuid")
    disks[3].update(filesystem="ext4", label="ATLASO_BKUP", uuid="backup-uuid")
    esx_disk = _disk(
        tmp_path / "dev" / "sde",
        "0:4:0",
        filesystem="ext4",
        label="lf-0123456789ab",
        uuid="external-uuid",
    )
    disks.append(esx_disk)
    esx_mount = "/mnt/operator esx data"
    stable_id = tmp_path / "dev" / "disk" / "by-id" / "atlaso-path-test-sde"
    fstab = f"UUID=external-uuid /mnt/operator\\040esx\\040data ext4 {fstab_options} 0 2\n"
    allowlist = f"external-uuid\t{stable_id}\t{esx_mount}\tmounted_ext4\n"

    completed, calls = _run_mount_script(
        tmp_path,
        disks,
        depot_tuple="0:2:0",
        backup_tuple="0:3:0",
        mounts={
            "/mnt/atlaso-vcf-offline-depot": str(disks[2]["path"]),
            "/mnt/atlaso-vcf-backups": str(disks[3]["path"]),
            esx_mount: str(esx_disk["path"]),
        },
        mount_options={esx_mount: esx_mount_options},
        fstab=fstab,
        esx_allowlist=allowlist,
    )

    if accepted:
        assert completed.returncode == 0, completed.stdout + completed.stderr
    else:
        assert completed.returncode != 0
        assert "unexpected whole disk" in completed.stdout + completed.stderr
    assert calls == []
