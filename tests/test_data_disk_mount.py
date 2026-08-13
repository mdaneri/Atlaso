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
) -> dict[str, object]:
    """Build one fake whole-disk record.

    Args:
        path: Fake block-device path.
        tuple_value: Guest-visible SCSI channel, target, and LUN tuple.
        size: Reported disk capacity in bytes.
        filesystem: Whole-disk filesystem type, when present.
        label: Whole-disk filesystem label, when present.
        uuid: Whole-disk filesystem UUID, when present.

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
) -> tuple[subprocess.CompletedProcess[str], list[list[str]]]:
    """Execute the appliance mount script against fake block-device commands.

    Args:
        tmp_path: Isolated filesystem root for the behavior scenario.
        disks: Fake whole-disk records exposed to the mount script.
        depot_tuple: Trusted depot SCSI identity from image policy.
        backup_tuple: Trusted backup SCSI identity from image policy.
        mounts: Initial mapping from mountpoints to fake disk paths.

    Returns:
        Completed shell process and recorded ``mkfs.ext4`` argument lists.
    """
    if os.name == "nt" or shutil.which("sh") is None:
        pytest.skip("the appliance shell behavior harness requires a native POSIX shell")

    dev_root = tmp_path / "dev"
    by_id_root = dev_root / "disk" / "by-id"
    sys_root = tmp_path / "sys" / "class" / "block"
    fake_bin = tmp_path / "bin"
    by_id_root.mkdir(parents=True)
    sys_root.mkdir(parents=True)
    fake_bin.mkdir()

    root_partition = dev_root / "sda1"
    root_partition.touch()
    for disk in disks:
        path = Path(str(disk["path"]))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
        if disk.get("partitions"):
            Path(f"{path}1").touch()
        block_root = sys_root / path.name
        (block_root / "holders").mkdir(parents=True)
        if disk.get("holders"):
            (block_root / "holders" / "dm-test").touch()
        scsi_device = tmp_path / "scsi" / f"1:{disk['tuple']}"
        scsi_device.mkdir(parents=True, exist_ok=True)
        (block_root / "device").symlink_to(scsi_device, target_is_directory=True)
        if path.name != "sda":
            (by_id_root / f"atlaso-path-test-{path.name}").symlink_to(path)

    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps({"disks": disks, "mounts": mounts or {}}), encoding="utf-8")
    mkfs_log = tmp_path / "mkfs.jsonl"
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
                if len(args) == 5 and args[:2] == ["-rn", "-S"] and args[3:] == ["-o", "TARGET"]:
                    disk = disk_for(args[2])
                    for target, source in mounts.items():
                        if disk and disk_for(source) is disk:
                            print(target)
                    raise SystemExit(0)
                if len(args) == 5 and args[:2] == ["-rn", "-M"] and args[3:] == ["-o", "UUID"]:
                    source = mounts.get(args[2])
                    disk = disk_for(source) if source else None
                    if disk and disk["uuid"]:
                        print(disk["uuid"])
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
                disk = next(disk for disk in disks if disk["label"] == label)
                mounts[target] = disk["path"]
                state_path.write_text(json.dumps(state), encoding="utf-8")
                raise SystemExit(0)
            if command in {"install", "chown", "chmod", "logger"}:
                raise SystemExit(0)
            raise SystemExit(2)
            """
        ),
        encoding="utf-8",
    )
    fake_command.chmod(0o755)
    for command in ["findmnt", "lsblk", "blkid", "mkfs.ext4", "install", "mount", "chown", "chmod", "logger"]:
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
            "ATLASO_DATA_DISK_FSTAB_PATH": str(tmp_path / "fstab"),
            "ATLASO_TEST_STATE": str(state_path),
            "ATLASO_TEST_ROOT_PARTITION": str(root_partition),
            "ATLASO_TEST_MKFS_LOG": str(mkfs_log),
        }
    )
    completed = subprocess.run(
        ["sh", str(MOUNT_SCRIPT.resolve())],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
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
    assert all("atlaso-path-test-" in call[-1] for call in calls)


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
        "ambiguous",
        "undersized",
        "oversized",
        "reordered",
        "partition_label",
        "read_only",
        "in_use",
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
