"""Build an unpublished Atlaso VMware OVA from the pinned Photon 5 image."""

from __future__ import annotations

import argparse
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from scripts.virtualization.prepare_photon_ovf import (
    VMDK_NAMES,
    digest,
    package,
    require_stream_vmdk,
)
from scripts.virtualization.validate_ova import EXPECTED_PAYLOADS, OVF, VMW

SOURCE = Path(__file__).resolve().parents[2]
ASSETS = SOURCE / "image/photon-ova"
PHOTON_URL = "https://packages.broadcom.com/photon/5.0/GA/ova/photon-hw15-5.0-dde71ec57.x86_64.ova"
PHOTON_SHA512 = (
    "6bd6a307745adb00b8452013f2c308c9abefd24a9d82611e8a1551afb965873388e"
    "bde81a34296dc0ad2fa7f0f7b4cd3924701abde0c963ea40b363c444bb037"
)
PHOTON_BYTES = 322365440
PHOTON_DISK = "photon-ova-disk1.vmdk"
PHOTON_MEMBERS = {"photon-ova.ovf", "photon-ova.mf", "photon-ova.cert", PHOTON_DISK}
GIB = 1024**3
ROOT = "/dev/sda2"
ESP = "/dev/sda3"
SEED = "/var/tmp/atlaso-ova-build"
SERVICE = "atlaso-ova-build.service"
RECEIPT = "/var/lib/atlaso-ova-build/complete"
# Match the staging inputs of the canonical Workstation provisioner.
SOURCE_PATHS = (
    "atlaso", "pyproject.toml", "requirements-appliance.lock", "README.md",
    "scripts/appliance", "scripts/check_photon_compatibility.py",
    "scripts/generate_third_party_notices.py", "scripts/third_party_notices.json",
    "scripts/version.py", "scripts/run_tdnf_with_progress.py",
    "third_party/ipxe", "image/inventory-linux/README.md",
    "image/vmware-workstation/systemd", "image/common",
)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Keep the upstream download on the exact pinned URL."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Reject redirects, including redirects within the same provider."""
        raise ValueError("The pinned Photon download URL attempted a redirect")


def fetch_photon(path: Path) -> None:
    """Download exactly the pinned amount of data before verifying it."""
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(PHOTON_URL, timeout=60) as response, path.open("xb") as output:
        remaining = PHOTON_BYTES
        while remaining:
            block = response.read(min(remaining, 1024**2))
            if not block:
                raise ValueError("The Photon download ended before the pinned length")
            output.write(block)
            remaining -= len(block)
        if response.read(1):
            raise ValueError("The Photon download exceeds the pinned length")


def extract_photon(path: Path, desired_disk: Path) -> None:
    """Verify the vendor digest and copy only the admitted regular VMDK."""
    if path.stat().st_size != PHOTON_BYTES or digest(path, "sha512") != PHOTON_SHA512:
        raise ValueError("The Photon OVA does not match the pinned archive")
    with tarfile.open(path, "r:") as archive:
        members: dict[str, tarfile.TarInfo] = {}
        for member in archive:
            if member.name not in PHOTON_MEMBERS or member.name in members or not member.isfile():
                raise ValueError("Unexpected or unsafe member in the Photon OVA")
            members[member.name] = member
        if set(members) != PHOTON_MEMBERS or not 0 < members["photon-ova.ovf"].size <= 2**20:
            raise ValueError("Unexpected Photon OVA member inventory or descriptor size")
        with archive.extractfile(members["photon-ova.ovf"]) as ovf:
            descriptor = ET.parse(ovf)
        entry = descriptor.find(f"./{{{OVF}}}References/{{{OVF}}}File")
        efi = [
            element.get(f"{{{VMW}}}value")
            for element in descriptor.iter(f"{{{VMW}}}Config")
            if element.get(f"{{{VMW}}}key") == "firmware"
        ]
        if entry is None or entry.get(f"{{{OVF}}}href") != PHOTON_DISK or efi != ["efi"]:
            raise ValueError("Unexpected Photon OVA disk or firmware definition")
        with archive.extractfile(members[PHOTON_DISK]) as stream, desired_disk.open("xb") as output:
            shutil.copyfileobj(stream, output, length=1024**2)
    require_stream_vmdk(desired_disk, 16 * GIB)


def run(*args: str, seconds: int = 600, capture: bool = False) -> str:
    """Run a bounded host command with an optional captured standard output."""
    result = subprocess.run(args, check=True, timeout=seconds, text=True, stdout=subprocess.PIPE if capture else None)
    return result.stdout or ""


def fish(disk: Path, *actions: tuple[str, ...], readonly: bool = False, second: Path | None = None) -> str:
    """Run bounded libguestfs operations against explicitly formatted images."""
    args = ["guestfish", "--ro" if readonly else "--rw", "--format=qcow2", "-a", str(disk)]
    if second is not None:
        args.extend(("--format=qcow2", "-a", str(second)))
    args.append("run")
    for action in actions:
        args.extend((":", *action))
    return run(*args, capture=True)


def setup_disk(disk: Path, original: Path, source_archive: Path) -> dict[str, str]:
    """Preserve the Photon partition identifiers, expand root and seed the guest."""
    run("qemu-img", "convert", "-f", "vmdk", "-O", "qcow2", str(original), str(disk))
    checks = (
        ("part-get-parttype", "/dev/sda"), ("part-get-gpt-guid", "/dev/sda", "2"),
        ("part-get-gpt-guid", "/dev/sda", "3"), ("vfs-type", ROOT), ("vfs-type", ESP),
        ("mount-ro", ROOT, "/"), ("mount-ro", ESP, "/boot/efi"),
        ("is-file", "/boot/efi/EFI/BOOT/BOOTX64.EFI"),
    )
    metadata = fish(disk, *checks, readonly=True).strip().lower().splitlines()
    expected = ["gpt", "c724cded-cf33-4d1c-b510-59478c322f84", "df4477b9-3574-4e94-9729-c60d1b211fc7",
                "ext4", "vfat", "true"]
    if metadata != expected:
        raise ValueError("The pinned Photon disk does not match the inspected GPT and EFI layout")

    run("qemu-img", "resize", "-f", "qcow2", str(disk), "40G")
    normalized = fish(
        disk, ("part-expand-gpt", "/dev/sda"),
        ("part-resize", "/dev/sda", "2", str(40 * GIB // 512 - 34)),
        ("e2fsck", ROOT, "correct:true"), ("resize2fs", ROOT),
        *checks[:5],
        ("mount", ROOT, "/"),
        ("sh", "PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH; "
               "usermod --password '!' root && chage -d \"$(date +%F)\" -E -1 -I -1 -M -1 root "
               "&& rm -f /etc/shadow-"),
        ("mkdir", SEED), ("chmod", "0700", SEED),
        ("upload", str(source_archive), f"{SEED}/source.tar"),
        ("upload", str(ASSETS / "provision.sh"), f"{SEED}/provision.sh"),
        ("upload", str(ASSETS / SERVICE), f"/etc/systemd/system/{SERVICE}"),
        ("mkdir-p", "/etc/systemd/system/multi-user.target.wants"),
        ("ln-s", f"/etc/systemd/system/{SERVICE}", f"/etc/systemd/system/multi-user.target.wants/{SERVICE}"),
    ).strip().lower().splitlines()
    if normalized != expected[:5]:
        raise ValueError("Photon partition identity changed while growing the disk")
    return {"partition_table": "gpt", "root_partuuid": metadata[1], "esp_partuuid": metadata[2]}


def provision(work: Path, disk: Path, content: Path, firmware: Path) -> tuple[dict[str, str], str]:
    """Provision in QEMU with the same PVSCSI bus and NIC type as the target."""
    vars_file = work / "ovmf-vars.fd"
    shutil.copyfile(firmware / "OVMF_VARS_4M.fd", vars_file)
    run(
        "qemu-system-x86_64", "-name", "atlaso-photon-ova",
        "-machine", "q35,accel=kvm", "-cpu", "host", "-smp", "4", "-m", "4096",
        "-nodefaults", "-device", "VGA", "-display", "none", "-serial", "stdio", "-monitor", "none",
        "-drive", f"if=pflash,format=raw,readonly=on,file={firmware / 'OVMF_CODE_4M.fd'}",
        "-drive", f"if=pflash,format=raw,file={vars_file}",
        "-device", "pvscsi,id=scsi",
        "-drive", f"if=none,id=root,format=qcow2,discard=unmap,file={disk}",
        "-device", "scsi-hd,drive=root,bus=scsi.0,scsi-id=0,bootindex=1",
        "-drive", f"if=none,id=system,format=qcow2,discard=unmap,file={content}",
        "-device", "scsi-hd,drive=system,bus=scsi.0,scsi-id=1",
        "-netdev", "user,id=management", "-device", "vmxnet3,netdev=management",
        seconds=130 * 60,
    )
    receipt = fish(
        disk, ("mount-ro", ROOT, "/"), ("mount-ro", "/dev/sdb", "/var/lib/atlaso-system"),
        ("sh", """set -eu
            export PATH=/usr/sbin:/usr/bin:/sbin:/bin
            test -z "$(getent passwd atlaso-build)"
            awk -F: '$1 == "root" || $1 == "admin" { if ($2 != "!" || $3 == 0) exit 1; seen++ }
                      END { if (seen != 2) exit 1 }' /etc/shadow
            test ! -e /home/atlaso-build
            test ! -e /etc/sudoers.d/90-atlaso-build
            test ! -e /etc/systemd/system/atlaso-ova-build.service
            test ! -e /var/tmp/atlaso-ova-build
            test ! -e /var/lib/atlaso-system/opt-atlaso/bin/atlaso-finalize-image-build
            python3 /var/lib/atlaso-system/opt-atlaso/image/common/scripts/verify-template-state.py
        """),
        ("cat", RECEIPT), ("vfs-uuid", "/dev/sdb"), readonly=True, second=content,
    ).strip()
    build_info, system_uuid = receipt.rsplit("\n", 1)
    if not re.fullmatch(r"[0-9a-f-]{36}", system_uuid):
        raise ValueError("Atlaso System Content does not have a filesystem UUID")
    final_info = dict(line.split("=", 1) for line in build_info.splitlines() if "=" in line)
    if not {"kernel", "python", "powershell", "powercli", "vcf_sdk"} <= final_info.keys():
        raise ValueError("The live build did not record its required software versions")
    # userdel in the shared finalizer rewrites the account backups.
    fstab = fish(
        disk, ("mount", ROOT, "/"), ("cat", "/etc/fstab"),
        ("rm", RECEIPT), ("rmdir", "/var/lib/atlaso-ova-build"),
        ("rm-f", "/etc/shadow-"), ("rm-f", "/etc/gshadow-"),
        ("rm-f", "/etc/passwd-"), ("rm-f", "/etc/group-"),
    ).splitlines()
    if f"UUID={system_uuid} /var/lib/atlaso-system ext4 defaults 0 2" not in fstab:
        raise ValueError("The system disk UUID does not match the persistent mount")
    return final_info, system_uuid


def build_artifact(output: Path, scratch: Path, firmware: Path, override: Path | None) -> Path:
    """Run the trial build and write only validated artifacts to the output."""
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("This build requires x86-64 Linux")
    with Path("/dev/kvm").open("r+b", buffering=0):
        pass
    if len(os.sched_getaffinity(0)) < 4:
        raise ValueError("This build needs access to at least four logical CPUs")
    if (os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")) < 8 * GIB:
        raise ValueError("This build needs at least 8 GiB host RAM")
    if shutil.disk_usage(scratch).free < 140 * GIB:
        raise ValueError("The scratch filesystem needs at least 140 GiB of free space")
    if shutil.disk_usage(output.parent).free < 4 * GIB:
        raise ValueError("The output filesystem needs at least 4 GiB of free space")
    for file in ("OVMF_CODE_4M.fd", "OVMF_VARS_4M.fd"):
        if not (firmware / file).is_file():
            raise ValueError(f"Missing non-Secure-Boot OVMF firmware file: {file}")

    if run("git", "-C", str(SOURCE), "status", "--porcelain", "--untracked-files=no", capture=True):
        raise ValueError("Trial builds require an exact clean source commit")
    commit = run("git", "-C", str(SOURCE), "rev-parse", "HEAD", capture=True).strip()
    project = run("git", "-C", str(SOURCE), "show", f"{commit}:pyproject.toml", capture=True)
    version = tomllib.loads(project)["project"]["version"]
    tools = {
        name: run(name, "--version", capture=True).splitlines()[0]
        for name in ("qemu-system-x86_64", "qemu-img", "guestfish")
    }

    with tempfile.TemporaryDirectory(dir=scratch, prefix="atlaso-ova-") as directory:
        work = Path(directory)
        # libguestfs supermin scratch and its appliance cache are owned by this run.
        os.environ.update(LIBGUESTFS_BACKEND="direct", LIBGUESTFS_CACHEDIR=directory, LIBGUESTFS_TMPDIR=directory)
        archive = override or work / "photon.ova"
        if override is None:
            fetch_photon(archive)
        original = work / PHOTON_DISK
        extract_photon(archive, original)
        source_archive = work / "source.tar"
        run("git", "-C", str(SOURCE), "archive", "--format=tar", "-o", str(source_archive), commit, *SOURCE_PATHS)

        disk = work / "root.qcow2"
        disk_layout = setup_disk(disk, original, source_archive)
        content = work / "system.qcow2"
        run("qemu-img", "create", "-f", "qcow2", str(content), "20G")
        build_info, system_uuid = provision(work, disk, content, firmware)

        candidate = work / "artifacts"
        candidate.mkdir()
        for slot, payload in enumerate((disk, content)):
            stream = candidate / VMDK_NAMES[slot]
            run("qemu-img", "convert", "-f", "qcow2", "-O", "vmdk",
                "-o", "subformat=streamOptimized,adapter_type=lsilogic", str(payload), str(stream), seconds=2400)
            require_stream_vmdk(stream, EXPECTED_PAYLOADS[slot][2])

        evidence: dict[str, Any] = {
            "photon": {"build": "5.0-dde71ec57", "url": PHOTON_URL, "sha512": PHOTON_SHA512, **disk_layout},
            "tool_versions": tools,
            "ovmf_code_sha256": digest(firmware / "OVMF_CODE_4M.fd"),
            "system_content_uuid": system_uuid,
            "guest_build_info": build_info,
        }
        ova = package(candidate, version, commit, evidence, work / "validation")
        output.mkdir()
        for file in (ova, candidate / "atlaso-provenance.json"):
            shutil.copyfile(file, output / file.name)
        (output / "SHA256SUMS").write_text(f"{digest(ova)}  {ova.name}\n", encoding="ascii")
        return output / ova.name


def main() -> int:
    """Build from a clean checkout or reuse bytes of the exact pinned Photon OVA."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New directory for validated trial artifacts")
    parser.add_argument("--scratch", type=Path, required=True, help="Existing task-owned scratch parent")
    parser.add_argument("--firmware", type=Path, default=Path("/usr/share/OVMF"))
    parser.add_argument("--photon-ova", type=Path, help="Existing checksum-pinned Photon OVA to reuse")
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        parser.error("--output must be a new directory")
    for path in (args.scratch, args.output.parent, args.firmware):
        if not path.is_dir():
            parser.error(f"Directory must already exist: {path}")
    if args.photon_ova is not None and not args.photon_ova.is_file():
        parser.error("--photon-ova must be an existing regular file")

    def interrupted(_signal: int, _frame: object) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    try:
        print(build_artifact(args.output.resolve(), args.scratch.resolve(), args.firmware.resolve(), args.photon_ova))
    except (ValueError, OSError, subprocess.SubprocessError, KeyboardInterrupt, tarfile.TarError) as error:
        print(f"Trial OVA build failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
