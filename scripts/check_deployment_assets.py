#!/usr/bin/env python3
"""Validate Atlaso's checked-in Packer, systemd, and sudoers assets."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKER_TEMPLATES = (
    Path("image/hyperv/atlaso-photon.pkr.hcl"),
    Path("image/vmware-workstation/atlaso-photon.pkr.hcl"),
)
SYSTEMD_DIRECTORIES = (
    Path("image/common/systemd"),
    Path("image/hyperv/systemd"),
    Path("image/vmware-workstation/systemd"),
)
SYSTEMD_ASSETS = (
    Path("image/common/systemd/atlaso-console-manager.conf"),
    Path("image/common/systemd/atlaso-console.service"),
    Path("image/common/systemd/atlaso-worker.service"),
    Path("image/hyperv/systemd/atlaso.service"),
    Path("image/vmware-workstation/systemd/atlaso-vmware-ovf-customize.service"),
    Path("image/vmware-workstation/systemd/atlaso.service"),
)
SUDOERS_DIRECTORIES = (
    Path("image/hyperv/sudoers.d"),
    Path("image/vmware-workstation/sudoers.d"),
)
SUDOERS_FRAGMENTS = (
    Path("image/hyperv/sudoers.d/atlaso-helper"),
    Path("image/vmware-workstation/sudoers.d/atlaso-helper"),
)
SYSTEMD_SUFFIXES = {".conf", ".service"}
MANAGER_DIRECTIVES = {
    "CtrlAltDelBurstAction": {
        "exit-force",
        "exit-immediate",
        "none",
        "poweroff-force",
        "poweroff-immediate",
        "reboot-force",
        "reboot-immediate",
    },
    "ShowStatus": {"auto", "error", "no", "yes"},
}
PACKER_CHECKSUM = "sha512:" + ("0" * 128)
PACKER_VALIDATION_VARS = (
    "iso_url=https://example.invalid/atlaso-photon.iso",
    f"iso_checksum={PACKER_CHECKSUM}",
    "iso_contains_kickstart=true",
)
SYSTEMD_STUB_UNITS = (
    "atlaso-bootstrap-https.service",
    "atlaso-data-disks.service",
    "atlaso-firewall.service",
    "basic.target",
    "getty@tty1.service",
    "local-fs.target",
    "multi-user.target",
    "network-online.target",
    "network-pre.target",
    "nginx.service",
    "shutdown.target",
    "systemd-networkd.service",
    "systemd-vconsole-setup.service",
    "sysinit.target",
)
EXECUTABLE_RE = re.compile(
    r"^Exec(?:Start|StartPre|StartPost|Reload|Stop|StopPost)="
    r"(?:[-+!:@|]+)?(?P<path>/\S+)",
    re.MULTILINE,
)


@dataclass(frozen=True)
class Finding:
    """Describe one deployment validation failure."""

    path: Path
    message: str

    def render(self, root: Path) -> str:
        """Render the finding with a repository-relative path when possible."""
        try:
            display = self.path.resolve().relative_to(root.resolve())
        except ValueError:
            display = self.path
        return f"{display}: {self.message}"


@dataclass(frozen=True)
class Inventory:
    """Hold the complete supported declarative deployment inventory."""

    packer: tuple[Path, ...]
    systemd: tuple[Path, ...]
    sudoers: tuple[Path, ...]

    @property
    def all(self) -> tuple[Path, ...]:
        """Return every inventoried asset in deterministic order."""
        return tuple(sorted((*self.packer, *self.systemd, *self.sudoers)))


def _files(directory: Path, findings: list[Finding]) -> tuple[Path, ...]:
    """Return direct files and reject nested or special entries in a managed directory."""
    if not directory.is_dir():
        return ()
    files: list[Path] = []
    for path in sorted(directory.iterdir()):
        if path.is_symlink():
            findings.append(
                Finding(
                    path,
                    "unsupported symbolic link; managed asset directories require direct regular files",
                )
            )
            continue
        if path.is_file():
            files.append(path)
            continue
        findings.append(
            Finding(
                path,
                "unsupported nested or special entry; managed asset directories require direct regular files",
            )
        )
    return tuple(files)


def inventory_assets(root: Path) -> tuple[Inventory, list[Finding]]:
    """Inventory every supported asset and reject unclassified deployment files."""
    findings: list[Finding] = []
    packer: list[Path] = []
    for path in sorted((root / "image").rglob("*.pkr.*")):
        if path.is_symlink():
            findings.append(Finding(path, "unsupported symbolic link for Packer asset"))
            continue
        relative = path.relative_to(root / "image")
        if len(relative.parts) != 2:
            findings.append(
                Finding(
                    path,
                    "unsupported nested Packer asset; add a validator or reviewed exclusion",
                )
            )
            continue
        if path.suffixes[-2:] != [".pkr", ".hcl"]:
            findings.append(
                Finding(path, "unsupported Packer asset type; add a validator or reviewed exclusion")
            )
            continue
        packer.append(path)
    required_packer = tuple(root / path for path in PACKER_TEMPLATES)
    for path in required_packer:
        if not path.is_file() or path.is_symlink():
            findings.append(Finding(path, "required Packer template is missing"))

    systemd: list[Path] = []
    for relative in SYSTEMD_DIRECTORIES:
        directory = root / relative
        for path in _files(directory, findings):
            if path.suffix not in SYSTEMD_SUFFIXES:
                findings.append(
                    Finding(path, "unsupported systemd asset type; add a validator or reviewed exclusion")
                )
                continue
            systemd.append(path)
    for relative in SYSTEMD_ASSETS:
        path = root / relative
        if not path.is_file() or path.is_symlink():
            findings.append(Finding(path, "required systemd asset is missing"))
    common_directory = root / SYSTEMD_DIRECTORIES[0]
    common_names = {path.name for path in systemd if path.parent == common_directory}
    for relative in SYSTEMD_DIRECTORIES[1:]:
        platform_directory = root / relative
        for path in (candidate for candidate in systemd if candidate.parent == platform_directory):
            if path.name in common_names:
                findings.append(
                    Finding(
                        path,
                        "systemd asset basename collides with a common asset in the composed validation root",
                    )
                )

    sudoers: list[Path] = []
    for relative in SUDOERS_DIRECTORIES:
        for path in _files(root / relative, findings):
            if path.suffix:
                findings.append(
                    Finding(
                        path,
                        "unsupported sudoers asset type; fragments must use extensionless filenames",
                    )
                )
                continue
            sudoers.append(path)
    for relative in SUDOERS_FRAGMENTS:
        path = root / relative
        if not path.is_file() or path.is_symlink():
            findings.append(Finding(path, "required sudoers fragment is missing"))

    inventory = Inventory(
        packer=tuple(packer),
        systemd=tuple(sorted(systemd)),
        sudoers=tuple(sorted(sudoers)),
    )
    for label, assets in (
        ("Packer", inventory.packer),
        ("systemd", inventory.systemd),
        ("sudoers", inventory.sudoers),
    ):
        if not assets:
            findings.append(Finding(root / "image", f"no {label} assets were inventoried"))
    return inventory, findings


def _selected_assets(inventory: Inventory, raw_paths: list[str], root: Path) -> Inventory:
    """Select requested assets while retaining full-inventory checks."""
    if not raw_paths:
        return inventory
    requested: set[Path] = set()
    for raw in raw_paths:
        path = Path(raw)
        if not path.is_absolute():
            path = root / path
        if path.is_dir():
            requested.update(candidate.resolve() for candidate in path.rglob("*") if candidate.is_file())
        else:
            requested.add(path.resolve())

    def selected(paths: tuple[Path, ...]) -> tuple[Path, ...]:
        return tuple(path for path in paths if path.resolve() in requested)

    return Inventory(
        packer=selected(inventory.packer),
        systemd=selected(inventory.systemd),
        sudoers=selected(inventory.sudoers),
    )


def _command_failure(path: Path, label: str, result: subprocess.CompletedProcess[str]) -> Finding:
    """Convert bounded native-validator output into one finding."""
    detail = (result.stderr or result.stdout or "").strip().splitlines()
    message = detail[-1] if detail else f"exit code {result.returncode}"
    return Finding(path, f"{label} failed: {message}")


def _run(
    command: list[str],
    cwd: Path,
    path: Path,
    label: str,
    *,
    stderr_is_failure: bool = False,
) -> Finding | None:
    """Run one validator without echoing its arguments or unbounded output."""
    result = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0 and not (stderr_is_failure and result.stderr.strip()):
        return None
    return _command_failure(path, label, result)


def validate_packer(assets: tuple[Path, ...], packer: str) -> list[Finding]:
    """Run formatting and wrapper-equivalent validation for selected Packer targets."""
    findings: list[Finding] = []
    for template in assets:
        directory = template.parent
        commands = (
            ("packer init", [packer, "init", "."]),
            ("packer fmt -check", [packer, "fmt", "-check", "-diff", template.name]),
            (
                "packer validate",
                [
                    packer,
                    "validate",
                    *[item for value in PACKER_VALIDATION_VARS for item in ("-var", value)],
                    ".",
                ],
            ),
        )
        for label, command in commands:
            finding = _run(command, directory, template, label)
            if finding is not None:
                findings.append(finding)
                break
    return findings


def _write_stub_executable(root: Path, absolute_path: str) -> None:
    """Create an inert executable at a unit's absolute command path."""
    destination = root / absolute_path.lstrip("/")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    destination.chmod(0o755)


def _prepare_systemd_root(root: Path, platform: str, repository: Path) -> tuple[Path, ...]:
    """Create a controlled offline systemd root for one image target."""
    unit_directory = root / "etc/systemd/system"
    manager_directory = root / "etc/systemd/system.conf.d"
    unit_directory.mkdir(parents=True)
    manager_directory.mkdir(parents=True)
    (root / "etc/systemd/system.conf").write_text("[Manager]\n", encoding="utf-8")

    source_units = sorted((repository / "image/common/systemd").glob("*.service"))
    source_units.extend(sorted((repository / f"image/{platform}/systemd").glob("*.service")))
    copied: list[Path] = []
    for source in source_units:
        destination = unit_directory / source.name
        shutil.copyfile(source, destination)
        copied.append(destination)
        text = source.read_text(encoding="utf-8")
        for match in EXECUTABLE_RE.finditer(text):
            _write_stub_executable(root, match.group("path"))

    for name in SYSTEMD_STUB_UNITS:
        destination = unit_directory / name
        if destination.exists():
            continue
        contents = f"[Unit]\nDescription=Validation stub for {name}\n"
        if name.endswith(".service"):
            _write_stub_executable(root, "/bin/true")
            contents += "\n[Service]\nType=oneshot\nExecStart=/bin/true\nRemainAfterExit=yes\n"
        destination.write_text(contents, encoding="utf-8")

    for source in sorted((repository / "image/common/systemd").glob("*.conf")):
        shutil.copyfile(source, manager_directory / source.name)
    for source in sorted((repository / f"image/{platform}/systemd").glob("*.conf")):
        shutil.copyfile(source, manager_directory / source.name)
    return tuple(copied)


def validate_manager_dropins(assets: tuple[Path, ...]) -> list[Finding]:
    """Strictly parse Atlaso's supported system manager drop-in contract."""
    findings: list[Finding] = []
    for path in assets:
        section: str | None = None
        for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            line = raw_line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            if line.startswith("["):
                if not line.endswith("]"):
                    findings.append(Finding(path, f"line {line_number}: malformed section header"))
                    continue
                section = line[1:-1]
                if section != "Manager":
                    findings.append(
                        Finding(path, f"line {line_number}: unsupported manager section [{section}]")
                    )
                continue
            if section != "Manager":
                findings.append(
                    Finding(path, f"line {line_number}: assignment must be inside [Manager]")
                )
                continue
            if "=" not in line:
                findings.append(Finding(path, f"line {line_number}: expected Key=Value assignment"))
                continue
            key, value = (part.strip() for part in line.split("=", maxsplit=1))
            allowed_values = MANAGER_DIRECTIVES.get(key)
            if allowed_values is None:
                findings.append(
                    Finding(path, f"line {line_number}: unsupported [Manager] directive {key}")
                )
            elif value.lower() not in allowed_values:
                findings.append(
                    Finding(path, f"line {line_number}: invalid value for [Manager] directive {key}")
                )
    return findings


def validate_systemd(systemd_analyze: str, repository: Path) -> list[Finding]:
    """Verify both platform unit sets and manager drop-ins in isolated roots."""
    manager_assets = tuple(
        sorted(
            path
            for relative in SYSTEMD_DIRECTORIES
            for path in (repository / relative).glob("*.conf")
        )
    )
    findings = validate_manager_dropins(manager_assets)
    for platform in ("hyperv", "vmware-workstation"):
        with tempfile.TemporaryDirectory(prefix=f"atlaso-systemd-{platform}-") as temporary:
            validation_root = Path(temporary)
            units = _prepare_systemd_root(validation_root, platform, repository)
            command = [
                systemd_analyze,
                f"--root={validation_root}",
                "--man=no",
                "verify",
                *(str(path) for path in units),
            ]
            finding = _run(
                command,
                repository,
                repository / f"image/{platform}/systemd",
                "systemd-analyze verify",
                stderr_is_failure=True,
            )
            if finding is not None:
                findings.append(finding)
                continue
            manager_finding = _run(
                [
                    systemd_analyze,
                    f"--root={validation_root}",
                    "cat-config",
                    "systemd/system.conf",
                ],
                repository,
                repository / "image/common/systemd/atlaso-console-manager.conf",
                "systemd-analyze cat-config",
                stderr_is_failure=True,
            )
            if manager_finding is not None:
                findings.append(manager_finding)
    return findings


def validate_sudoers(assets: tuple[Path, ...], visudo: str, repository: Path) -> list[Finding]:
    """Validate every selected sudoers fragment independently."""
    findings: list[Finding] = []
    for path in assets:
        finding = _run([visudo, "-cf", str(path)], repository, path, "visudo -cf")
        if finding is not None:
            findings.append(finding)
    return findings


def main(argv: list[str] | None = None) -> int:
    """Run inventory and the native validators available or required by the selected mode."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=("auto", "inventory", "linux", "packer"),
        default="auto",
        help="Validator set. CI uses linux and packer in their native runner jobs.",
    )
    parser.add_argument("paths", nargs="*", help="Optional changed deployment assets.")
    args = parser.parse_args(argv)

    inventory, findings = inventory_assets(ROOT)
    selected = _selected_assets(inventory, args.paths, ROOT)
    executed: list[str] = []

    packer = shutil.which("packer")
    run_packer = args.mode in {"auto", "packer"} and bool(selected.packer)
    if run_packer and packer is None and args.mode == "packer":
        findings.append(Finding(ROOT / "image", "Packer is required for CI deployment validation"))
    elif run_packer and packer is not None:
        findings.extend(validate_packer(selected.packer, packer))
        executed.append("packer")

    systemd_analyze = shutil.which("systemd-analyze")
    visudo = shutil.which("visudo")
    run_linux = args.mode in {"auto", "linux"} and bool(selected.systemd or selected.sudoers)
    if run_linux:
        if systemd_analyze is None and args.mode == "linux":
            findings.append(Finding(ROOT / "image", "systemd-analyze is required for CI deployment validation"))
        elif systemd_analyze is not None and selected.systemd:
            findings.extend(validate_systemd(systemd_analyze, ROOT))
            executed.append("systemd")
        if visudo is None and args.mode == "linux":
            findings.append(Finding(ROOT / "image", "visudo is required for CI deployment validation"))
        elif visudo is not None and selected.sudoers:
            findings.extend(validate_sudoers(selected.sudoers, visudo, ROOT))
            executed.append("sudoers")

    if findings:
        print(f"Deployment asset checks failed with {len(findings)} issue(s):", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding.render(ROOT)}", file=sys.stderr)
        return 1

    validator_summary = ", ".join(executed) if executed else "inventory only"
    print(
        f"Deployment asset checks passed for {len(selected.all)} selected file(s) "
        f"from {len(inventory.all)} inventoried asset(s); validators: {validator_summary}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
