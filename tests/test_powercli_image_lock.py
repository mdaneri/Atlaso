"""Exercise image dependency admission with real PowerShell module manifests."""

import hashlib
import json
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from scripts.update_powercli_lock import content_digest

SCRIPT = Path("image/common/powershell/provision-powercli.ps1").resolve()
PWSH = shutil.which("pwsh")
pytestmark = pytest.mark.skipif(PWSH is None, reason="PowerShell is required")


def module(root: Path, name: str, version: str, required: str = "@()") -> Path:
    """Write a minimal importable vendor-shaped module without external dependencies.

    Args:
        root: Root directory containing the module bundle or checkout being validated.
        name: Published module name used to identify its manifest and package.
        version: Exact module or suite version selected for this operation.
        required: PowerShell RequiredModules expression written into the fixture manifest.
    """
    directory = root / name / version
    directory.mkdir(parents=True)
    manifest = directory / f"{name}.psd1"
    manifest.write_text(
        f"@{{ModuleVersion='{version}'; RootModule='{name}.psm1'; "
        f"RequiredModules={required}; FunctionsToExport='*'}}",
        encoding="utf-8",
    )
    (directory / f"{name}.psm1").write_text(
        "function Get-PowerCLIConfiguration { param($Scope) "
        "[pscustomobject]@{ParticipateInCEIP=$false} }\n"
        "function Connect-VIServer {}\n"
        if name == "VCF.PowerCLI"
        else "",
        encoding="utf-8",
    )
    return manifest


def pin_bundle(root: Path, lock: Path) -> None:
    """Freeze inert test archives and payload hashes before exercising admission.

    Args:
        root: Root directory containing the module bundle or checkout being validated.
        lock: JSON lock path that records the reviewed fixture versions and hashes.
    """
    data = json.loads(lock.read_text(encoding="utf-8"))
    data["schema_version"] = 2
    data["hashes"] = {}
    archives = root.parent / ".archives"
    archives.mkdir(exist_ok=True)
    for name, version in data["modules"].items():
        directory = root / name / version
        files = {
            p.relative_to(directory).as_posix(): p.read_bytes()
            for p in directory.rglob("*")
            if p.is_file()
        }
        archive = archives / f"{name}.{version}.nupkg"
        with zipfile.ZipFile(archive, "w") as package:
            for relative, payload in files.items():
                package.writestr(relative, payload)
        data["hashes"][name] = {
            "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "content_sha256": content_digest(files),
        }
    lock.write_text(json.dumps(data), encoding="utf-8")


@pytest.fixture
def bundle(tmp_path: Path) -> tuple[Path, Path]:
    """Create a suite whose open-ended dependency must use the reviewed version.

    Args:
        tmp_path: Isolated pytest directory for fixture files and child-process scripts.
    """
    root = tmp_path / "modules"
    module(root, "VMware.OpenAPI", "1.0.0")
    module(
        root,
        "VCF.PowerCLI",
        "9.1.0",
        "@(@{ModuleName='VMware.OpenAPI';ModuleVersion='1.0.0'})",
    )
    lock = tmp_path / "lock.json"
    lock.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "suite_version": "9.1.0",
                "modules": {"VCF.PowerCLI": "9.1.0", "VMware.OpenAPI": "1.0.0"},
            }
        ),
        encoding="utf-8",
    )
    pin_bundle(root, lock)
    return root, lock


def run(
    bundle: tuple[Path, Path], mode: str = "Validate", extra_root: Path | None = None
) -> subprocess.CompletedProcess[str]:
    """Run one clean process using only explicitly selected module search roots.

    Args:
        bundle: Fixture module-root and lock-file pair passed to the provisioning helper.
        mode: Provisioning mode invoked in the fresh PowerShell process.
        extra_root: Optional second module search directory used to test shadowing.
    """
    root, lock = bundle
    env = os.environ.copy()
    env.pop("ATLASO_POWERCLI_VERSION", None)
    env["PSModulePath"] = str(root) + (
        os.pathsep + str(extra_root) if extra_root else ""
    )
    return subprocess.run(
        [
            str(PWSH),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(SCRIPT),
            "-Mode",
            mode,
            "-ModuleRoot",
            str(root),
            "-LockPath",
            str(lock),
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_exact_closure_imports_in_fresh_process(bundle: tuple[Path, Path]) -> None:
    """A compatible minimum version loads with the suite and exposes its command.

    Args:
        bundle: Fixture module-root and lock-file pair passed to the provisioning helper.
    """
    result = run(bundle, "Verify")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Loaded locked PowerCLI module VMware.OpenAPI 1.0.0" in result.stdout


@pytest.mark.parametrize("persist", [True, False])
def test_ceip_setting_requires_fresh_process_readback(
    bundle: tuple[Path, Path],
    persist: bool,
) -> None:
    """Model vendor import-time caching and reject a setter that did not persist.

    Args:
        bundle: Fixture module-root and lock-file pair passed to the provisioning helper.
        persist: Whether the fixture persists CEIP changes across fresh processes.
    """
    root, lock = bundle
    script = root / "VCF.PowerCLI/9.1.0/VCF.PowerCLI.psm1"
    script.write_text(
        "$script:cached = $null\n"
        "$script:setting = Join-Path $PSScriptRoot '../../../ceip-disabled'\n"
        "if (Test-Path $script:setting) { $script:cached = $false }\n"
        "function Get-PowerCLIConfiguration { param($Scope) "
        "[pscustomobject]@{ParticipateInCEIP=$script:cached} }\n"
        "function Connect-VIServer {}\n"
        "function Set-PowerCLIConfiguration { param($ParticipateInCeip,$Scope,$Confirm)\n"
        + ("Set-Content $script:setting 'false'\n" if persist else "")
        + "}\n",
        encoding="utf-8",
    )
    pin_bundle(root, lock)
    env = os.environ.copy()
    env.pop("ATLASO_POWERCLI_VERSION", None)
    env["PSModulePath"] = str(root)
    result = subprocess.run(
        [
            str(PWSH),
            "-NoProfile",
            "-File",
            str(SCRIPT),
            "-Mode",
            "Verify",
            "-ConfigureCeip",
            "-ModuleRoot",
            str(root),
            "-LockPath",
            str(lock),
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert (result.returncode == 0) is persist, result.stdout + result.stderr
    if not persist:
        assert "Fresh-process PowerCLI CEIP verification failed" in result.stderr


def test_side_by_side_newer_release_is_rejected(bundle: tuple[Path, Path]) -> None:
    """A later Gallery version cannot satisfy an open-ended requirement silently.

    Args:
        bundle: Fixture module-root and lock-file pair passed to the provisioning helper.
    """
    module(bundle[0], "VMware.OpenAPI", "1.1.0")
    result = run(bundle)
    assert result.returncode != 0
    assert "requires only VMware.OpenAPI 1.0.0" in result.stderr


def test_user_module_shadow_is_rejected(
    bundle: tuple[Path, Path], tmp_path: Path
) -> None:
    """Fresh administrator verification rejects another discoverable version.

    Args:
        bundle: Fixture module-root and lock-file pair passed to the provisioning helper.
        tmp_path: Isolated pytest directory for fixture files and child-process scripts.
    """
    shadow = tmp_path / "user-modules"
    module(shadow, "VMware.OpenAPI", "1.1.0")
    result = run(bundle, "Verify", shadow)
    assert result.returncode != 0
    assert "discovery is ambiguous" in result.stderr


@pytest.mark.parametrize(
    "requirement",
    [
        "@{ModuleName='VMware.OpenAPI';ModuleVersion='1.1.0'}",
        "@{ModuleName='VMware.OpenAPI';RequiredVersion='1.1.0'}",
        "@{ModuleName='VMware.OpenAPI';MaximumVersion='0.9.0'}",
        "@{ModuleName='VMware.Missing';ModuleVersion='1.0.0'}",
    ],
)
def test_incompatible_vendor_constraint_is_rejected(
    bundle: tuple[Path, Path],
    requirement: str,
) -> None:
    """A lock must satisfy every unmodified vendor dependency declaration.

    Args:
        bundle: Fixture module-root and lock-file pair passed to the provisioning helper.
        requirement: Gallery dependency range whose bounds must be honored.
    """
    manifest = bundle[0] / "VCF.PowerCLI/9.1.0/VCF.PowerCLI.psd1"
    manifest.write_text(
        "@{ModuleVersion='9.1.0';RequiredModules=@(" + requirement + ")}",
        encoding="utf-8",
    )
    pin_bundle(*bundle)
    result = run(bundle)
    assert result.returncode != 0
    assert "violates" in result.stderr or "omits dependency" in result.stderr


def test_missing_locked_module_is_rejected(bundle: tuple[Path, Path]) -> None:
    """Incomplete offline bundles fail before copy or import.

    Args:
        bundle: Fixture module-root and lock-file pair passed to the provisioning helper.
    """
    (bundle[0] / "VMware.OpenAPI/1.0.0/VMware.OpenAPI.psd1").unlink()
    assert run(bundle).returncode != 0


def test_changed_payload_with_identical_manifest_is_rejected(
    bundle: tuple[Path, Path],
) -> None:
    """Offline admission rejects modified executable code even when version metadata agrees.

    Args:
        bundle: Fixture module-root and lock-file pair passed to the provisioning helper.
    """
    (bundle[0] / "VMware.OpenAPI/1.0.0/VMware.OpenAPI.psm1").write_text(
        'throw "tampered"', encoding="utf-8"
    )
    result = run(bundle, "Verify")
    assert result.returncode != 0
    assert "content hash mismatch" in result.stderr


@pytest.mark.parametrize("tamper", [False, True])
def test_install_saves_each_exact_package_without_resolution(
    bundle: tuple[Path, Path],
    tmp_path: Path,
    tamper: bool,
) -> None:
    """A simulated Gallery latest release must never enter the saved package set.

    Args:
        bundle: Fixture module-root and lock-file pair passed to the provisioning helper.
        tmp_path: Isolated pytest directory for fixture files and child-process scripts.
        tamper: Whether the package bytes are altered after their digest is locked.
    """
    root, lock = bundle
    target = tmp_path / "saved"
    wrapper = tmp_path / "install.ps1"
    wrapper.write_text(
        "param($Script,$Source,$Target,$Lock)\n"
        "function Invoke-WebRequest {\n"
        "param($Uri,$OutFile,$TimeoutSec)\n"
        "$parts = $Uri.Split('/'); $Name = $parts[-2]; $Version = $parts[-1]\n"
        'Copy-Item -LiteralPath (Join-Path (Split-Path $Source -Parent) ".archives/$Name.$Version.nupkg") -Destination $OutFile\n}\n'
        "& $Script -Mode Install -ModuleRoot $Target -LockPath $Lock\n",
        encoding="utf-8",
    )
    # The source advertises a newer dependency; only an exact version request is copied.
    module(root, "VMware.OpenAPI", "1.1.0")
    if tamper:
        archive = root.parent / ".archives/VCF.PowerCLI.9.1.0.nupkg"
        archive.write_bytes(archive.read_bytes() + b"corrupted or replaced bytes")
    result = subprocess.run(
        [
            str(PWSH),
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(wrapper),
            str(SCRIPT),
            str(root),
            str(target),
            str(lock),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if tamper:
        assert result.returncode != 0
        assert "archive hash mismatch" in result.stderr
        assert not (target / "VCF.PowerCLI").exists()
        return
    assert result.returncode == 0, result.stdout + result.stderr
    assert sorted(p.name for p in (target / "VMware.OpenAPI").iterdir()) == ["1.0.0"]
    for path in target.rglob("*.psd1"):
        assert path.read_bytes() == (root / path.relative_to(target)).read_bytes()


@pytest.mark.parametrize("linked_component", ["module", "root"])
def test_linked_bundle_ancestor_is_rejected(
    bundle: tuple[Path, Path], linked_component: str
) -> None:
    """Identical package bytes outside a linked parent must never pass offline admission.

    Args:
        bundle: Fixture module-root and lock-file pair passed to the provisioning helper.
        linked_component: Bundle-root or module-parent component replaced by a filesystem link.
    """
    root, lock = bundle
    source = root / "VMware.OpenAPI" if linked_component == "module" else root
    destination = root.parent / f"relocated-{linked_component}"
    assert source.resolve().is_relative_to(lock.parent.resolve())
    assert destination.resolve().is_relative_to(lock.parent.resolve())
    source.rename(destination)
    if os.name == "nt":
        result = subprocess.run(
            [
                str(PWSH),
                "-NoProfile",
                "-Command",
                "New-Item -ItemType Junction -Path $env:LINK_PATH -Target $env:LINK_TARGET | Out-Null",
            ],
            env={
                **os.environ,
                "LINK_PATH": str(source),
                "LINK_TARGET": str(destination),
            },
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
    else:
        source.symlink_to(destination, target_is_directory=True)
    result = run(bundle)
    assert result.returncode != 0
    assert (
        "top-level inventory"
        if linked_component == "module"
        else "directory path contains a symlink"
    ) in result.stderr


def test_checked_in_lock_pins_the_reported_dependency_chain() -> None:
    """Keep the repaired release family explicit instead of resolving Gallery latest."""
    lock = json.loads(
        SCRIPT.with_name("powercli-lock.json").read_text(encoding="utf-8")
    )
    # Baseline upgrades may change the family, but these components must move together.
    family = lock["modules"]["VMware.OpenAPI"]
    assert lock["modules"]["VMware.Vcf.Sso"] == family
    assert lock["modules"]["VMware.VimAutomation.Common"] == family
    assert lock["modules"]["VMware.VimAutomation.Sdk"] == family
    assert lock["modules"]["VCF.PowerCLI"] == lock["suite_version"]


@pytest.mark.parametrize("extra_kind", ["module", "file", "link"])
def test_unlocked_top_level_entry_is_rejected(
    bundle: tuple[Path, Path], extra_kind: str
) -> None:
    """Reject everything outside the reviewed module inventory before vendor import.

    Args:
        bundle: Fixture module-root and lock-file pair passed to the validator.
        extra_kind: Unlocked module, loose file, or directory link added to the root.
    """
    root, _ = bundle
    if extra_kind == "module":
        module(root, "Unreviewed.Module", "1.0.0")
    elif extra_kind == "file":
        (root / ".unreviewed.psm1").write_text("throw 'unreviewed'", encoding="utf-8")
    else:
        target = root.parent / "unreviewed-target"
        target.mkdir()
        if os.name == "nt":
            result = subprocess.run(
                [
                    str(PWSH),
                    "-NoProfile",
                    "-Command",
                    "New-Item -ItemType Junction -Path $env:LINK_PATH -Target $env:LINK_TARGET | Out-Null",
                ],
                env={
                    **os.environ,
                    "LINK_PATH": str(root / "Unreviewed.Link"),
                    "LINK_TARGET": str(target),
                },
                timeout=30,
                capture_output=True,
                text=True,
                check=False,
            )
            assert result.returncode == 0, result.stderr
        else:
            (root / "Unreviewed.Link").symlink_to(target, target_is_directory=True)
    result = run(bundle)
    assert result.returncode != 0
    assert "top-level inventory" in result.stderr
