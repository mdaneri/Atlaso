"""Exercise image dependency admission with real PowerShell module manifests."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path("image/common/powershell/provision-powercli.ps1").resolve()
PWSH = shutil.which("pwsh")
pytestmark = pytest.mark.skipif(PWSH is None, reason="PowerShell is required")


def module(root: Path, name: str, version: str, required: str = "@()") -> Path:
    """Write a minimal importable vendor-shaped module without external dependencies."""
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


@pytest.fixture
def bundle(tmp_path: Path) -> tuple[Path, Path]:
    """Create a suite whose open-ended dependency must use the reviewed version."""
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
    return root, lock


def run(
    bundle: tuple[Path, Path], mode: str = "Validate", extra_root: Path | None = None
) -> subprocess.CompletedProcess[str]:
    """Run one clean process using only explicitly selected module search roots."""
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
    """A compatible minimum version loads with the suite and exposes its command."""
    result = run(bundle, "Verify")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Loaded locked PowerCLI module VMware.OpenAPI 1.0.0" in result.stdout


def test_side_by_side_newer_release_is_rejected(bundle: tuple[Path, Path]) -> None:
    """A later Gallery version cannot satisfy an open-ended requirement silently."""
    module(bundle[0], "VMware.OpenAPI", "1.1.0")
    result = run(bundle)
    assert result.returncode != 0
    assert "requires only VMware.OpenAPI 1.0.0" in result.stderr


def test_user_module_shadow_is_rejected(
    bundle: tuple[Path, Path], tmp_path: Path
) -> None:
    """Fresh administrator verification rejects another discoverable version."""
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
    """A lock must satisfy every unmodified vendor dependency declaration."""
    manifest = bundle[0] / "VCF.PowerCLI/9.1.0/VCF.PowerCLI.psd1"
    manifest.write_text(
        "@{ModuleVersion='9.1.0';RequiredModules=@(" + requirement + ")}",
        encoding="utf-8",
    )
    result = run(bundle)
    assert result.returncode != 0
    assert "violates" in result.stderr or "omits dependency" in result.stderr


def test_missing_locked_module_is_rejected(bundle: tuple[Path, Path]) -> None:
    """Incomplete offline bundles fail before copy or import."""
    (bundle[0] / "VMware.OpenAPI/1.0.0/VMware.OpenAPI.psd1").unlink()
    assert run(bundle).returncode != 0


def test_install_saves_each_exact_package_without_resolution(
    bundle: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    """A simulated Gallery latest release must never enter the saved package set."""
    root, lock = bundle
    target = tmp_path / "saved"
    wrapper = tmp_path / "install.ps1"
    wrapper.write_text(
        "param($Script,$Source,$Target,$Lock)\n"
        "function Save-PSResource {\n"
        "param($Name,$Version,$Repository,$Path,[switch]$SkipDependencyCheck,"
        "[switch]$TrustRepository,[switch]$AcceptLicense)\n"
        "if (-not $SkipDependencyCheck -or $Repository -ne 'PSGallery') { throw 'resolver called' }\n"
        "New-Item -ItemType Directory -Path (Join-Path $Path $Name) -Force | Out-Null\n"
        'Copy-Item -LiteralPath (Join-Path $Source "$Name/$Version") '
        "-Destination (Join-Path $Path $Name) -Recurse\n}\n"
        "& $Script -Mode Install -ModuleRoot $Target -LockPath $Lock\n",
        encoding="utf-8",
    )
    # The source advertises a newer dependency; only an exact version request is copied.
    module(root, "VMware.OpenAPI", "1.1.0")
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
    assert result.returncode == 0, result.stdout + result.stderr
    assert sorted(p.name for p in (target / "VMware.OpenAPI").iterdir()) == ["1.0.0"]
    for path in target.rglob("*.psd1"):
        assert path.read_bytes() == (root / path.relative_to(target)).read_bytes()


def test_checked_in_lock_pins_the_reported_dependency_chain() -> None:
    """Keep the repaired release family explicit instead of resolving Gallery latest."""
    lock = json.loads(
        SCRIPT.with_name("powercli-lock.json").read_text(encoding="utf-8")
    )
    assert lock["modules"]["VMware.OpenAPI"] == "13.5.0.25380678"
    assert lock["modules"]["VMware.Vim"] == "9.1.0.25380678"
    assert lock["modules"]["VMware.Vcf.Sso"] == "13.5.0.25380678"
    assert lock["modules"]["VMware.VimAutomation.Common"] == "13.5.0.25380678"
