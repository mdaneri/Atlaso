"""Tests for isolated development ISO input admission."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.installation import build, development
from scripts.installation.manifest import DEVELOPMENT_KEY_ID, MANIFEST


def _git(repository: Path, *args: str) -> str:
    """Run a quiet Git command for a disposable test repository.

    Args:
        repository: Temporary Git repository.
        *args: Git arguments after the executable.
    """
    return subprocess.check_output(
        ["git", "-C", str(repository), *args], text=True, stderr=subprocess.DEVNULL
    ).strip()


def _source_repository(path: Path) -> str:
    """Create a committed source fixture with the shared provisioning inputs.

    Args:
        path: Temporary path for the repository.
    """
    path.mkdir()
    _git(path, "init", "--quiet")
    _git(path, "config", "user.email", "tests@example.invalid")
    _git(path, "config", "user.name", "Atlaso test")
    files = {
        "image/common/scripts/provision-atlaso.sh": (
            'run_tdnf "Photon appliance package installation" \\\n  install python3 linux-firmware\n'
        ),
        "image/common/photon-rpm-gpg/VMWARE-RPM-GPG-KEY-test": "test-key\n",
        "image/common/powershell/provision-powercli.ps1": "# validation fixture\n",
        "image/common/update-trust/atlaso-release-2026-01.pem": "public trust fixture\n",
        "scripts/installation/installer.py": "print('fixture')\n",
    }
    for name, content in files.items():
        target = path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    _git(path, "add", ".")
    _git(path, "commit", "--quiet", "-m", "test source")
    return _git(path, "rev-parse", "HEAD")


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path]:
    """Create source, signed-release, RPM, PowerCLI, and scratch fixtures.

    Args:
        tmp_path: Pytest-owned fixture directory.
    """
    repository = tmp_path / "repository"
    _source_repository(repository)
    software = tmp_path / "software"
    software.mkdir()
    (software / "wheel.whl").write_bytes(b"signed-main-release-wheel")
    rpms = tmp_path / "rpms"
    rpms.mkdir()
    (rpms / "package.rpm").write_bytes(b"photon-package")
    powercli = tmp_path / "powercli"
    powercli.mkdir()
    (powercli / "module.psm1").write_text("module fixture\n", encoding="utf-8")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    return repository, software, rpms, powercli, scratch


def _mock_build_tools(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    """Stub external release, RPM, metadata, and PowerShell validation.

    Args:
        monkeypatch: Pytest fixture for controlled replacement.
    """
    monkeypatch.setattr(
        "scripts.prepare_virtualization_source.verify_directory",
        lambda _root, _key, version, commit: {"version": version, "source_commit": commit},
    )
    validation_scratch: list[Path] = []

    def verify_rpms(_rpms: Path, _source: Path, scratch: Path) -> list[dict[str, str]]:
        """Stub RPM verification and record its private scratch directory.

        Args:
            _rpms: RPM repository supplied to the verifier.
            _source: Trusted source checkout supplied to the verifier.
            scratch: Existing directory for RPM validation state.
        """
        (scratch / "rpmdb").mkdir()
        validation_scratch.append(scratch)
        return [{
            "file": "package.rpm",
            "name": "package",
            "version": "1-1",
            "architecture": "x86_64",
            "sha256": "a" * 64,
        }]

    monkeypatch.setattr(build, "verify_rpms", verify_rpms)

    def rebuild(rpms: Path, _scratch: Path) -> None:
        """Stub replacement of RPM repository metadata.

        Args:
            rpms: RPM repository whose metadata is rebuilt.
            _scratch: Existing directory for temporary validation state.
        """
        metadata = rpms / "repodata"
        metadata.mkdir()
        (metadata / "repomd.xml").write_text("generated metadata", encoding="utf-8")

    monkeypatch.setattr(build, "rebuild_repository", rebuild)

    monkeypatch.setattr(
        development,
        "subprocess",
        SimpleNamespace(
            check_output=subprocess.check_output,
            run=lambda *_args, **_kwargs: None,
            DEVNULL=subprocess.DEVNULL,
        ),
    )
    return validation_scratch


def test_prepare_payload_separates_pr_source_from_main_software_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Development provenance records independent source and software commits.

    Args:
        tmp_path: Pytest-owned fixture directory.
        monkeypatch: Pytest fixture for controlled replacement.
    """
    repository, software, rpms, powercli, scratch = _inputs(tmp_path)
    source_commit = _git(repository, "rev-parse", "HEAD")
    software_commit = "b" * 40
    rpm_scratch = _mock_build_tools(monkeypatch)
    output = tmp_path / "payload"

    development.prepare_payload(
        repository=repository,
        commit=source_commit,
        software_version="1.2.3",
        software_commit=software_commit,
        software=software,
        rpms=rpms,
        powercli=powercli,
        output=output,
        scratch=scratch,
    )

    manifest = json.loads((output / MANIFEST).read_bytes())
    assert manifest["source_commit"] == source_commit
    assert manifest["version"] == "1.2.3"
    assert manifest["development"] == {
        "schema": 1,
        "software_source_commit": software_commit,
        "non_production": True,
    }
    assert manifest["signing_key_id"] == DEVELOPMENT_KEY_ID
    assert (output / "source/scripts/installation/installer.py").read_text(encoding="utf-8") == "print('fixture')\n"
    assert (output / "rpms/repodata/repomd.xml").exists()
    assert len(rpm_scratch) == 2
    assert rpm_scratch[0] != rpm_scratch[1]
    assert all((path / "rpmdb").is_dir() for path in rpm_scratch)


@pytest.mark.parametrize(
    ("mutation", "commit", "message"),
    [
        ("dirty", None, "checkout must be clean"),
        ("clean", "0" * 40, "HEAD differs"),
    ],
    ids=["dirty-checkout", "different-head"],
)
def test_prepare_payload_rejects_source_that_is_not_clean_exact_head(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    commit: str | None,
    message: str,
) -> None:
    """Source archive admission refuses dirty or mismatched checkouts.

    Args:
        tmp_path: Pytest-owned fixture directory.
        monkeypatch: Pytest fixture for controlled replacement.
        mutation: Source condition to introduce.
        commit: Optional incorrect source commit.
        message: Expected admission diagnostic.
    """
    repository, software, rpms, powercli, scratch = _inputs(tmp_path)
    head = _git(repository, "rev-parse", "HEAD")
    _mock_build_tools(monkeypatch)
    if mutation == "dirty":
        (repository / "scripts/installation/installer.py").write_text("modified\n", encoding="utf-8")
    output = tmp_path / "payload"

    with pytest.raises(ValueError, match=message):
        development.prepare_payload(
            repository=repository,
            commit=commit or head,
            software_version="1.2.3",
            software_commit="b" * 40,
            software=software,
            rpms=rpms,
            powercli=powercli,
            output=output,
            scratch=scratch,
        )

    assert not output.exists()


def test_prepare_payload_rejects_non_main_software_commit_before_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Software release commit must independently be reachable from main.

    Args:
        tmp_path: Pytest-owned fixture directory.
        monkeypatch: Pytest fixture for controlled replacement.
    """
    repository, software, rpms, powercli, scratch = _inputs(tmp_path)
    source_commit = _git(repository, "rev-parse", "HEAD")
    _mock_build_tools(monkeypatch)
    calls: list[list[str]] = []

    def run(command: list[str], **_kwargs: object) -> None:
        """Record the Git command and emulate an unrelated-ancestry result.

        Args:
            command: Git argument vector passed by the payload builder.
            **_kwargs: Additional subprocess options supplied by the builder.
        """
        calls.append(command)
        if "merge-base" in command:
            raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(development.subprocess, "run", run)
    output = tmp_path / "payload"

    with pytest.raises(subprocess.CalledProcessError):
        development.prepare_payload(
            repository=repository,
            commit=source_commit,
            software_version="1.2.3",
            software_commit="b" * 40,
            software=software,
            rpms=rpms,
            powercli=powercli,
            output=output,
            scratch=scratch,
        )

    assert not output.exists()
    assert len(calls) == 1


@pytest.mark.parametrize(
    ("version", "software_commit"),
    [("1.2", "b" * 40), ("1.2.3", "not-a-sha")],
    ids=["invalid-version", "invalid-software-sha"],
)
def test_prepare_payload_rejects_invalid_software_identity_before_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    version: str,
    software_commit: str,
) -> None:
    """Reject malformed independent software identity fields early.

    Args:
        tmp_path: Pytest-owned fixture directory.
        monkeypatch: Pytest fixture for controlled replacement.
        version: Software version input.
        software_commit: Software source commit input.
    """
    repository, software, rpms, powercli, scratch = _inputs(tmp_path)
    source_commit = _git(repository, "rev-parse", "HEAD")
    output = tmp_path / "payload"

    with pytest.raises(ValueError, match="software (version|commit)"):
        development.prepare_payload(
            repository=repository,
            commit=source_commit,
            software_version=version,
            software_commit=software_commit,
            software=software,
            rpms=rpms,
            powercli=powercli,
            output=output,
            scratch=scratch,
        )

    assert not output.exists()


def test_prepare_payload_rejects_existing_output_without_mutating_it(
    tmp_path: Path,
) -> None:
    """Output collisions fail closed and preserve the existing sentinel.

    Args:
        tmp_path: Pytest-owned fixture directory.
    """
    repository, software, rpms, powercli, scratch = _inputs(tmp_path)
    output = tmp_path / "payload"
    output.mkdir()
    sentinel = output / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")

    with pytest.raises(ValueError, match="must be absent"):
        development.prepare_payload(
            repository=repository,
            commit=_git(repository, "rev-parse", "HEAD"),
            software_version="1.2.3",
            software_commit="b" * 40,
            software=software,
            rpms=rpms,
            powercli=powercli,
            output=output,
            scratch=scratch,
        )

    assert sentinel.read_text(encoding="utf-8") == "keep"
