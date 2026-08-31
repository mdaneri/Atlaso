"""Functional tests for shared Photon image-build safety contracts."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

VENV_VALIDATOR = Path("image/common/scripts/validate-bootstrap-venv.py")
QEMU_BUILDER = Path("image/common/scripts/build-qemu-guest-agent-rpm.sh")


def _make_bootstrap_layout(
    tmp_path: Path, version: str = "0.9.254"
) -> tuple[Path, Path]:
    """Create the supported two-link bootstrap virtualenv layout.

    Args:
        tmp_path: Temporary root for the isolated layout.
        version: Bootstrap release version to create.

    Returns:
        The Atlaso home and physical purelib paths.
    """
    home = tmp_path / "opt" / "atlaso"
    purelib = (
        home
        / "releases"
        / f"bootstrap-{version}"
        / ".venv"
        / "lib"
        / "python3.14"
        / "site-packages"
    )
    purelib.mkdir(parents=True)
    try:
        (home / "current").symlink_to(
            Path("releases") / f"bootstrap-{version}", target_is_directory=True
        )
        (home / ".venv").symlink_to(
            Path("current") / ".venv", target_is_directory=True
        )
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")
    return home, purelib


def _run_venv_validator(home: Path, version: str, purelib: Path) -> subprocess.CompletedProcess[str]:
    """Run the bootstrap identity validator with isolated paths.

    Args:
        home: Isolated Atlaso home path.
        version: Expected bootstrap release version.
        purelib: Logical or physical purelib path to validate.

    Returns:
        The completed validator subprocess.
    """
    return subprocess.run(
        [
            sys.executable,
            str(VENV_VALIDATOR),
            "--atlaso-home",
            str(home),
            "--version",
            version,
            "--purelib",
            str(purelib),
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def test_bootstrap_venv_validator_accepts_supported_two_link_chain(tmp_path: Path) -> None:
    """The compatibility paths may resolve to the exact physical release environment.

    Args:
        tmp_path: Temporary root for the isolated layout.
    """
    home, physical_purelib = _make_bootstrap_layout(tmp_path)

    result = _run_venv_validator(
        home, "0.9.254", home / ".venv" / "lib" / "python3.14" / "site-packages"
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(physical_purelib.resolve())


@pytest.mark.parametrize("failure", ["broken", "wrong-version", "escaping"])
def test_bootstrap_venv_validator_rejects_invalid_link_chains(
    tmp_path: Path, failure: str
) -> None:
    """Broken, wrong-version, and escaping compatibility links fail closed.

    Args:
        tmp_path: Temporary root for the isolated layout.
        failure: Invalid compatibility-link scenario to exercise.
    """
    home, _ = _make_bootstrap_layout(tmp_path)
    compatibility_venv = home / ".venv"
    logical_purelib = compatibility_venv / "lib" / "python3.14" / "site-packages"

    if failure == "broken":
        compatibility_venv.unlink()
        compatibility_venv.symlink_to("missing/.venv", target_is_directory=True)
    elif failure == "wrong-version":
        wrong_purelib = (
            home
            / "releases"
            / "bootstrap-0.9.999"
            / ".venv"
            / "lib"
            / "python3.14"
            / "site-packages"
        )
        wrong_purelib.mkdir(parents=True)
        (home / "current").unlink()
        (home / "current").symlink_to(
            "releases/bootstrap-0.9.999", target_is_directory=True
        )
    else:
        escaped_venv = tmp_path / "escaped" / ".venv"
        (escaped_venv / "lib" / "python3.14" / "site-packages").mkdir(
            parents=True
        )
        compatibility_venv.unlink()
        compatibility_venv.symlink_to(escaped_venv, target_is_directory=True)

    result = _run_venv_validator(home, "0.9.254", logical_purelib)

    assert result.returncode == 2
    assert "actual=" in result.stderr
    assert "expected=" in result.stderr
    assert "\n" not in result.stderr.rstrip("\n")


def test_bootstrap_venv_validator_rejects_escaping_purelib(tmp_path: Path) -> None:
    """The supported purelib directory itself cannot redirect outside the physical venv.

    Args:
        tmp_path: Temporary root for the isolated layout.
    """
    home, physical_purelib = _make_bootstrap_layout(tmp_path)
    escaped = tmp_path / "escaped-site-packages"
    escaped.mkdir()
    physical_purelib.rmdir()
    physical_purelib.symlink_to(escaped, target_is_directory=True)

    result = _run_venv_validator(
        home, "0.9.254", home / ".venv" / "lib" / "python3.14" / "site-packages"
    )

    assert result.returncode == 2
    assert "purelib identity mismatch" in result.stderr


def _write_executable(path: Path, content: str) -> None:
    """Write one executable test command.

    Args:
        path: Destination command path.
        content: Complete executable content.
    """
    path.write_text(content, encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell builder test")
def test_qemu_builder_overrides_preserved_communicator_home(tmp_path: Path) -> None:
    """QEMU mkvenv uses a private root-build HOME/cache and preserves pip indexes.

    Args:
        tmp_path: Temporary root for fake commands, output, and evidence.
    """
    command_dir = tmp_path / "commands"
    command_dir.mkdir()
    system_path = os.defpath
    real_stat = shutil.which("stat", path=system_path)
    real_install = shutil.which("install", path=system_path)
    shell = shutil.which("sh", path=system_path)
    assert real_stat and real_install and shell

    _write_executable(command_dir / "id", "#!/bin/sh\nprintf '0\\n'\n")
    _write_executable(
        command_dir / "stat",
        "#!/bin/sh\n"
        'value="$("$ATLASO_TEST_REAL_STAT" "$@")"\n'
        "printf '%s\\n' \"$value\" | awk -F: '{print $1 \":\" $2 \":0:0:\" $5}'\n",
    )
    _write_executable(
        command_dir / "install",
        f"#!{sys.executable}\n"
        "import os, pathlib, shutil, sys\n"
        "args = sys.argv[1:]\n"
        "mode = None\n"
        "paths = []\n"
        "directory = '-d' in args\n"
        "i = 0\n"
        "while i < len(args):\n"
        "    if args[i] in {'-o', '-g', '-m'}:\n"
        "        if args[i] == '-m': mode = int(args[i + 1], 8)\n"
        "        i += 2\n"
        "    elif args[i] == '-d': i += 1\n"
        "    else: paths.append(args[i]); i += 1\n"
        "if directory:\n"
        "    for item in paths:\n"
        "        pathlib.Path(item).mkdir(parents=True, exist_ok=True)\n"
        "        if mode is not None: os.chmod(item, mode)\n"
        "else:\n"
        "    source, destination = paths[-2:]\n"
        "    target = pathlib.Path(destination)\n"
        "    if target.is_dir(): target = target / pathlib.Path(source).name\n"
        "    target.parent.mkdir(parents=True, exist_ok=True)\n"
        "    shutil.copyfile(source, target)\n"
        "    if mode is not None: os.chmod(target, mode)\n",
    )
    _write_executable(
        command_dir / "curl",
        f"#!{sys.executable}\n"
        "import pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "pathlib.Path(args[args.index('--output') + 1]).write_bytes(b'archive')\n",
    )
    _write_executable(command_dir / "sha256sum", "#!/bin/sh\ncat >/dev/null\n")
    _write_executable(
        command_dir / "tar",
        f"#!{sys.executable}\n"
        "import os, pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "root = pathlib.Path(args[args.index('-C') + 1]) / 'qemu-10.2.2'\n"
        "root.mkdir(parents=True)\n"
        "configure = root / 'configure'\n"
        "configure.write_text('#!/bin/sh\\n'\n"
        "    'printf \\\"HOME=%s\\\\nPIP_CACHE_DIR=%s\\\\nXDG_CACHE_HOME=%s\\\\nPIP_INDEX_URL=%s\\\\n\\\" \\\"$HOME\\\" \\\"$PIP_CACHE_DIR\\\" \\\"$XDG_CACHE_HOME\\\" \\\"$PIP_INDEX_URL\\\" >\\\"$ATLASO_TEST_ENV_LOG\\\"\\n'\n"
        "    'case \\\"$HOME\\\" in /tmp/atlaso-qemu-guest-agent-build.*/home) ;; *) exit 40 ;; esac\\n'\n"
        "    'case \\\"$PIP_CACHE_DIR\\\" in /tmp/atlaso-qemu-guest-agent-build.*/pip-cache) ;; *) exit 41 ;; esac\\n'\n"
        "    'test \\\"$PIP_INDEX_URL\\\" = https://index.example.invalid/simple || exit 42\\n'\n"
        "    'mkdir -p build/qga build/meson-logs\\n', encoding='utf-8')\n"
        "os.chmod(configure, 0o755)\n",
    )
    _write_executable(
        command_dir / "ninja",
        "#!/bin/sh\nprintf '#!/bin/sh\\n' >build/qga/qemu-ga\nchmod 0755 build/qga/qemu-ga\n",
    )
    _write_executable(
        command_dir / "rpmbuild",
        f"#!{sys.executable}\n"
        "import pathlib, sys\n"
        "definition = sys.argv[sys.argv.index('--define') + 1]\n"
        "root = pathlib.Path(definition.removeprefix('_topdir '))\n"
        "rpm = root / 'RPMS' / 'x86_64' / 'atlaso-qemu-guest-agent-10.2.2-1.x86_64.rpm'\n"
        "rpm.parent.mkdir(parents=True, exist_ok=True)\n"
        "rpm.write_bytes(b'rpm')\n",
    )

    output = tmp_path / "output"
    environment_log = tmp_path / "environment.log"
    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{command_dir}{os.pathsep}{system_path}",
            "HOME": "/home/atlaso-build",
            "PIP_CACHE_DIR": "/home/atlaso-build/.cache/pip",
            "PIP_INDEX_URL": "https://index.example.invalid/simple",
            "ATLASO_SRC": str(Path.cwd()),
            "ATLASO_TEST_ENV_LOG": str(environment_log),
            "ATLASO_TEST_REAL_STAT": real_stat,
        }
    )

    result = subprocess.run(
        [shell, str(QEMU_BUILDER), str(output)],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    combined_output = result.stdout + result.stderr
    assert "/home/atlaso-build/.cache/pip" not in combined_output
    assert "not owned or is not writable" not in combined_output
    build_environment = environment_log.read_text(encoding="utf-8")
    assert "HOME=/tmp/atlaso-qemu-guest-agent-build." in build_environment
    assert "/home" in build_environment
    assert "PIP_CACHE_DIR=/tmp/atlaso-qemu-guest-agent-build." in build_environment
    assert "/pip-cache" in build_environment
    assert "PIP_INDEX_URL=https://index.example.invalid/simple" in build_environment
    assert len(list(output.glob("atlaso-qemu-guest-agent-*.rpm"))) == 1
