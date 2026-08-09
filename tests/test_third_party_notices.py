"""Test third party notices behavior."""

from __future__ import annotations

import importlib.util
import json
import sys
import zipfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def load_module():
    """Return module."""
    spec = importlib.util.spec_from_file_location(
        "generate_third_party_notices", ROOT / "scripts/generate_third_party_notices.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_wheel(path: Path, *, license_name: str = "MIT") -> None:
    """Persist wheel.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        license_name: License name supplied by the caller.
    """
    metadata = "\n".join(
        [
            "Metadata-Version: 2.4",
            "Name: Example-Package",
            "Version: 1.2.3",
            f"License-Expression: {license_name}" if license_name else "",
            "Home-page: https://example.invalid/package",
            "",
        ]
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("example_package-1.2.3.dist-info/METADATA", metadata)
        archive.writestr(
            "example_package/_vendor/helper-1.0.dist-info/METADATA",
            "Metadata-Version: 2.4\nName: helper\nVersion: 1.0\nLicense: MIT\n",
        )


def test_generator_uses_locked_wheel_metadata_and_is_deterministic(monkeypatch, tmp_path):
    """Verify that generator uses locked wheel metadata and is deterministic.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    module = load_module()
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    write_wheel(wheelhouse / "example_package-1.2.3-py3-none-any.whl")
    lock = tmp_path / "requirements.lock"
    lock.write_text("example-package==1.2.3\n", encoding="utf-8")
    config = tmp_path / "vendors.json"
    config.write_text(
        json.dumps(
            {
                "vendored_components": [
                    {
                        "name": "Bundled test component",
                        "version": "1.0",
                        "license": "MIT",
                        "source": "https://example.invalid/vendor",
                        "notice_path": "LICENSE",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    rpm = tmp_path / "rpm.tsv"
    rpm.write_text("photon-package\t1.0-1\tApache-2.0\thttps://example.invalid/rpm\n", encoding="utf-8")
    first = tmp_path / "first.md"
    second = tmp_path / "second.md"
    arguments = [
        "generate_third_party_notices.py",
        "--version",
        "1.2.3",
        "--lock",
        str(lock),
        "--wheelhouse",
        str(wheelhouse),
        "--vendored-config",
        str(config),
        "--rpm-inventory",
        str(rpm),
        "--output",
        str(first),
    ]
    monkeypatch.setattr(sys, "argv", arguments)
    assert module.main() == 0
    arguments[-1] = str(second)
    monkeypatch.setattr(sys, "argv", arguments)
    assert module.main() == 0
    assert first.read_bytes() == second.read_bytes()
    text = first.read_text(encoding="utf-8")
    assert "Example-Package" in text
    assert "Photon appliance RPM packages" in text
    assert "Bundled test component" in text


def test_generator_rejects_wheel_without_license(monkeypatch, tmp_path):
    """Verify that generator rejects wheel without license.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    module = load_module()
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    write_wheel(wheelhouse / "example_package-1.2.3-py3-none-any.whl", license_name="")
    lock = tmp_path / "requirements.lock"
    lock.write_text("example-package==1.2.3\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="missing a license"):
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "generate_third_party_notices.py",
                "--version",
                "1.2.3",
                "--lock",
                str(lock),
                "--wheelhouse",
                str(wheelhouse),
                "--output",
                str(tmp_path / "notices.md"),
            ],
        )
        module.main()


@pytest.mark.parametrize(
    "site_packages_relative",
    (
        "lib/python3.14/site-packages",
        "lib64/python3.14/site-packages",
        "Lib/site-packages",
    ),
)
def test_installed_records_ignore_nested_vendored_distribution_metadata(
    tmp_path,
    site_packages_relative,
):
    """Verify that installed records ignore nested vendored distribution metadata.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        site_packages_relative: Site packages relative supplied to the test scenario.
    """
    module = load_module()
    environment = tmp_path / "environment"
    site_packages = environment / site_packages_relative
    installed_metadata = site_packages / "wheel-0.45.1.dist-info/METADATA"
    installed_metadata.parent.mkdir(parents=True)
    installed_metadata.write_text(
        "\n".join(
            [
                "Metadata-Version: 2.4",
                "Name: wheel",
                "Version: 0.45.1",
                "License-Expression: MIT",
                "Home-page: https://github.com/pypa/wheel",
                "",
            ]
        ),
        encoding="utf-8",
    )
    vendored_metadata = site_packages / "setuptools/_vendor/wheel-0.46.3.dist-info/METADATA"
    vendored_metadata.parent.mkdir(parents=True)
    vendored_metadata.write_text(
        "\n".join(
            [
                "Metadata-Version: 2.4",
                "Name: wheel",
                "Version: 0.46.3",
                "License-Expression: MIT",
                "Home-page: https://github.com/pypa/wheel",
                "",
            ]
        ),
        encoding="utf-8",
    )

    records = module.installed_python_records(
        environment,
        {"wheel": ("0.45.1", "wheel")},
    )

    assert records["wheel"]["version"] == "0.45.1"
