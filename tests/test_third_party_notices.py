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


def test_notice_version_lock(tmp_path):
    """A selected release's installed package cannot satisfy a newer source lock.

    Args:
        tmp_path: Isolated installed metadata and different dependency locks.
    """
    module = load_module()
    environment = tmp_path / "environment"
    metadata = environment / "Lib/site-packages/authlib-1.8.0.dist-info/METADATA"
    metadata.parent.mkdir(parents=True)
    metadata.write_text(
        "Metadata-Version: 2.4\nName: Authlib\nVersion: 1.8.0\n"
        "License-Expression: BSD-3-Clause\nHome-page: https://example.invalid/authlib\n"
    )
    release, checkout = tmp_path / "release.lock", tmp_path / "checkout.lock"
    release.write_text("authlib==1.8.0\n")
    checkout.write_text("authlib==1.9.1\n")
    records = module.installed_python_records(environment, module.locked_packages(release))
    assert records["authlib"]["version"] == "1.8.0"
    with pytest.raises(ValueError, match="installed Python version mismatch"):
        module.installed_python_records(environment, module.locked_packages(checkout))


def write_wheel(
    path: Path,
    *,
    license_name: str = "MIT",
    top_level: tuple[str, str] | None = ("Example-Package", "1.2.3"),
    nested_metadata: tuple[str, str] = ("helper", "1.0"),
    duplicate_top_level: bool = False,
) -> None:
    """Persist wheel.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        license_name: License name supplied by the caller.
        top_level: Optional top-level distribution identity.
        nested_metadata: Vendored distribution identity to embed.
        duplicate_top_level: Whether to add a second matching top-level identity.
    """
    def metadata(name: str, version: str) -> str:
        """Build distribution metadata for a synthetic wheel.

        Args:
            name: Distribution name declared by the fixture.
            version: Distribution version declared by the fixture.
        """
        return "\n".join(
            [
                "Metadata-Version: 2.4",
                f"Name: {name}",
                f"Version: {version}",
                f"License-Expression: {license_name}" if license_name else "",
                "Home-page: https://example.invalid/package",
                "",
            ]
        )

    with zipfile.ZipFile(path, "w") as archive:
        top_level_metadata = metadata(*top_level) if top_level is not None else None
        if top_level_metadata is not None:
            archive.writestr("example_package-1.2.3.dist-info/METADATA", top_level_metadata)
        if duplicate_top_level:
            archive.writestr("duplicate_example-1.2.3.dist-info/METADATA", top_level_metadata)
        archive.writestr(
            "example_package/_vendor/helper-1.0.dist-info/METADATA",
            metadata(*nested_metadata),
        )


def test_wheel_records_ignore_vendored_metadata_for_another_locked_package(tmp_path):
    """A vendored locked identity cannot make a wheel metadata-ambiguous.

    Args:
        tmp_path: Isolated wheelhouse used by the test.
    """
    module = load_module()
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    write_wheel(
        wheelhouse / "example_package-1.2.3-py3-none-any.whl",
        nested_metadata=("packaging", "26.3"),
    )
    write_wheel(
        wheelhouse / "packaging-26.3-py3-none-any.whl",
        top_level=("packaging", "26.3"),
    )

    records = module.wheel_records(
        wheelhouse,
        {"example-package": ("1.2.3", "example-package"), "packaging": ("26.3", "packaging")},
    )

    assert records["example-package"]["version"] == "1.2.3"
    assert records["packaging"]["version"] == "26.3"


@pytest.mark.parametrize("top_level", (None, ("Example-Package", "9.9.9")))
def test_wheel_records_do_not_use_nested_metadata_as_locked_identity(tmp_path, top_level):
    """Nested metadata cannot supply a missing or mismatched top-level identity.

    Args:
        tmp_path: Isolated wheelhouse used by the test.
        top_level: Optional top-level distribution identity.
    """
    module = load_module()
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    write_wheel(
        wheelhouse / "example_package-1.2.3-py3-none-any.whl",
        top_level=top_level,
        nested_metadata=("Example-Package", "1.2.3"),
    )

    with pytest.raises(ValueError, match="exactly one locked package"):
        module.wheel_records(wheelhouse, {"example-package": ("1.2.3", "example-package")})


def test_wheel_records_reject_ambiguous_top_level_locked_metadata(tmp_path):
    """Multiple matching top-level identities remain an error.

    Args:
        tmp_path: Isolated wheelhouse used by the test.
    """
    module = load_module()
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    write_wheel(
        wheelhouse / "example_package-1.2.3-py3-none-any.whl",
        duplicate_top_level=True,
    )

    with pytest.raises(ValueError, match="exactly one locked package"):
        module.wheel_records(wheelhouse, {"example-package": ("1.2.3", "example-package")})


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
