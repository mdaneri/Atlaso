"""Signed offline media must fail before disk consent when any byte differs."""

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.build_development_installation_iso import sign_test_manifest
from scripts.build_installation_iso import write_signed
from scripts.installation import manifest
from scripts.verify_installation_iso import verify_release


def test_inventory_uses_host_independent_posix_path_order(tmp_path):
    """Match Linux verification order when assembling on case-insensitive Windows.

    Args:
        tmp_path: Temporary fixture directory for mixed-case media names.
    """
    names = ["[Content_Types].xml", "EULA.rtf", "a-file", "Z-file"]
    for name in names:
        (tmp_path / name).write_bytes(b"public ordering fixture")
    assert [record["path"] for record in manifest.inventory(tmp_path)] == sorted(names)


@pytest.fixture
def signed_media(tmp_path, monkeypatch):
    """Create synthetic signed content without an operational signing secret.

Args:
    tmp_path: Temporary directory for this test's filesystem fixtures.
    monkeypatch: Pytest fixture for replacing controlled dependencies.
"""
    openssl = shutil.which("openssl")
    if openssl is None:
        bundled = Path("C:/Program Files/Git/usr/bin/openssl.exe")
        if bundled.is_file():
            openssl = str(bundled)
    if openssl is None:
        pytest.skip("OpenSSL is required for the boot-interpreter verification path")
    original_run = subprocess.run

    def run(command, **kwargs):
        """
        Args:
            command: Subprocess argument vector received by the test double.
            **kwargs: Additional subprocess options received by the test double.
        """
        return original_run([openssl, *command[1:]], **kwargs)

    monkeypatch.setattr(manifest.subprocess, "run", run)
    root = tmp_path / "media"
    root.mkdir()
    key = Ed25519PrivateKey.generate()
    trust = tmp_path / "trust.pem"
    trust.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    files = {
        "source/scripts/installation/installer.py": b"# installer fixture\n",
        "source/image/common/scripts/provision-atlaso.sh": b"# provision fixture\n",
        "software/release-manifest.json": b"{}\n",
        "software/release-manifest.json.sig": b"{}\n",
        "rpms/linux-fixture.rpm": b"rpm fixture",
        "rpms/python3-fixture.rpm": b"python fixture",
        "powercli/fixture": b"module fixture",
        "tdnf.conf": b"[main]\n",
    }
    source = {"version": "0.9.453", "source_commit": "a" * 40, "release_manifest_sha256": hashlib.sha256(files["software/release-manifest.json"]).hexdigest()}
    files["software/virtualization-source.json"] = json.dumps(source).encode()
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    rpms = [{"file": f"{name}-fixture.rpm", "name": name, "version": "1.0-1.ph5", "architecture": "x86_64", "sha256": manifest.digest(root / f"rpms/{name}-fixture.rpm")} for name in ("linux", "python3")]
    value = {"schema": 1, "architecture": "x86_64", "photon_installer": "2.2", "photon_installer_sha256": manifest.PHOTON_INSTALLER_SHA256, "photon_iso_sha512": manifest.SOURCE_ISO_SHA512, "version": source["version"], "source_commit": source["source_commit"], "signing_key_id": manifest.KEY_ID, "packages": ["linux", "python3"], "rpm_inventory": rpms, "files": manifest.inventory(root)}
    write_signed(root / manifest.MANIFEST, value, key)
    return root, trust, scratch, value, key


@pytest.mark.parametrize("boot_crypto", [False, True])
def test_complete_media_is_verified_with_existing_crypto(signed_media, monkeypatch, boot_crypto):
    """
    Args:
        signed_media: Synthetic signed media fixture used by the test.
        monkeypatch: Fixture for rejecting external commands in boot mode.
        boot_crypto: Whether to use the existing initrd Python verifier.
    """
    root, trust, scratch, value, _ = signed_media
    if boot_crypto:
        def reject_command(*_args, **_kwargs):
            """Reject external executables in the boot verification regression.

            Args:
                *_args: Positional subprocess options.
                **_kwargs: Named subprocess options.
            """
            raise AssertionError("Boot verification must not require an OpenSSL executable")

        monkeypatch.setattr(manifest.subprocess, "run", reject_command)
    assert manifest.verify_media(root, trust, scratch=scratch, boot_crypto=boot_crypto) == value
    assert not list(scratch.iterdir())


def test_development_media_requires_explicit_separate_trust(signed_media):
    """Production defaults reject public-test signatures and distinct identities.

    Args:
        signed_media: Synthetic signed media fixture used by the test.
    """
    root, trust, scratch, value, _ = signed_media
    value["signing_key_id"] = manifest.DEVELOPMENT_KEY_ID
    value["source_commit"] = "b" * 40
    value["development"] = {"schema": 1, "software_source_commit": "a" * 40, "non_production": True}
    (root / manifest.MANIFEST).write_bytes(manifest.canonical_json(value))
    (root / manifest.SIGNATURE).unlink()
    trust.write_bytes(sign_test_manifest(root))
    with pytest.raises(ValueError, match="pinned Atlaso key"):
        manifest.verify_media(root, trust, scratch=scratch)
    assert manifest.verify_media(root, trust, scratch=scratch, expected_key_id=manifest.DEVELOPMENT_KEY_ID) == value
    with pytest.raises(ValueError, match="public test signing"):
        value["signing_key_id"] = manifest.KEY_ID
        (root / manifest.MANIFEST).write_bytes(manifest.canonical_json(value))
        sign_test_manifest(root)


def test_development_marker_is_vmware_only(monkeypatch, tmp_path):
    """An absent marker retains production trust; physical systems reject test mode.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        tmp_path: Temporary directory for filesystem fixtures.
    """
    marker = tmp_path / "development"
    monkeypatch.setattr(manifest, "DEVELOPMENT_MARKER", marker)
    assert manifest.installer_key_id() == manifest.KEY_ID
    marker.write_bytes((manifest.DEVELOPMENT_KEY_ID + "\n").encode())
    original = Path.read_text

    def read_text(path, *args, **kwargs):
        """Return a controlled DMI vendor while retaining ordinary file reads.

        Args:
            path: File path to read.
            *args: Positional file read options.
            **kwargs: Named file read options.
        """
        if str(path).replace("\\", "/") == "/sys/class/dmi/id/sys_vendor":
            return "Physical hardware\n"
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read_text)
    with pytest.raises(ValueError, match="VMware test guests"):
        manifest.installer_key_id()


@pytest.mark.parametrize("mutation", ["file", "extra", "signature", "manifest", "trust"])
@pytest.mark.parametrize("boot_crypto", [False, True])
def test_changed_media_is_rejected(signed_media, mutation, boot_crypto):
    """
    Args:
        signed_media: Synthetic signed media fixture used by the test.
        mutation: Callback that changes one signed fixture input.
        boot_crypto: Existing host or initrd verifier being exercised.
    """
    root, trust, scratch, _, _ = signed_media
    if mutation == "file":
        (root / "rpms/linux-fixture.rpm").write_bytes(b"different bytes")
    elif mutation == "extra":
        (root / "unexpected").write_text("unbound")
    elif mutation == "signature":
        value = json.loads((root / manifest.SIGNATURE).read_bytes())
        value["signature"] = "A" * 88
        (root / manifest.SIGNATURE).write_text(json.dumps(value))
    elif mutation == "manifest":
        (root / manifest.MANIFEST).write_bytes(b"{}\n")
    else:
        other = Ed25519PrivateKey.generate()
        trust.write_bytes(other.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        manifest.verify_media(root, trust, scratch=scratch, boot_crypto=boot_crypto)


@pytest.mark.parametrize("field,value", [("architecture", "aarch64"), ("schema", 2), ("packages", ["linux;echo injected"]), ("packages", [["linux"]]), ("photon_installer", "2.3"), ("rpm_inventory", []), ("source_commit", "b" * 40)])
def test_even_signed_incompatible_metadata_is_rejected(signed_media, field, value):
    """
    Args:
        signed_media: Synthetic signed media fixture used by the test.
        field: Manifest field modified by the parameterized case.
        value: Value supplied to the test case.
    """
    root, trust, scratch, document, key = signed_media
    document[field] = value
    write_signed(root / manifest.MANIFEST, document, key)
    with pytest.raises(ValueError):
        manifest.verify_media(root, trust, scratch=scratch)


def test_release_verification_binds_parts_to_version_and_commit(signed_media):
    """
    Args:
        signed_media: Synthetic signed media fixture used by the test.
    """
    root, trust, scratch, _, key = signed_media
    iso = root / "atlaso.iso"
    iso.write_bytes(b"synthetic ISO bytes")
    record = {"name": iso.name, "size": iso.stat().st_size, "sha256": manifest.digest(iso)}
    verifier = root / "verify-installation.pyz"
    verifier.write_bytes(b"synthetic verifier")
    verifier_record = {"name": verifier.name, "size": verifier.stat().st_size, "sha256": manifest.digest(verifier)}
    value = {"schema": 1, "kind": "atlaso-installation", "architecture": "x86_64", "signing_key_id": manifest.KEY_ID, "version": "0.9.453", "source_commit": "a" * 40, "asset_manifest": {"schema": 1, "iso": record, "assets": [record]}, "verifier": verifier_record}
    write_signed(root / "installation-artifact-index.json", value, key)
    assert verify_release(root, trust, scratch, version="0.9.453", commit="a" * 40) == value
    with pytest.raises(ValueError, match="version or source"):
        verify_release(root, trust, scratch, version="0.9.454", commit="a" * 40)
    verifier.write_bytes(b"tampered verifier")
    with pytest.raises(ValueError, match="checksum"):
        verify_release(root, trust, scratch, version="0.9.453", commit="a" * 40)
    verifier.write_bytes(b"synthetic verifier")
    iso.write_bytes(b"different ISO bytes")
    with pytest.raises(ValueError, match="checksum"):
        verify_release(root, trust, scratch, version="0.9.453", commit="a" * 40)


def test_signed_rpm_inventory_must_match_every_rpm(signed_media):
    """
    Args:
        signed_media: Synthetic signed media fixture used by the test.
    """
    root, trust, scratch, value, key = signed_media
    value["rpm_inventory"][0]["sha256"] = "0" * 64
    write_signed(root / manifest.MANIFEST, value, key)
    with pytest.raises(ValueError, match="RPM inventory differs"):
        manifest.verify_media(root, trust, scratch=scratch)
