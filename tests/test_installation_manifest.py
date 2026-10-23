"""Signed offline media must fail before disk consent when any byte differs."""

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.build_installation_iso import write_signed
from scripts.installation import manifest
from scripts.verify_installation_iso import verify_release


@pytest.fixture
def signed_media(tmp_path, monkeypatch):
    """Create synthetic signed content without an operational signing secret."""
    openssl = shutil.which("openssl")
    if openssl is None:
        bundled = Path("C:/Program Files/Git/usr/bin/openssl.exe")
        if bundled.is_file():
            openssl = str(bundled)
    if openssl is None:
        pytest.skip("OpenSSL is required for the boot-interpreter verification path")
    original_run = subprocess.run

    def run(command, **kwargs):
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


def test_complete_media_is_verified_with_openssl(signed_media):
    root, trust, scratch, value, _ = signed_media
    assert manifest.verify_media(root, trust, scratch=scratch) == value
    assert not list(scratch.iterdir())


@pytest.mark.parametrize("mutation", ["file", "extra", "signature", "manifest", "trust"])
def test_changed_media_is_rejected(signed_media, mutation):
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
        manifest.verify_media(root, trust, scratch=scratch)


@pytest.mark.parametrize("field,value", [("architecture", "aarch64"), ("schema", 2), ("packages", ["linux;echo injected"]), ("packages", [["linux"]]), ("photon_installer", "2.3"), ("rpm_inventory", []), ("source_commit", "b" * 40)])
def test_even_signed_incompatible_metadata_is_rejected(signed_media, field, value):
    root, trust, scratch, document, key = signed_media
    document[field] = value
    write_signed(root / manifest.MANIFEST, document, key)
    with pytest.raises(ValueError):
        manifest.verify_media(root, trust, scratch=scratch)


def test_release_verification_binds_parts_to_version_and_commit(signed_media):
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
    root, trust, scratch, value, key = signed_media
    value["rpm_inventory"][0]["sha256"] = "0" * 64
    write_signed(root / manifest.MANIFEST, value, key)
    with pytest.raises(ValueError, match="RPM inventory differs"):
        manifest.verify_media(root, trust, scratch=scratch)
