"""Prove management handoff certificates cover actual acquired addresses."""

import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tests.test_appliance_helper import load_helper_module


def certificate_material(addresses):
    """Create synthetic public certificates without persisting private keys.

    Args:
        addresses: IP subject alternative names for the leaf.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "handoff test")])
    now = datetime.now(timezone.utc)
    base = (x509.CertificateBuilder().issuer_name(name)
            .public_key(key.public_key())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1)))
    root = base.subject_name(name).serial_number(x509.random_serial_number()).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256())
    leaf = (base.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "candidate")])).serial_number(x509.random_serial_number())
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ip_address(a)) for a in addresses]), critical=False)
            .sign(key, hashes.SHA256()))
    return tuple(cert.public_bytes(serialization.Encoding.PEM).decode() for cert in (root, leaf))


@pytest.fixture
def candidate(tmp_path, monkeypatch):
    """Provide an isolated staged and deployed public certificate pair.

    Args:
        tmp_path: Owned pytest directory.
        monkeypatch: Reversible helper boundary substitutions.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper, "CA_MANAGED_PATH_BASE", tmp_path)
    root, leaf = certificate_material(["192.0.2.10", "2001:db8::10"])
    root_path, cert_path, key_path = (tmp_path / name for name in ("root.pem", "leaf.pem", "key.pem"))
    root_path.write_text(root)
    cert_path.write_text(leaf)
    staged = {"root": {"root_cert_path": str(root_path), "certificate_pem": root},
              "certificates": [{"cert_path": str(cert_path), "key_path": str(key_path), "certificate_pem": leaf}]}
    monkeypatch.setattr(helper, "_load_ca_payload", lambda _path: staged)
    settings = {"management_https_enabled": True, "management_https_cert_path": str(cert_path),
                "management_https_key_path": str(key_path)}
    return helper, settings, staged, root_path


@pytest.mark.parametrize("addresses,accepted", [(["192.0.2.10"], True), (["192.0.2.11"], False),
                                                  (["192.0.2.10", "2001:db8::10"], True),
                                                  (["192.0.2.10", "2001:db8::11"], False)])
def test_actual_address_certificate_coverage(candidate, addresses, accepted):
    """Require every acquired family to match the real certificate SAN.

    Args:
        candidate: Synthetic certificate fixture.
        addresses: Acquired addresses, including same-address renewal.
        accepted: Whether all SANs match.
    """
    if not shutil.which("openssl"):
        pytest.skip("OpenSSL is required for certificate verification")
    helper, settings, _staged, root = candidate
    if accepted:
        assert helper._management_handoff_candidate_ca(helper._management_handoff_public_certificate({}, settings), addresses) == root
    else:
        with pytest.raises(ValueError, match="does not authenticate candidate address"):
            helper._management_handoff_candidate_ca(helper._management_handoff_public_certificate({}, settings), addresses)


@pytest.mark.parametrize("staged_matches", [False, True])
def test_staged_ca_mismatch(candidate, staged_matches):
    """Reject a deployed trust root that differs from transaction staging.

    Args:
        candidate: Synthetic certificate fixture.
        staged_matches: Whether staging also names the unrelated root.
    """
    helper, settings, staged, root = candidate
    replacement = certificate_material(["192.0.2.10"])[0]
    root.write_text(replacement)
    if staged_matches:
        if not shutil.which("openssl"):
            pytest.skip("OpenSSL is required for certificate verification")
        staged["root"]["certificate_pem"] = replacement
    message = "does not authenticate" if staged_matches else "does not match the staged transaction"
    with pytest.raises(ValueError, match=message):
        helper._management_handoff_candidate_ca(helper._management_handoff_public_certificate({}, settings), ["192.0.2.10"])


def test_http_requires_no_certificate():
    """Keep HTTP handoffs independent of managed certificate material."""
    helper = load_helper_module()
    assert helper._management_handoff_public_certificate({}, {}) is None
    assert helper._management_handoff_candidate_ca(None, ["192.0.2.11"]) is None


def test_explicit_ca_never_uses_insecure(candidate, monkeypatch):
    """Use an explicit CA without disabling curl identity verification.

    Args:
        candidate: Synthetic certificate fixture.
        monkeypatch: Reversible command collector.
    """
    helper, _settings, _staged, root = candidate
    calls = []
    monkeypatch.setattr(helper, "_run", lambda command: calls.append(command) or subprocess.CompletedProcess(command, 0, "200"))
    assert helper._console_management_http_status("curl", "https://192.0.2.10", insecure=True, ca_certificate=root) == "200"
    assert "--insecure" not in calls[0]
    assert calls[0][calls[0].index("--cacert") + 1] == str(root)



def test_readiness_uses_candidate_trust_only_for_selected_addresses(candidate, monkeypatch):
    """Keep old certificate holdovers distinct from the new candidate trust.

    Args:
        candidate: Synthetic certificate fixture.
        monkeypatch: Reversible readiness probes.
    """
    helper, _settings, _staged, root = candidate
    calls = []
    monkeypatch.setattr(helper.shutil, "which", lambda _name: "curl")
    monkeypatch.setattr(helper, "_console_management_http_status", lambda _curl, url, **options: calls.append((url, options)) or "200")
    helper._management_handoff_readiness(["192.0.2.10", "192.0.2.11"], True, 443,
                                         samples=1, tls_ca_paths={"192.0.2.11": root})
    assert calls[1][1] == {"insecure": True}
    assert calls[2][1] == {"ca_certificate": root}
    calls.clear()
    helper._management_handoff_readiness(["192.0.2.10", "192.0.2.11"], True, 443,
                                         samples=1, tls_ca_paths={address: root for address in ["192.0.2.10", "192.0.2.11"]})
    assert all(options == {"ca_certificate": root} for _url, options in calls[1:])


def test_public_certificate_survives_actual_ca_stage_cleanup(candidate, tmp_path, monkeypatch):
    """Verify acquired SANs after the real CA wrapper consumes its staged JSON.

    Args:
        candidate: Synthetic public certificate fixture.
        tmp_path: Owned test directory.
        monkeypatch: Reversible validation substitutions for synthetic public material.
    """
    import json

    if not shutil.which("openssl"):
        pytest.skip("OpenSSL is required for certificate verification")
    helper, settings, staged, root = candidate
    staged["root"].update(legacy_root_cert_path=str(tmp_path / "legacy.pem"),
                          ca_bundle_path=str(tmp_path / "bundle.pem"))
    stage = tmp_path / "ca.json"
    stage.write_text(json.dumps(staged))
    # Restore the actual JSON reader: an in-memory loader would mask stage deletion.
    monkeypatch.setattr(helper, "_load_ca_payload", load_helper_module()._load_ca_payload)
    monkeypatch.setattr(helper, "_validate_ca_config_path", lambda _path: stage)
    monkeypatch.setattr(helper, "_ca_payload_errors", lambda _path: [])
    snapshot = helper._management_handoff_public_certificate({"ca_config_path": str(stage)}, settings)
    assert isinstance(snapshot, tuple) and len(snapshot) == 4
    assert snapshot[1].startswith("-----BEGIN CERTIFICATE-----")
    assert snapshot[3].startswith("-----BEGIN CERTIFICATE-----")
    assert helper._handle_ca("apply", [str(stage)]) == 0
    assert not stage.exists()
    assert helper._management_handoff_candidate_ca(snapshot, ["192.0.2.10", "2001:db8::10"]) == root
    with pytest.raises(ValueError, match="does not authenticate candidate address"):
        helper._management_handoff_candidate_ca(snapshot, ["192.0.2.11"])
