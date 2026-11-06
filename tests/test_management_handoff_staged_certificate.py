"""Exercise staged certificate validation against real retained listener scope."""

import json
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tests.test_appliance_helper import load_helper_module


@pytest.fixture
def staged_case(tmp_path, monkeypatch):
    """Build staged material in memory; persist public certificates and settings only.

    Args:
        tmp_path: Owned test directory.
        monkeypatch: Isolate unrelated unit validators and private-key file I/O.
    """
    if not shutil.which("openssl"):
        pytest.skip("OpenSSL is required for native certificate coverage checks")

    def create(method="static", invalid=""):
        """Return a public test case while all private signing material stays in memory.

        Args:
            method: Reviewed management interface address method.
            invalid: Optional malformed material or mismatched configured key path.
        """
        helper = load_helper_module()
        monkeypatch.setattr(helper, "CA_MANAGED_PATH_BASE", tmp_path.resolve())
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(UTC)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "handoff fixture CA")])
        builder = (x509.CertificateBuilder().issuer_name(name).public_key(key.public_key())
                   .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1)))
        root = (builder.subject_name(name).serial_number(x509.random_serial_number())
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(key, hashes.SHA256()))

        def leaf(address):
            """Issue one public fixture certificate.

            Args:
                address: IP subject alternative name.
            """
            certificate = (builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "candidate")]))
                           .serial_number(x509.random_serial_number())
                           .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                           .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                           .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ip_address(address))]), critical=False)
                           .sign(key, hashes.SHA256()))
            return certificate.public_bytes(serialization.Encoding.PEM).decode()

        root_pem = root.public_bytes(serialization.Encoding.PEM).decode()
        candidate_pem = leaf("192.0.2.20")
        root_path, certificate_path, key_path = (tmp_path / value for value in ("root.pem", "leaf.pem", "key.pem"))
        root_path.write_text(root_pem)
        certificate_path.write_text(leaf("192.0.2.10"))
        signing_key = ec.generate_private_key(ec.SECP256R1()) if invalid == "key_mismatch" else key
        staged = {"root": {"root_cert_path": str(root_path), "certificate_pem": root_pem}, "certificates": [{
            "cert_path": str(certificate_path),
            "key_path": str(tmp_path / "foreign.key") if invalid == "foreign_path" else str(key_path),
            "certificate_pem": "invalid public certificate" if invalid == "certificate" else candidate_pem,
            "private_key_pem": signing_key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
            ).decode(),
        }]}
        monkeypatch.setattr(helper, "_load_ca_payload", lambda _path: staged)

        def public_key_in_memory(pem, *, private_key):
            """Replace only OpenSSL's temporary-file adapter with in-memory public-key extraction.

            Args:
                pem: Fixture PEM held only in the test process.
                private_key: Whether to parse the private side of the pair.
            """
            try:
                material = (serialization.load_pem_private_key(pem.encode(), password=None)
                            if private_key else x509.load_pem_x509_certificate(pem.encode()))
                return material.public_key().public_bytes(
                    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode()
            except ValueError:
                return ""

        monkeypatch.setattr(helper, "_openssl_public_key", public_key_in_memory)
        settings = {"fqdn": "appliance.example.test", "resolver_mode": "external",
                    "resolver_servers": ["192.0.2.1"], "local_dns_enabled": False,
                    "management_interface": "eth0", "management_ip": "" if method == "dhcp" else "192.0.2.20",
                    "management_https_enabled": True, "management_https_cert_path": str(certificate_path),
                    "management_https_key_path": str(key_path)}
        settings_path = tmp_path / "settings.json"
        settings_path.write_text(json.dumps(settings))
        network = tmp_path / "network.conf"
        network.write_text("[physical_interfaces]\ninterface=eth0\nrole=management\nadmin_state=up\n"
                           f"ipv4_method={method}\nip_cidr={'192.0.2.20/24' if method == 'static' else ''}\n")
        site = tmp_path / "management.conf"
        site.write_text(helper._management_nginx_config(
            settings, certificate_path, key_path, listen_addresses=["127.0.0.1", "::1", "192.0.2.10"],
        ))
        monkeypatch.setattr(helper, "NGINX_MANAGEMENT_SITE_PATH", site)
        # Keep the real staged Settings/CA material and native listener parser.
        # Other unit validators have their own tests and need no host commands here.
        monkeypatch.setattr(helper, "_network_config_errors", lambda _path: [])
        monkeypatch.setattr(helper, "_validate_firewall_config", lambda _path: subprocess.CompletedProcess([], 0, "", ""))
        monkeypatch.setattr(helper, "_public_services_config_errors", lambda _path, **_options: [])
        monkeypatch.setattr(helper, "_ca_payload_errors", lambda _path: [])
        payload = {"network_config_path": str(network), "appliance_settings_config_path": str(settings_path),
                   "firewall_config_path": str(tmp_path / "firewall.nft"),
                   "public_services_config_path": str(tmp_path / "public.json"),
                   "ca_config_path": str(tmp_path / "ca.json")}
        return SimpleNamespace(helper=helper, payload=payload, settings=settings, settings_path=settings_path,
                               root_path=root_path, certificate_path=certificate_path,
                               candidate_pem=candidate_pem, site=site)

    return create


@pytest.mark.parametrize("method", ["static", "dhcp"])
def test_handoff_prevalidation_separates_candidate_leaf_from_old_scope(staged_case, method):
    """A valid staged candidate need not authenticate the preserved old certificate's IP.

    Args:
        staged_case: Factory for isolated public fixture state.
        method: Static candidate or DHCP candidate awaiting native acquisition.
    """
    case = staged_case(method)
    assert case.helper._management_handoff_validation_errors(case.payload) == []
    public = case.helper._management_handoff_public_certificate(case.payload, case.settings)
    case.certificate_path.write_text(case.candidate_pem)
    if method == "static":
        assert case.helper._management_handoff_candidate_ca(public, ["192.0.2.20"]) == case.root_path
    else:
        with pytest.raises(ValueError, match="does not authenticate candidate address 192.0.2.30"):
            case.helper._management_handoff_candidate_ca(public, ["192.0.2.30"])


def test_ordinary_staged_rotation_still_requires_retained_listener_coverage(staged_case):
    """Ordinary Settings validation retains its current-listener certificate guard.

    Args:
        staged_case: Factory for isolated public fixture state.
    """
    case = staged_case()
    errors = case.helper._appliance_settings_config_errors(
        case.settings_path, staged_ca_path=case.payload["ca_config_path"],
    )
    assert any("does not authenticate retained address 192.0.2.10" in error for error in errors)


@pytest.mark.parametrize("invalid,reason", [
    ("certificate", "must contain a PEM certificate block"),
    ("key_mismatch", "private key does not match"),
    ("foreign_path", "does not contain the configured management HTTPS certificate and key"),
])
def test_handoff_prevalidation_still_refuses_invalid_staged_material(staged_case, invalid, reason):
    """Candidate context must preserve PEM, key-pair and configured-path admission.

    Args:
        staged_case: Factory for isolated public fixture state.
        invalid: Invalid certificate material or ownership selection.
        reason: Expected fixed public refusal text.
    """
    case = staged_case(invalid=invalid)
    assert any(reason in error for error in case.helper._management_handoff_validation_errors(case.payload))


def test_handoff_prevalidation_still_refuses_malformed_previous_listener_scope(staged_case):
    """Keep native old-listener parsing fail-closed even when its leaf is separate.

    Args:
        staged_case: Factory for isolated public fixture state.
    """
    case = staged_case()
    case.site.write_text(case.site.read_text().replace("192.0.2.10:", "invalid:"))
    errors = case.helper._management_handoff_validation_errors(case.payload)
    assert any("existing management listener" in error for error in errors)
