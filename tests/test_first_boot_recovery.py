"""Exercise interrupted VMware initialization without trusting completion markers alone."""

import configparser
import runpy
from graphlib import TopologicalSorter
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from atlaso.app.models import CaSettings
from atlaso.app.secrets import encrypt_secret
from tests.test_ca import development_root_material


@pytest.mark.parametrize("state", ["valid", "missing-row", "wrong-certificate", "wrong-key", "wrong-proof"])
def test_consumed_ca_requires_matching_encrypted_material(tmp_path, monkeypatch, state):
    """A proof file cannot authorize recovery with absent or mismatched CA state.

    Args:
        tmp_path: Isolated proof directory.
        monkeypatch: Dependency replacement fixture.
        state: Stored-material failure to reproduce.
    """
    namespace = runpy.run_path("scripts/appliance/atlaso-bootstrap-https")
    verify = namespace["verify_imported_development_root"]
    engine = create_engine("sqlite://")
    CaSettings.__table__.create(engine)
    sessions = sessionmaker(engine)
    certificate, key = development_root_material()
    other_certificate, other_key = development_root_material()
    fingerprint = x509.load_pem_x509_certificate(certificate.encode()).fingerprint(hashes.SHA256()).hex().upper()
    proof = tmp_path / "imported"
    proof.write_text("0" * 64 if state == "wrong-proof" else fingerprint)
    monkeypatch.setitem(verify.__globals__, "SessionLocal", sessions)
    monkeypatch.setitem(verify.__globals__, "DEVELOPMENT_ROOT_CA_IMPORTED_MARKER_PATH", proof)
    try:
        with sessions.begin() as db:
            if state != "missing-row":
                db.add(CaSettings(
                    root_certificate_pem=other_certificate if state == "wrong-certificate" else certificate,
                    root_private_key_encrypted=encrypt_secret(other_key if state == "wrong-key" else key),
                ))
        assert verify(certificate) is (state == "valid")
        with sessions() as db:
            assert db.query(CaSettings).count() == (0 if state == "missing-row" else 1)
    finally:
        engine.dispose()


def test_vmware_firewall_and_activation_have_acyclic_boot_order():
    """Verify the actual OVF units preserve firewall-before-network ordering."""
    graph = {"network-pre.target": {"atlaso-firewall.service"},
             "systemd-networkd.service": {"network-pre.target"}}
    for name in ("atlaso-vmware-ovf-prepare.service", "atlaso-vmware-ovf-customize.service"):
        unit = configparser.ConfigParser(interpolation=None, strict=False)
        unit.read(Path("image/vmware-workstation/systemd") / name)
        graph.setdefault(name, set()).update(unit["Unit"]["After"].split())
        for successor in unit["Unit"]["Before"].split():
            graph.setdefault(successor, set()).add(name)
    ordered = list(TopologicalSorter(graph).static_order())
    assert ordered.index("atlaso-vmware-ovf-prepare.service") < ordered.index("atlaso-firewall.service")
    assert ordered.index("atlaso-firewall.service") < ordered.index("systemd-networkd.service")
    assert ordered.index("systemd-networkd.service") < ordered.index("atlaso-vmware-ovf-customize.service")
