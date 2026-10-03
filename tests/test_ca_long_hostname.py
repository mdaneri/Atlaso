"""Exercise the CA reconciliation used by first-boot HTTPS for long FQDNs."""

import importlib.machinery
import importlib.util
import json
from pathlib import Path, PurePosixPath

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID
from sqlalchemy import select

from atlaso.app.database import SessionLocal
from atlaso.app.models import ApplianceSettings, CaCertificate, CaSettings
from atlaso.app.security import Identity
from atlaso.app.services.ca import render_ca_apply_payload
from atlaso.app.ui import (
    ca_managed_certificate_paths,
    download_ca_certificate,
    download_ca_certificate_chain,
    download_ca_certificate_private_key,
    ensure_ca_state,
)


@pytest.mark.parametrize("fqdn", [
    "atlaso-pr-900-time-source-guard-verified-appliance.atlaso.internal",
    ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 61)),
])
def test_first_boot_ca_reconciliation_retains_long_appliance_identity(client, tmp_path, fqdn):
    """Issue, reconcile, and rotate the management leaf without shortening SANs.

    Args:
        client: Seeded application fixture with an isolated database.
        tmp_path: Isolated local filesystem for public certificate write checks.
        fqdn: Full DNS identity, including the maximum supported length.
    """
    with SessionLocal() as db:
        appliance = db.execute(select(ApplianceSettings)).scalar_one()
        settings = db.execute(select(CaSettings)).scalar_one()
        appliance.fqdn = fqdn
        settings.enabled = True
        db.commit()

        assert ensure_ca_state(db) == []
        leaf = db.execute(
            select(CaCertificate).where(CaCertificate.managed_owner == "appliance:https")
        ).scalar_one()
        issued = x509.load_pem_x509_certificate(leaf.certificate_pem.encode("ascii"))
        assert leaf.common_name == fqdn
        assert leaf.subject_alt_names == fqdn
        assert issued.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName) == [fqdn]
        assert len(issued.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value) <= 64
        assert leaf.private_key_encrypted.startswith("fernet:v1:")
        paths = ca_managed_certificate_paths(db, "appliance:https")
        assert all(paths)
        assert all(len(PurePosixPath(path).name.encode("ascii")) <= 255 for path in paths)
        payload = json.loads(render_ca_apply_payload(settings, [leaf], include_private_keys=False))
        deployed = payload["certificates"][0]
        assert tuple(deployed[field] for field in ("cert_path", "key_path", "chain_path")) == paths

        identity = Identity(username="admin", role="admin", scopes=set())
        for endpoint, path in zip(
            (download_ca_certificate, download_ca_certificate_private_key, download_ca_certificate_chain),
            paths, strict=True,
        ):
            response = endpoint(leaf.id, identity, db)
            assert response.headers["Content-Disposition"] == (
                f'attachment; filename="{PurePosixPath(path).name}"'
            )

        # Exercise the production deployment writer with public material only.
        helper_path = Path(__file__).resolve().parents[1] / "scripts/appliance/atlaso-helper"
        loader = importlib.machinery.SourceFileLoader("ca_filename_helper", str(helper_path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        assert spec is not None
        helper = importlib.util.module_from_spec(spec)
        loader.exec_module(helper)
        for field, material in (("cert_path", "certificate_pem"), ("chain_path", "chain_pem")):
            destination = tmp_path / PurePosixPath(deployed[field]).name
            helper._write_secret_file(destination, deployed[material], 0o644)
            assert destination.read_text(encoding="utf-8") == deployed[material]
        fingerprint = leaf.fingerprint
        root_fingerprint = settings.root_fingerprint

        assert ensure_ca_state(db) == []
        assert leaf.fingerprint == fingerprint
        assert ca_managed_certificate_paths(db, "appliance:https") == paths

        replacement = fqdn[:-1] + ("e" if fqdn[-1] != "e" else "f")
        appliance.fqdn = replacement
        db.commit()
        assert ensure_ca_state(db) == []
        assert leaf.fingerprint != fingerprint
        assert settings.root_fingerprint == root_fingerprint
        assert leaf.common_name == replacement
        rotated = x509.load_pem_x509_certificate(leaf.certificate_pem.encode("ascii"))
        assert rotated.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName) == [replacement]
