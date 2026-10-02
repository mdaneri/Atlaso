"""Exercise the CA reconciliation used by first-boot HTTPS for long FQDNs."""

from cryptography import x509
from cryptography.x509.oid import NameOID
from sqlalchemy import select

from atlaso.app.database import SessionLocal
from atlaso.app.models import ApplianceSettings, CaCertificate, CaSettings
from atlaso.app.ui import ca_managed_certificate_paths, ensure_ca_state


def test_first_boot_ca_reconciliation_retains_long_appliance_identity(client):
    """Issue, reconcile, and rotate the management leaf without shortening SANs.

    Args:
        client: Seeded application fixture with an isolated database.
    """
    fqdn = "atlaso-pr-900-time-source-guard-verified-appliance.atlaso.internal"
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
        fingerprint = leaf.fingerprint
        root_fingerprint = settings.root_fingerprint

        assert ensure_ca_state(db) == []
        assert leaf.fingerprint == fingerprint
        assert ca_managed_certificate_paths(db, "appliance:https") == paths

        replacement = fqdn.replace("900", "901")
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
