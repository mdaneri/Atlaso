"""Test nts restoration behavior."""

import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sqlalchemy import select

from atlaso.app.models import AuditEvent, CaCertificate, CaSettings, NtpSettings, Setting
from atlaso.app.seed import NTP_NTS_RESTORATION_SETTING_KEY, seed_initial_data
from atlaso.app.secrets import decrypt_secret, encrypt_secret
from atlaso.app.services.ntp import dump_ntp_upstream_sources, ntp_upstream_sources
from atlaso.app.services.settings_archive import export_settings_archive, restore_settings_archive


def _issued_certificate_material(
    common_name: str,
    *,
    issuer_certificate_pem: str = "",
    issuer_private_key_encrypted: str = "",
) -> tuple[str, str]:
    """Return issued certificate material, self-signing when no issuer is supplied."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer_name = subject
    signing_key = key
    if issuer_certificate_pem and issuer_private_key_encrypted:
        issuer_name = x509.load_pem_x509_certificate(
            issuer_certificate_pem.encode("ascii")
        ).subject
        signing_key = serialization.load_pem_private_key(
            decrypt_secret(issuer_private_key_encrypted).encode("ascii"),
            password=None,
        )
    now = datetime.now(timezone.utc)
    certificate_pem = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(signing_key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode("ascii")
    )
    private_key_encrypted = encrypt_secret(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii")
    )
    return certificate_pem, private_key_encrypted


def test_nts_restoration_reenables_only_canonical_defaults_once(client):
    """Verify that nts restoration reenables only canonical defaults once.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import atlaso.app.database as database

    with database.SessionLocal() as db:
        settings = db.execute(select(NtpSettings)).scalar_one()
        marker = db.execute(
            select(Setting).where(Setting.key == NTP_NTS_RESTORATION_SETTING_KEY)
        ).scalar_one()
        db.delete(marker)
        settings.upstream_sources_json = dump_ntp_upstream_sources(
            [
                {
                    "id": "cloudflare-ntp",
                    "source": "time.cloudflare.com",
                    "enabled": False,
                    "use_nts": False,
                    "description": "Cloudflare public NTP",
                },
                {
                    "id": "netnod-ntp",
                    "source": "nts.netnod.se",
                    "enabled": False,
                    "use_nts": False,
                    "description": "Netnod public NTP",
                },
                {
                    "id": "ptb-germany-ntp",
                    "source": "ptbtime1.ptb.de",
                    "enabled": False,
                    "use_nts": False,
                    "description": "PTB Germany public NTP",
                },
                {
                    "id": "custom-cloudflare",
                    "source": "time.cloudflare.com",
                    "enabled": False,
                    "use_nts": False,
                    "description": "Operator-owned duplicate",
                },
                {
                    "id": "custom-source",
                    "source": "time.example.test",
                    "enabled": True,
                    "use_nts": False,
                    "description": "Operator-owned source",
                },
            ]
        )
        settings.upstream_servers = "time.example.test"
        db.add(settings)
        db.commit()

        seed_initial_data(db, include_examples=False)

        restored = ntp_upstream_sources(settings)
        assert restored[0] == {
            "id": "cloudflare-nts",
            "source": "time.cloudflare.com",
            "enabled": True,
            "use_nts": True,
            "description": "Cloudflare public NTS",
        }
        assert restored[1] == {
            "id": "netnod-nts",
            "source": "nts.netnod.se",
            "enabled": True,
            "use_nts": True,
            "description": "Netnod public NTS",
        }
        assert restored[2] == {
            "id": "ptb-germany-nts",
            "source": "ptbtime1.ptb.de",
            "enabled": False,
            "use_nts": True,
            "description": "PTB Germany public NTS",
        }
        assert restored[3]["id"] == "custom-cloudflare"
        assert restored[3]["enabled"] is False
        assert restored[3]["use_nts"] is False
        assert restored[3]["description"] == "Operator-owned duplicate"
        assert restored[4]["id"] == "custom-source"
        assert restored[4]["use_nts"] is False
        assert settings.upstream_servers.splitlines() == [
            "time.cloudflare.com",
            "nts.netnod.se",
            "time.example.test",
        ]
        assert db.execute(
            select(Setting).where(Setting.key == NTP_NTS_RESTORATION_SETTING_KEY)
        ).scalar_one().value == "complete"

        audits = db.execute(
            select(AuditEvent).where(AuditEvent.action == "restore_ntp_nts_defaults")
        ).scalars().all()
        assert len(audits) == 1
        assert audits[0].actor == "system"
        assert audits[0].detail == "Reconciled canonical NTS defaults."

        seed_initial_data(db, include_examples=False)
        audits = db.execute(
            select(AuditEvent).where(AuditEvent.action == "restore_ntp_nts_defaults")
        ).scalars().all()
        assert len(audits) == 1


def test_fresh_nts_defaults_are_marked_without_restoration_audit(client):
    """Verify that fresh nts defaults are marked without restoration audit.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import atlaso.app.database as database

    with database.SessionLocal() as db:
        assert db.execute(
            select(Setting).where(Setting.key == NTP_NTS_RESTORATION_SETTING_KEY)
        ).scalar_one().value == "complete"
        assert db.execute(
            select(AuditEvent).where(AuditEvent.action == "restore_ntp_nts_defaults")
        ).scalar_one_or_none() is None


def test_settings_archive_round_trips_enabled_nts_and_drops_disabled_server_certificate(client):
    """Verify that settings archive round trips enabled nts and drops disabled server certificate.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import atlaso.app.database as database

    with database.SessionLocal() as db:
        root_certificate_pem, root_private_key_encrypted = _issued_certificate_material(
            "Atlaso Internal Root CA"
        )
        certificate_pem, private_key_encrypted = _issued_certificate_material(
            "ntp.atlaso.internal",
            issuer_certificate_pem=root_certificate_pem,
            issuer_private_key_encrypted=root_private_key_encrypted,
        )
        ca_settings = db.execute(select(CaSettings)).scalar_one()
        ca_settings.enabled = True
        ca_settings.root_certificate_pem = root_certificate_pem
        ca_settings.root_private_key_encrypted = root_private_key_encrypted
        settings = db.execute(select(NtpSettings)).scalar_one()
        settings.nts_server_enabled = True
        settings.nts_server_cert_path = "/etc/atlaso/ntp/certs/ntp.atlaso.internal-chain.pem"
        settings.nts_server_key_path = "/etc/atlaso/ntp/certs/ntp.atlaso.internal.key"
        settings.upstream_sources_json = dump_ntp_upstream_sources(
            [
                {
                    "id": "cloudflare-nts",
                    "source": "time.cloudflare.com",
                    "enabled": True,
                    "use_nts": True,
                    "description": "Cloudflare public NTS",
                }
            ]
        )
        db.add(
            CaCertificate(
                common_name="ntp.atlaso.internal",
                managed_owner="ntp:nts",
                status="issued",
                certificate_pem=certificate_pem,
                private_key_encrypted=private_key_encrypted,
                cert_path="/etc/atlaso/ntp/certs/ntp.atlaso.internal.crt",
                key_path=settings.nts_server_key_path,
                chain_path=settings.nts_server_cert_path,
            )
        )
        db.add(settings)
        db.commit()

        enabled_archive = export_settings_archive(db, actor="admin")
        assert enabled_archive["data"]["ntp_settings"][0]["nts_server_enabled"] is True
        assert enabled_archive["data"]["ntp_settings"][0]["upstream_sources_json"] == settings.upstream_sources_json
        assert [row["managed_owner"] for row in enabled_archive["data"]["ca_certificates"]].count("ntp:nts") == 1
        assert [
            row["value"]
            for row in enabled_archive["data"]["settings"]
            if row["key"] == NTP_NTS_RESTORATION_SETTING_KEY
        ] == ["complete"]

        restore_settings_archive(db, enabled_archive)
        restored = db.execute(select(NtpSettings)).scalar_one()
        assert restored.nts_server_enabled is True
        assert ntp_upstream_sources(restored)[0]["use_nts"] is True
        assert db.execute(
            select(CaCertificate).where(CaCertificate.managed_owner == "ntp:nts")
        ).scalar_one().chain_path == restored.nts_server_cert_path

        disabled_archive = deepcopy(enabled_archive)
        disabled_archive["data"]["ntp_settings"][0]["nts_server_enabled"] = False
        disabled_archive["data"]["ntp_settings"][0]["nts_server_cert_path"] = ""
        disabled_archive["data"]["ntp_settings"][0]["nts_server_key_path"] = ""
        disabled_sources = json.loads(disabled_archive["data"]["ntp_settings"][0]["upstream_sources_json"])
        disabled_sources[0]["enabled"] = False
        disabled_archive["data"]["ntp_settings"][0]["upstream_sources_json"] = dump_ntp_upstream_sources(disabled_sources)
        disabled_archive["data"]["ntp_settings"][0]["upstream_servers"] = ""
        counts = restore_settings_archive(db, disabled_archive)
        seed_initial_data(db, include_examples=False)
        disabled = db.execute(select(NtpSettings)).scalar_one()
        assert disabled.nts_server_enabled is False
        assert ntp_upstream_sources(disabled)[0]["use_nts"] is True
        assert ntp_upstream_sources(disabled)[0]["enabled"] is False
        assert db.execute(
            select(Setting).where(Setting.key == NTP_NTS_RESTORATION_SETTING_KEY)
        ).scalar_one().value == "complete"
        assert db.execute(
            select(CaCertificate).where(CaCertificate.managed_owner == "ntp:nts")
        ).scalar_one_or_none() is None
        assert counts["ca_certificates"] == len(disabled_archive["data"]["ca_certificates"]) - 1

        disabled_export = export_settings_archive(db, actor="admin")
        assert all(row.get("managed_owner") != "ntp:nts" for row in disabled_export["data"]["ca_certificates"])
