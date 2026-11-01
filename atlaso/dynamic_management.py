"""Publish applied dedicated DHCP/IPv4LL management changes through the guarded front door."""

from __future__ import annotations

import hashlib
import json
import os
import re
import runpy
import ssl
import stat
import subprocess
import tempfile
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_interface
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from atlaso.app.audit import record_audit
from atlaso.app.database import SessionLocal
from atlaso.app.models import (
    ApplianceSettings,
    CaCertificate,
    CaProfile,
    CaSettings,
    Job,
    PhysicalInterface,
)
from atlaso.app.secrets import decrypt_secret
from atlaso.app.services.ca import (
    ManagedCertificateSpec,
    ensure_aware,
    ensure_managed_certificate_rows,
    issue_certificate,
    render_ca_apply_payload,
)
from atlaso.app.services.dynamic_management import (
    PUBLICATION_PATH,
    applied_snapshots,
    native_management_addresses,
    read_publication,
    snapshot_digest,
)
from atlaso.app.services.management_bindings import (
    _network_rows,
    applied_management_bindings,
)
from atlaso.app.services.network_objects import acquire_network_objects_write_lock

HELPER_PATH = Path("/opt/atlaso/bin/atlaso-helper")
BOOTSTRAP_PATH = Path("/opt/atlaso/bin/atlaso-bootstrap-https")
BOOTSTRAP_NETWORK_PATH = Path("/etc/systemd/network/00-atlaso-mgmt.network")


def installed_pair_matches(leaf: CaCertificate, certificate: Path, private_key: Path) -> bool:
    """Require the installed pair and encrypted candidate to describe the same leaf.

    Args:
        leaf: Existing management-only encrypted certificate row.
        certificate: Applied managed public certificate path.
        private_key: Applied managed private-key path; its contents never leave this process.
    """
    try:
        public = x509.load_pem_x509_certificate(certificate.read_bytes())
        private = serialization.load_pem_private_key(private_key.read_bytes(), password=None)
        return (public.fingerprint(hashes.SHA256()).hex() == leaf.fingerprint
                and public.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                == private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm):
        return False


def write_publication(value: dict[str, Any]) -> None:
    """Atomically replace the root-owned public receipt; never include private material.

    Args:
        value: Bounded public native identity and publication evidence.
    """
    parent = PUBLICATION_PATH.parent
    parent.mkdir(mode=0o755, exist_ok=True)
    metadata = parent.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise ValueError("dynamic management publication directory is unsafe")
    if PUBLICATION_PATH.is_symlink():
        raise ValueError("dynamic management publication is a symlink")
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            json.dump(value, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o644)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.replace(temporary, PUBLICATION_PATH)
        descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def bootstrap_row(db: Session, observation: dict[str, Any]) -> dict[str, str]:
    """Read the root-owned image/first-boot network binding before the first Apply.

    Args:
        db: Read-only transaction used solely to confirm the MAC inventory identity.
        observation: Complete native interface evidence.
    """
    metadata = BOOTSTRAP_NETWORK_PATH.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022 or metadata.st_size > 16384:
        return {}
    text = BOOTSTRAP_NETWORK_PATH.read_text()
    names = re.findall(r"(?m)^Name=([A-Za-z0-9_.-]{1,15})$", text)
    if len(names) != 1 or not re.search(r"(?m)^DHCP=ipv4$", text):
        return {}
    interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == names[0]))
    if interface is None:
        return {}
    static_ipv6 = [str(ip_interface(value)) for value in re.findall(r"(?m)^Address=([^\s]+)$", text)
                   if ip_interface(value).version == 6]
    if len(static_ipv6) > 1:
        return {}
    return {"name": names[0], "mac": interface.mac_address.lower(), "role": "management", "mode": "access",
            "admin_state": "up", "ipv4_method": "dhcp",
            "ipv4_link_local_fallback_enabled": "false" if "# Atlaso IPv4LL fallback enabled=false" in text else "true",
            "ipv6_enabled": "false" if "IPv6AcceptRA=no" in text and re.search(r"(?m)^LinkLocalAddressing=(no|ipv4)$", text) else "true",
            "ipv6_cidr": static_ipv6[0] if static_ipv6 else ""}


def reconcile(helper: dict[str, Any], bootstrap: dict[str, Any]) -> None:
    """Refresh only native dynamic management state and its existing TLS leaf.

    Args:
        helper: Canonical installed privileged helper functions.
        bootstrap: Canonical installed HTTPS bootstrap/recovery helpers.
    """
    with helper["_network_transaction_lock"]():
        if helper["_network_transaction_state"]() or helper["MANAGEMENT_HANDOFF_STATE_PATH"].exists():
            return
        if not helper["_console_bootstrap_is_idle"]():
            return
        # An interrupted front-door publication must recover before any newer one.
        if helper["_recover_management_front_door"](quiet=True):
            raise ValueError("previous management publication requires recovery")
        observation = helper["_network_address_observation"]()
        with SessionLocal() as db:
            acquire_network_objects_write_lock(db)
            if db.scalar(select(Job.id).where(Job.type == "appliance-apply", Job.status.in_(["pending", "running"]))):
                return
            baselines = applied_snapshots(db)
            network = baselines.get("network")
            rows = _network_rows(network["config_preview"]) if network else [bootstrap_row(db, observation)]
            candidates = [row for row in rows if row.get("role") == "management" and row.get("ipv4_method") == "dhcp"]
            if len(candidates) != 1:
                write_publication({"phase": "withdrawn"})
                return
            row = candidates[0]
            if network:
                row = {**row, "name": network.get("physical_interface_aliases", {}).get(row["name"], row["name"])}
            native = native_management_addresses(row, observation)
            if native["ipv4_state"] == "unknown":
                # Observation failure cannot authorize listener retirement. The
                # public receipt ages out while the last working runtime stays.
                return
            identity = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == row["name"]))
            if identity is None or identity.mac_address.lower() != row.get("mac", "").lower():
                raise ValueError("applied management inventory identity changed")
            settings_baseline = baselines.get("appliance_settings")
            if settings_baseline:
                settings = json.loads(settings_baseline["config_preview"])
            else:
                # Freeze the first-boot published CA identity, never a leaf row
                # that desired-state reconciliation may already have changed.
                appliance = db.scalar(select(ApplianceSettings))
                ca_baseline = json.loads(str((baselines.get("ca") or {}).get("config_preview") or "{}"))
                published_leaves = [item for item in ca_baseline.get("certificates", []) if item.get("managed_owner") == "appliance:https"]
                if (appliance is None or len(published_leaves) != 1
                        or bootstrap["read_regular_text"](bootstrap["MARKER_PATH"], maximum_size=256) != bootstrap["COMPLETION_MARKER_TEXT"]):
                    return
                published_leaf = published_leaves[0]
                settings = {"fqdn": published_leaf["common_name"], "management_https_enabled": True,
                            "management_https_cert_path": published_leaf["cert_path"], "management_https_key_path": published_leaf["key_path"],
                            "web_terminal_enabled": False, "web_terminal_addresses": [], "management_upstream_host": "127.0.0.1",
                            "management_upstream_port": 8000, "management_public_http_port": 80, "management_public_https_port": 443}
            settings_interface = settings.get("management_interface")
            if network:
                settings_interface = network.get("physical_interface_aliases", {}).get(settings_interface, settings_interface)
            if settings_interface not in (None, "", row["name"]):
                return
            settings = {**settings, "management_interface": row["name"]}
            published = {"interface": row["name"], "mac": row["mac"], **native,
                         "network_digest": snapshot_digest(network), "settings_digest": snapshot_digest(settings_baseline),
                         "observed_at": datetime.now(timezone.utc).isoformat(), "phase": "pending"}
            old = applied_management_bindings(db) or []
            retained = [item["address"] for item in old if item["interface"] != row["name"]]
            addresses = sorted(set(native["addresses"] + retained + ["127.0.0.1", "::1"]))
            dynamic_old = {item["address"] for item in old if item["interface"] == row["name"]}
            dynamic_old.add(str(settings.get("management_ip") or ""))
            terminal = [value for value in settings.get("web_terminal_addresses", []) if value not in dynamic_old]
            target_sans = {value for value in addresses + terminal if not ip_address(value).is_loopback}
            public_site = helper["NGINX_PUBLIC_SERVICES_SITE_PATH"]
            public_tls = helper["_management_handoff_candidate_public_tls_addresses"](
                public_site, int(settings.get("management_public_https_port") or 443)) if public_site.is_file() else set()
            https_addresses = [address for address in addresses if address not in public_tls]
            previous = read_publication(db)
            site_path = helper["NGINX_MANAGEMENT_SITE_PATH"]
            current_leaf = db.scalar(select(CaCertificate).where(CaCertificate.managed_owner == "appliance:https"))
            if (previous and previous.get("addresses") == native["addresses"]
                    and previous.get("apipa_addresses") == native["apipa_addresses"]
                    and (not settings.get("management_https_enabled") or current_leaf is not None
                         and current_leaf.enabled and current_leaf.status != "revoked" and current_leaf.expires_at is not None
                         and ensure_aware(current_leaf.expires_at) > datetime.now(timezone.utc) + timedelta(seconds=90)
                         and set((current_leaf.ip_addresses or "").splitlines()) == target_sans
                         and current_leaf.fingerprint == previous.get("leaf_fingerprint")
                         and installed_pair_matches(current_leaf,
                             helper["_ca_managed_path"](settings["management_https_cert_path"], "management_https_cert_path"),
                             helper["_ca_managed_path"](settings["management_https_key_path"], "management_https_key_path")))
                    and site_path.is_file()
                    and previous.get("site_digest") == hashlib.sha256(site_path.read_bytes()).hexdigest()
                    and helper["_run"](["systemctl", "is-active", "--quiet", "nginx.service"], timeout=5).returncode == 0):
                if settings.get("management_https_enabled"):
                    served = ssl.get_server_certificate((native["addresses"][0], int(settings.get("management_public_https_port") or 443)), timeout=3)
                    if hashlib.sha256(ssl.PEM_cert_to_DER_cert(served)).hexdigest() != previous.get("leaf_fingerprint"):
                        raise ValueError("active management TLS identity differs from its publication")
                # The same verified runtime remains published. Native state is
                # fresh, while pending desired CA/settings edits stay pending.
                previous["observed_at"] = datetime.now(timezone.utc).isoformat()
                write_publication(previous)
                return
            if not native["addresses"]:
                write_publication({**published, "phase": "withdrawn"})
                # Remove only the owned dynamic listener. Other management paths
                # remain represented by the applied binding inventory.
                kept = sorted(set(retained + ["127.0.0.1", "::1"]))
                site = helper["_management_nginx_config"](settings, listen_addresses=kept,
                            http_listen_addresses=kept, https_listen_addresses=[address for address in kept if address not in public_tls],
                            cert_path=Path(settings["management_https_cert_path"]) if settings.get("management_https_enabled") else None,
                            key_path=Path(settings["management_https_key_path"]) if settings.get("management_https_enabled") else None)
                if helper["_install_nginx_site"](helper["NGINX_MANAGEMENT_SITE_PATH"], site):
                    raise ValueError("obsolete dynamic management listener could not be withdrawn")
                identity.host_ip_cidr = None
                identity.host_ip_cidrs = []
                db.commit()
                if previous:
                    record_audit(db, actor="system:networkd", action="withdraw_dynamic_management", resource_type="network",
                                 resource_id=row["name"], detail=f"{row['name']}: {native['ipv4_state']}; dynamic setup listener withdrawn.")
                return
            settings["management_ip"] = native["addresses"][0]
            leaf = db.scalar(select(CaCertificate).where(CaCertificate.managed_owner == "appliance:https"))
            ca = db.scalar(select(CaSettings))
            profiles = list(db.scalars(select(CaProfile)))
            material_writer: Callable[[], None] | None = None
            if settings.get("management_https_enabled"):
                if ca is None or not ca.enabled or leaf is None or not leaf.enabled or leaf.status == "revoked":
                    raise ValueError("applied management CA or leaf is unavailable or revoked")
                cert_destination = helper["_ca_managed_path"](settings["management_https_cert_path"], "management_https_cert_path")
                key_destination = helper["_ca_managed_path"](settings["management_https_key_path"], "management_https_key_path")
                if not bootstrap["recovery_root_matches_baseline"](db):
                    raise ValueError("pending CA root changes require explicit Apply")
                # Preserve currently configured listener SANs for rollback. On
                # the next pass only the new sockets remain, so old SANs retire.
                old_sockets = {str(ip_address(match[1] or match[2])) for match in re.finditer(
                    r"(?m)^\s*listen (?:([0-9.]+)|\[([0-9a-fA-F:]+)\]):\d+", site_path.read_text())
                               if not ip_address(match[1] or match[2]).is_loopback} if site_path.is_file() else set()
                sans = sorted(target_sans | old_sockets)
                profile = next((profile for profile in profiles if profile.id == leaf.profile_id), None)
                if profile is None or not profile.enabled:
                    raise ValueError("applied management issuance profile is unavailable")
                spec = ManagedCertificateSpec(owner="appliance:https", common_name=settings["fqdn"],
                            dns_names=[settings["fqdn"]], ip_addresses=sans, profile_name=profile.name,
                            description=leaf.description or "Managed Atlaso appliance HTTPS certificate.", cert_path=settings["management_https_cert_path"],
                            key_path=settings["management_https_key_path"], chain_path=leaf.chain_path)
                ensure_managed_certificate_rows(db, settings=ca, profiles=profiles, specs=[spec])
                issue_certificate(ca, profiles, leaf)
                if leaf.expires_at is None or ensure_aware(leaf.expires_at) <= datetime.now(timezone.utc) + timedelta(seconds=90):
                    raise ValueError("management TLS leaf has insufficient remaining validity")
                # Commit the encrypted candidate first. An interrupted write can
                # always republish this exact pair; no private bytes enter receipts.
                candidate = leaf.fingerprint
                db.commit()
                acquire_network_objects_write_lock(db)
                db.refresh(leaf)
                if (db.scalar(select(Job.id).where(Job.type == "appliance-apply", Job.status.in_(["pending", "running"])))
                        or leaf.fingerprint != candidate or snapshot_digest(applied_snapshots(db).get("network")) != published["network_digest"]
                        or snapshot_digest(applied_snapshots(db).get("appliance_settings")) != published["settings_digest"]
                        or not bootstrap["recovery_root_matches_baseline"](db)):
                    raise ValueError("management publication inputs changed before activation")
                def install_pair() -> None:
                    """Replace only the management pair after its rollback snapshot is durable."""
                    bootstrap["write_secret_text_atomic"](key_destination, decrypt_secret(leaf.private_key_encrypted))
                    bootstrap["write_text_atomic"](cert_destination, leaf.chain_pem, mode=0o644)

                material_writer = install_pair
                published["leaf_fingerprint"] = candidate
            # Native re-read excludes carrier/address changes during issuance.
            if native_management_addresses(row, helper["_network_address_observation"]()) != native:
                raise ValueError("native management address changed during publication")
            result, _ = helper["_configure_atlaso_management_https"](
                settings, listen_addresses=addresses, http_listen_addresses=addresses, https_listen_addresses=https_addresses,
                material_writer=material_writer)
            if result:
                raise ValueError("dynamic management listener failed readiness; prior front door restored")
            if settings.get("management_https_enabled"):
                assert ca is not None and leaf is not None
                served = ssl.get_server_certificate((settings["management_ip"], int(settings.get("management_public_https_port") or 443)), timeout=3)
                if hashlib.sha256(ssl.PEM_cert_to_DER_cert(served)).hexdigest() != published["leaf_fingerprint"]:
                    raise ValueError("published TLS leaf is not active on the dynamic listener")
                public_payload = render_ca_apply_payload(ca, [leaf], include_private_keys=False, profiles=profiles)
                bootstrap["record_ca_publication_baseline"](db, public_payload, [], management_only=True)
            # Refresh only this proven observation, never interface desired state.
            identity.host_ip_cidr = next((address["cidr"] for link in observation["links"] if link["name"] == row["name"]
                                         for address in link["addresses"] if address["address"] in native["addresses"]
                                         and (address.get("source") == "DHCPv4" or address.get("dhcp4_lease") is True)), None)
            identity.host_ip_cidrs = [identity.host_ip_cidr] if identity.host_ip_cidr else []
            db.commit()
            record_audit(db, actor="system:networkd", action="publish_dynamic_management", resource_type="network",
                         resource_id=row["name"], detail=f"{row['name']}: {native['ipv4_state']}; verified management listeners {', '.join(native['addresses'])}.")
            port = settings.get("management_public_https_port", 443) if settings.get("management_https_enabled") else settings.get("management_public_http_port", 80)
            scheme = "https" if settings.get("management_https_enabled") else "http"
            published.update(phase="ready", observed_at=datetime.now(timezone.utc).isoformat(),
                             site_digest=hashlib.sha256(site_path.read_bytes()).hexdigest(),
                             urls=[f"{scheme}://{'[' + address + ']' if ':' in address else address}:{port}/ui/management/"
                                   for address in native["addresses"]])
            write_publication(published)


def main() -> int:
    """Run one bounded reconciliation; the timer owns retries."""
    try:
        reconcile(runpy.run_path(str(HELPER_PATH)), runpy.run_path(str(BOOTSTRAP_PATH)))
        return 0
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, SQLAlchemyError, subprocess.SubprocessError):
        # Leave an actionable unit failure without exposing DB URLs or private material.
        print("Dynamic management publication deferred; inspect applied identity, native carrier/address and CA readiness.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
