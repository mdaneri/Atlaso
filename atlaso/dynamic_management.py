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
from typing import Any, NamedTuple

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
    CA_SERVER_PROFILE_NAME,
    ensure_aware,
    issue_certificate,
    join_multiline,
    render_ca_apply_payload,
)
from atlaso.app.services.dynamic_management import (
    PUBLICATION_PATH,
    applied_snapshots,
    native_management_addresses,
    read_observer_checkpoint,
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


class _PublicationPreparation(NamedTuple):
    """Bind slow preparation to the applied upstream and HTTPS policy."""

    upstream_host: str
    upstream_port: int
    https_enabled: bool


def _installed_certificate_pair(certificate: Path, private_key: Path) -> x509.Certificate | None:
    """Read a matching installed pair without exposing its private material.

    Args:
        certificate: Applied managed public certificate path.
        private_key: Applied managed private-key path; its contents never leave this process.
    """
    try:
        public = x509.load_pem_x509_certificate(certificate.read_bytes())
        private = serialization.load_pem_private_key(private_key.read_bytes(), password=None)
        if (public.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                == private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)):
            return public
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm):
        return None
    return None


def installed_pair_matches(leaf: CaCertificate, certificate: Path, private_key: Path) -> bool:
    """Require an installed pair to match the specified desired certificate row.

    Args:
        leaf: Existing management-only encrypted certificate row.
        certificate: Applied managed public certificate path.
        private_key: Applied managed private-key path; its contents never leave this process.
    """
    public = _installed_certificate_pair(certificate, private_key)
    return public is not None and public.fingerprint(hashes.SHA256()).hex() == leaf.fingerprint


def published_pair_matches(
    fingerprint: str, addresses: set[str], fqdn: str, certificate: Path, private_key: Path,
) -> bool:
    """Verify the unchanged applied publication independently of pending CA edits.

    Args:
        fingerprint: Leaf identity from the checked root-owned applied publication.
        addresses: Current applied non-loopback listener SANs.
        fqdn: Applied appliance identity, independent of pending Settings.
        certificate: Applied managed public certificate path.
        private_key: Applied managed private-key path; its contents never leave this process.
    """
    if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
        return False
    public = _installed_certificate_pair(certificate, private_key)
    if public is None or public.fingerprint(hashes.SHA256()).hex() != fingerprint:
        return False
    now = datetime.now(timezone.utc)
    if public.not_valid_before_utc > now or public.not_valid_after_utc <= now + timedelta(seconds=90):
        return False
    try:
        sans = public.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False
    return (set(map(str, sans.get_values_for_type(x509.IPAddress))) == addresses
            and {name.casefold() for name in sans.get_values_for_type(x509.DNSName)} == {fqdn.casefold()})


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


def _reconcile_once(
    helper: dict[str, Any], bootstrap: dict[str, Any], *, prepared: _PublicationPreparation | None,
) -> _PublicationPreparation | None:
    """Reconcile fresh inputs, requesting slow preparation outside the writer lock.

    Args:
        helper: Canonical installed privileged helper functions.
        bootstrap: Canonical installed HTTPS bootstrap/recovery helpers.
        prepared: Applied upstream and HTTPS policy whose slow prerequisites completed without locks.

    Returns:
        Prerequisites to prepare before retrying with fresh inputs, or no further work.
    """
    with helper["_network_transaction_lock"]():
        if helper["_network_transaction_state"]() or helper["MANAGEMENT_HANDOFF_STATE_PATH"].exists():
            return None
        if not helper["_console_bootstrap_is_idle"]():
            return None
        observation = helper["_network_address_observation"]()
        with SessionLocal() as db:
            acquire_network_objects_write_lock(db)
            if db.scalar(select(Job.id).where(Job.type == "appliance-apply", Job.status.in_(["pending", "running"]))):
                return None
            # Ordinary Settings Apply does not hold the native network lock.
            # Check its ownership under writer admission and retain that same
            # admission through recovery, so a live activation is never restored
            # as though it were interrupted and no new Apply can enter the gap.
            if helper["_recover_management_front_door"](quiet=True):
                raise ValueError("previous management publication requires recovery")
            baselines = applied_snapshots(db)
            network = baselines.get("network")
            rows = _network_rows(network["config_preview"]) if network else [bootstrap_row(db, observation)]
            candidates = [row for row in rows if row.get("role") == "management" and row.get("ipv4_method") == "dhcp"]
            if len(candidates) != 1:
                write_publication({"phase": "withdrawn"})
                return None
            row = candidates[0]
            if network:
                row = {**row, "name": network.get("physical_interface_aliases", {}).get(row["name"], row["name"])}
            native = native_management_addresses(row, observation)
            if native["ipv4_state"] == "unknown":
                # Observation failure cannot authorize listener retirement. The
                # public receipt ages out while the last working runtime stays.
                return None
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
                    return None
                published_leaf = published_leaves[0]
                settings = {"fqdn": published_leaf["common_name"], "management_https_enabled": True,
                            "management_https_cert_path": published_leaf["cert_path"], "management_https_key_path": published_leaf["key_path"],
                            "web_terminal_enabled": False, "web_terminal_addresses": [], "management_upstream_host": "127.0.0.1",
                            "management_upstream_port": 8000, "management_public_http_port": 80, "management_public_https_port": 443}
            settings_interface = settings.get("management_interface")
            if network:
                settings_interface = network.get("physical_interface_aliases", {}).get(settings_interface, settings_interface)
            if settings_interface not in (None, "", row["name"]):
                return None
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
            previous = read_observer_checkpoint(db, include_withdrawn=True)
            site_path = helper["NGINX_MANAGEMENT_SITE_PATH"]
            current_leaf = db.scalar(select(CaCertificate).where(CaCertificate.managed_owner == "appliance:https"))
            if not previous and native["addresses"] and settings.get("management_https_enabled") and site_path.is_file():
                # /run is volatile. Recover only the durable, acknowledged
                # applied identity, never the possibly pending desired row.
                ca_baseline = json.loads(str((baselines.get("ca") or {}).get("config_preview") or "{}"))
                applied_leaves = [item for item in ca_baseline.get("certificates", []) if item.get("managed_owner") == "appliance:https"]
                if (len(applied_leaves) == 1 and applied_leaves[0].get("common_name") == settings["fqdn"]
                        and applied_leaves[0].get("cert_path") == settings["management_https_cert_path"]
                        and applied_leaves[0].get("key_path") == settings["management_https_key_path"]):
                    expected_site = helper["_management_nginx_config"](
                        settings, listen_addresses=addresses, http_listen_addresses=addresses, https_listen_addresses=https_addresses,
                        cert_path=helper["_ca_managed_path"](settings["management_https_cert_path"], "management_https_cert_path"),
                        key_path=helper["_ca_managed_path"](settings["management_https_key_path"], "management_https_key_path"),
                    ).rstrip() + "\n"
                    if site_path.read_bytes() == expected_site.encode("utf-8"):
                        port = int(settings.get("management_public_https_port") or 443)
                        previous = {**published, "phase": "ready", "leaf_fingerprint": applied_leaves[0].get("fingerprint"),
                                    "site_digest": hashlib.sha256(expected_site.encode("utf-8")).hexdigest(),
                                    "urls": [f"https://{'[' + address + ']' if ':' in address else address}:{port}/ui/management/"
                                             for address in native["addresses"]]}
                # This is only a candidate for the same live verification below;
                # no durable baseline or stale observation grants public access.
            if (previous.get("phase") == "ready" and previous.get("addresses") == native["addresses"]
                    and previous.get("apipa_addresses") == native["apipa_addresses"]
                    and (not settings.get("management_https_enabled") or current_leaf is not None
                         and current_leaf.enabled and current_leaf.status != "revoked"
                         and published_pair_matches(str(previous.get("leaf_fingerprint") or ""), target_sans, settings["fqdn"],
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
                return None
            if not native["addresses"]:
                # Remove only the owned dynamic listener. Other management paths
                # remain represented by the applied binding inventory.
                kept = sorted(set(retained + ["127.0.0.1", "::1"]))
                site = helper["_management_nginx_config"](settings, listen_addresses=kept,
                            http_listen_addresses=kept, https_listen_addresses=[address for address in kept if address not in public_tls],
                            cert_path=Path(settings["management_https_cert_path"]) if settings.get("management_https_enabled") else None,
                            key_path=Path(settings["management_https_key_path"]) if settings.get("management_https_enabled") else None)
                withdrawal_unchanged = (
                    previous.get("phase") == "withdrawn" and site_path.is_file()
                    and previous.get("site_digest") == hashlib.sha256(site_path.read_bytes()).hexdigest()
                    and site_path.read_text(encoding="utf-8") == site
                    and helper["_run"](["systemctl", "is-active", "--quiet", "nginx.service"], timeout=5).returncode == 0
                )
                withdrawn = {**published, "phase": "withdrawn"}
                if not withdrawal_unchanged:
                    # Retire public admission before activation. A written file
                    # alone is not proof of a successful reload: failed activation
                    # leaves no checkpoint digest, so the next pass must retry.
                    write_publication(withdrawn)
                    if helper["_install_nginx_site"](site_path, site):
                        raise ValueError("obsolete dynamic management listener could not be withdrawn")
                write_publication({**withdrawn, "site_digest": hashlib.sha256(site_path.read_bytes()).hexdigest(),
                                   "observed_at": datetime.now(timezone.utc).isoformat()})
                identity.host_ip_cidr = None
                identity.host_ip_cidrs = []
                db.commit()
                if previous.get("phase") == "ready":
                    record_audit(db, actor="system:networkd", action="withdraw_dynamic_management", resource_type="network",
                                 resource_id=row["name"], detail=f"{row['name']}: {native['ipv4_state']}; dynamic setup listener withdrawn.")
                return None
            prerequisites = _PublicationPreparation(
                str(settings.get("management_upstream_host") or "127.0.0.1"),
                int(settings.get("management_upstream_port") or settings.get("management_http_port") or 8000),
                bool(settings.get("management_https_enabled")),
            )
            if prepared is None:
                return prerequisites
            if prepared != prerequisites:
                raise ValueError("applied management upstream changed during publication preparation")
            settings["management_ip"] = native["addresses"][0]
            leaf = db.scalar(select(CaCertificate).where(CaCertificate.managed_owner == "appliance:https"))
            ca = db.scalar(select(CaSettings))
            profiles = list(db.scalars(select(CaProfile)))
            material_writer: Callable[[], None] | None = None
            applied_candidate: CaCertificate | None = None
            advance_desired = False
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
                profile = next((profile for profile in profiles if profile.name == CA_SERVER_PROFILE_NAME), None)
                if profile is None or not profile.enabled:
                    raise ValueError("applied management issuance profile is unavailable")
                applied_ca = json.loads(str((baselines.get("ca") or {}).get("config_preview") or "{}"))
                applied_leaves = [item for item in applied_ca.get("certificates", []) if item.get("managed_owner") == "appliance:https"]
                if (len(applied_leaves) != 1 or applied_leaves[0].get("common_name") != settings["fqdn"]
                        or applied_leaves[0].get("cert_path") != settings["management_https_cert_path"]
                        or applied_leaves[0].get("key_path") != settings["management_https_key_path"]):
                    raise ValueError("applied management certificate identity is unavailable")
                # Issuance is detached from desired state. In particular an
                # Apply review may already have prepared an entirely different
                # leaf; neither failure nor lease publication may replace it.
                advance_desired = (leaf.status == "issued" and leaf.profile_id == profile.id and not leaf.csr_text
                    and json.loads(render_ca_apply_payload(ca, [leaf], include_private_keys=False, profiles=profiles))["certificates"] == applied_leaves)
                applied_candidate = CaCertificate(
                    managed_owner="appliance:https", common_name=settings["fqdn"], profile_id=profile.id,
                    subject_alt_names=join_multiline([settings["fqdn"]]), ip_addresses=join_multiline(sans),
                    enabled=True, status="planned", csr_text=None,
                    cert_path=settings["management_https_cert_path"], key_path=settings["management_https_key_path"],
                    chain_path=applied_leaves[0].get("chain_path") or "",
                )
                if not issue_certificate(ca, profiles, applied_candidate):
                    raise ValueError("applied management certificate issuance failed")
                if applied_candidate.expires_at is None or ensure_aware(applied_candidate.expires_at) <= datetime.now(timezone.utc) + timedelta(seconds=90):
                    raise ValueError("management TLS leaf has insufficient remaining validity")
                # Retain writer admission through activation. The helper's
                # durable pair/site rollback owns interrupted file replacement;
                # no candidate is committed over pending desired intent.
                if (db.scalar(select(Job.id).where(Job.type == "appliance-apply", Job.status.in_(["pending", "running"])))
                        or snapshot_digest(applied_snapshots(db).get("network")) != published["network_digest"]
                        or snapshot_digest(applied_snapshots(db).get("appliance_settings")) != published["settings_digest"]
                        or snapshot_digest(applied_snapshots(db).get("ca")) != snapshot_digest(baselines.get("ca"))
                        or not bootstrap["recovery_root_matches_baseline"](db)):
                    raise ValueError("management publication inputs changed before activation")
                def install_pair() -> None:
                    """Replace only the management pair after its rollback snapshot is durable."""
                    assert applied_candidate is not None
                    bootstrap["write_secret_text_atomic"](key_destination, decrypt_secret(applied_candidate.private_key_encrypted))
                    bootstrap["write_text_atomic"](cert_destination, applied_candidate.chain_pem, mode=0o644)

                material_writer = install_pair
                published["leaf_fingerprint"] = applied_candidate.fingerprint
            # Native re-read excludes carrier/address changes during issuance.
            if native_management_addresses(row, helper["_network_address_observation"]()) != native:
                raise ValueError("native management address changed during publication")
            result, _ = helper["_configure_atlaso_management_https"](
                settings, listen_addresses=addresses, http_listen_addresses=addresses, https_listen_addresses=https_addresses,
                material_writer=material_writer)
            if result:
                raise ValueError("dynamic management listener failed readiness; prior front door restored")
            if settings.get("management_https_enabled"):
                assert ca is not None and leaf is not None and applied_candidate is not None
                served = ssl.get_server_certificate((settings["management_ip"], int(settings.get("management_public_https_port") or 443)), timeout=3)
                if hashlib.sha256(ssl.PEM_cert_to_DER_cert(served)).hexdigest() != published["leaf_fingerprint"]:
                    raise ValueError("published TLS leaf is not active on the dynamic listener")
                public_payload = render_ca_apply_payload(ca, [applied_candidate], include_private_keys=False, profiles=profiles)
                bootstrap["record_ca_publication_baseline"](db, public_payload, [], management_only=True)
                if advance_desired:
                    # Only an unchanged, already applied desired leaf follows
                    # the new publication, and only after verified activation.
                    for field in ("common_name", "profile_id", "subject_alt_names", "ip_addresses", "status", "serial_number",
                                  "certificate_pem", "private_key_encrypted", "chain_pem", "issuer_common_name", "fingerprint",
                                  "cert_path", "key_path", "chain_path", "issued_at", "expires_at"):
                        setattr(leaf, field, getattr(applied_candidate, field))
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
    return None


def reconcile(helper: dict[str, Any], bootstrap: dict[str, Any]) -> None:
    """Prepare publication without blocking application startup or audited console access.

    Args:
        helper: Canonical installed privileged helper functions.
        bootstrap: Canonical installed HTTPS bootstrap/recovery helpers.
    """
    preparation = _reconcile_once(helper, bootstrap, prepared=None)
    if preparation is not None:
        # Web startup needs SQLite writes and native Network admission before
        # it can answer HTTP. Waiting for it while holding either lock creates
        # a startup/publication cycle and blocks unrelated console audit writes.
        if preparation.https_enabled:
            bootstrap["_ui_functions"]()
        helper["_management_handoff_upstream_readiness"](
            upstream_host=preparation.upstream_host, upstream_port=preparation.upstream_port,
        )
        # No admission survives the unlocked wait: repeat observation, applied
        # snapshots, pending-Apply checks and endpoint binding before activation.
        _reconcile_once(helper, bootstrap, prepared=preparation)


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
