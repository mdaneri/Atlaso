"""Focused PR871 HTTP validation; only run beneath the supported bounded child.

Credentials and cookies stay in memory. Public evidence contains allowlisted fields.
The default mode inspects only. Mutation requires --execute and a reviewed plan.
"""

import argparse
import hashlib
import http.cookiejar
import ipaddress
import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from certificate_peer_proof import Refusal as PeerProofRefusal
from certificate_peer_proof import admit_receipts as admit_private_receipts
from certificate_peer_proof import read_native as read_private_native
from certificate_peer_transport import (
    PeerHTTPSHandler,
    PeerTransportRefusal,
    PinnedApplianceSession,
    PinnedPeerTransport,
)


class Refusal(Exception):
    """Fixed non-secret diagnostic suitable for evidence."""


class Page(HTMLParser):
    """Read server-rendered CSRF and physical-interface public projection."""

    def __init__(self, body):
        """Initialize the validated client or test double.

        Args:
            body: Body used by this operation."""
        super().__init__()
        self.csrf = ""
        self.rows = []
        self.certificates = []
        self.dns_fields = {}
        self.dns_textarea = None
        self.feed(body)

    def handle_starttag(self, tag, attributes):
        """Handle starttag for certificate handoff verification.

        Args:
            tag: Tag used by this operation.
            attributes: Attributes used by this operation."""
        values = dict(attributes)
        if values.get("name") in {"external_dns_servers", "upstream_servers"}:
            if tag == "input":
                self.dns_fields[values["name"]] = values.get("value", "")
            elif tag == "textarea":
                self.dns_textarea = values["name"]
                self.dns_fields[self.dns_textarea] = ""
        if tag == "input" and values.get("name") == "csrf":
            self.csrf = values.get("value", "")
        if values.get("id") == "physical-interfaces-table":
            self.rows = json.loads(values["data-interfaces"])
            self.csrf = values.get("data-csrf", self.csrf)
        if values.get("id") == "ca-certificates-table":
            self.certificates = json.loads(values["data-certificates"])


    def handle_data(self, data):
        """Read only the two public DNS values needed for restoration checks.

        Args:
            data: Data used by this operation."""
        if self.dns_textarea is not None:
            self.dns_fields[self.dns_textarea] += data

    def handle_endtag(self, tag):
        """Close an observed DNS textarea.

        Args:
            tag: Tag used by this operation."""
        if tag == "textarea":
            self.dns_textarea = None


def dns_baseline(client):
    """Require explicit setup DNS so conversion cannot silently adopt new defaults.

    Args:
        client: Authenticated appliance client used for this request."""
    result = {}
    for path, key in (("/ui/management/settings", "external_dns_servers"),
                      ("/ui/management/dns", "upstream_servers")):
        _, body = client.request(path)
        values = Page(body).dns_fields.get(key, "")
        servers = [str(ipaddress.ip_address(value.strip())) for value in values.splitlines() if value.strip()]
        if not servers:
            raise Refusal("explicit_verified_dns_baseline_required")
        result[key] = servers
    return result


class SameOrigin(urllib.request.HTTPRedirectHandler):
    """Never forward credentials to a redirect-selected different origin."""

    def redirect_request(self, request, response, code, message, headers, new_url):
        """Handle redirect request for certificate handoff verification.

        Args:
            request: HTTP request being processed.
            response: HTTP response being processed.
            code: Code used by this operation.
            message: Message used by this operation.
            headers: Headers used by this operation.
            new_url: Redirect destination URL."""
        old = urllib.parse.urlsplit(request.full_url)
        new = urllib.parse.urlsplit(new_url)
        if (old.scheme, old.netloc) != (new.scheme, new.netloc):
            raise Refusal("cross_origin_redirect")
        return super().redirect_request(request, response, code, message, headers, new_url)


class Client:
    """CA and hostname-verified HTTP with an in-memory session cookie jar."""

    def __init__(self, url, ca, *, peer, connect_ip):
        """Initialize the validated client or test double.

        Args:
            url: HTTPS origin to validate.
            ca: Trusted CA certificate used for TLS verification.
            peer: Pinned private-LAN peer transport.
            connect_ip: Pinned appliance address for the connection."""
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise Refusal("invalid_origin")
        self.url = url.rstrip("/")
        self.peer = peer
        self.connect_ip = str(ipaddress.IPv4Address(connect_ip))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_verify_locations(cafile=str(ca))
        self.context = context
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            SameOrigin(), urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(self.cookies),
            PeerHTTPSHandler(peer=peer, target_ip=self.connect_ip, context=self.context),
        )

    def request(self, path, form=None, accept="text/html"):
        """Handle request for certificate handoff verification.

        Args:
            path: Path to the resource being inspected.
            form: Form fields submitted to the appliance.
            accept: Accept used by this operation."""
        if not path.startswith("/") or path.startswith("//"):
            raise Refusal("invalid_request_path")
        data = None if form is None else urllib.parse.urlencode(form, doseq=True).encode()
        request = urllib.request.Request(self.url + path, data=data, headers={"Accept": accept})
        try:
            with self.opener.open(request, timeout=12) as response:
                body = response.read(2_000_001)
                if len(body) > 2_000_000:
                    raise Refusal("response_too_large")
                return response.status, body.decode("utf-8")
        except urllib.error.HTTPError as exc:
            # Do not expose error bodies, request URLs, or headers.
            raise Refusal(f"http_{exc.code}") from None

    def json(self, path, form=None):
        """Handle json for certificate handoff verification.

        Args:
            path: Path to the resource being inspected.
            form: Form fields submitted to the appliance."""
        status, body = self.request(path, form, "application/json")
        return status, json.loads(body)

    def login(self, username, password):
        """Handle login for certificate handoff verification.

        Args:
            username: Account name for this request.
            password: Credential held in memory for this request."""
        _, body = self.request("/ui/management/login")
        csrf = Page(body).csrf
        if not csrf:
            raise Refusal("login_csrf_missing")
        self.request("/ui/management/login", {"username": username, "password": password, "csrf": csrf})
        _, body = self.request("/ui/management/physical-interfaces")
        page = Page(body)
        if not page.rows or not page.csrf:
            raise Refusal("authenticated_inventory_missing")

    def interface(self, name):
        """Handle interface for certificate handoff verification.

        Args:
            name: Name used by this operation."""
        _, body = self.request("/ui/management/physical-interfaces")
        page = Page(body)
        matches = [row for row in page.rows if row.get("name") == name]
        if len(matches) != 1 or not page.csrf:
            raise Refusal("interface_identity_ambiguous")
        return matches[0], page.csrf

    def tls_identity(self):
        parsed = urllib.parse.urlsplit(self.url)
        with self.peer.open_socket(self.connect_ip, parsed.port or 443) as raw:
            with self.context.wrap_socket(raw, server_hostname=parsed.hostname) as connection:
                der = connection.getpeercert(binary_form=True)
                certificate = connection.getpeercert()
        return {"sha256": hashlib.sha256(der).hexdigest(),
                "ip_sans": [str(ipaddress.ip_address(value)) for kind, value in certificate.get("subjectAltName", []) if kind == "IP Address"]}


FIELDS = ("role", "mode", "ipv4_method", "ip_cidr", "gateway", "ipv6_enabled", "ipv6_cidr", "ipv6_gateway", "mtu", "admin_state", "check_duplicate_ip_addresses", "access_management_ui_enabled")


def same_mac(left, right):
    """Compare VMware and appliance MAC spellings without accepting missing identities.

    Args:
        left: Left used by this operation.
        right: Right used by this operation."""
    def canonical(value):
        """Handle canonical for certificate handoff verification.

        Args:
            value: Value used by this operation."""
        if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", value):
            return ""
        octets = value.replace("-", ":").lower().split(":")
        return ":".join(octets)

    first = canonical(left)
    return bool(first) and first == canonical(right)


def saved_fields(row):
    """Retain desired fields only; never POST inventory or audit properties.

    Args:
        row: Row used by this operation."""
    result = {key: "" if row.get(key) is None else row[key] for key in FIELDS}
    result["admin_state"] = "up" if row.get("admin_up") else "down"
    return result


def edit(client, name, fields, expected_mac):
    """Use the same atomic domain mutation and audit path as the UI.

    Args:
        client: Authenticated appliance client used for this request.
        name: Name used by this operation.
        fields: Physical interface fields to apply.
        expected_mac: Expected physical interface MAC address."""
    current, csrf = client.interface(name)
    if not same_mac(current.get("mac_address"), expected_mac):
        raise Refusal("interface_mac_changed")
    form = {key: "" if value is None else str(value).lower() if isinstance(value, bool) else value
            for key, value in fields.items()}
    form["access_management_ui_enabled"] = "on" if fields["access_management_ui_enabled"] else "off"
    form["csrf"] = csrf
    client.request(f"/ui/management/physical-interfaces/{int(current['id'])}/edit", form)


def submit(client):
    """Run ordinary review/admission and return the exact master task URL.

    Args:
        client: Authenticated appliance client used for this request."""
    _, review = client.json("/ui/management/appliance-apply/review")
    if review.get("active_task"):
        raise Refusal("apply_already_active")
    protected = {"network", "ca", "firewall", "appliance_settings", "public_services"}
    units = review.get("units", [])
    if any(unit.get("id") not in protected for unit in units):
        raise Refusal("unrelated_pending_units")
    if any(not unit.get("valid") for unit in units):
        raise Refusal("apply_review_invalid")
    _, body = client.request("/ui/management/physical-interfaces")
    csrf = Page(body).csrf
    if not csrf:
        raise Refusal("apply_csrf_missing")
    status, result = client.json("/ui/management/appliance-apply", {"csrf": csrf, "selected_units": sorted(protected)})
    if status != 202 or not result.get("job_id"):
        raise Refusal("apply_not_admitted")
    path = str(result.get("status_url", ""))
    if path not in (f"/tasks/{result['job_id']}/status", f"/ui/management/tasks/{result['job_id']}/status"):
        raise Refusal("unexpected_task_url")
    return result["job_id"], path


def wait_task(clients, status_path, username, password):
    """Follow the admitted task across only predeclared verified origins.

    Args:
        clients: Appliance clients for the original and candidate addresses.
        status_path: Task status endpoint to poll.
        username: Account name for this request.
        password: Credential held in memory for this request."""
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        for client in clients:
            try:
                _, result = client.json(status_path)
                task = result.get("task", {})
                if task and (task.get("id") != status_path.split("/")[-2] or task.get("type") != "appliance-apply"):
                    raise Refusal("task_identity_mismatch")
                if task.get("status") in ("succeeded", "failed", "cancelled"):
                    return task, client
                if not task:
                    client.login(username, password)
            except (Refusal, OSError, ValueError):
                try:
                    client.login(username, password)
                except (Refusal, OSError, ValueError):
                    pass
        time.sleep(1)
    raise Refusal("task_timeout_do_not_resubmit")


def evidence_values(value, key):
    """Find an explicit result property in task steps without logging task bodies.

    Args:
        value: Value used by this operation.
        key: Key used by this operation."""
    found = []
    if isinstance(value, dict):
        if key in value:
            found.append(value[key])
        for child in value.values():
            found.extend(evidence_values(child, key))
    elif isinstance(value, list):
        for child in value:
            found.extend(evidence_values(child, key))
    elif isinstance(value, str) and value.startswith(("{", "[")):
        try:
            found.extend(evidence_values(json.loads(value), key))
        except ValueError:
            pass
    return found


def public_certificate_excludes(client, certificate_id, address, ca, destination, openssl):
    """Validate the actual public desired leaf, never a handcrafted CA payload.

    Args:
        client: Authenticated appliance client used for this request.
        certificate_id: Certificate identifier to verify.
        address: Address used by this operation.
        ca: Trusted CA certificate used for TLS verification.
        destination: Destination endpoint of the transport.
        openssl: OpenSSL executable for certificate verification."""
    _, pem = client.request(f"/ui/management/certificate-authority/certificates/{certificate_id}/downloads/certificate.pem")
    if "PRIVATE KEY" in pem or not pem.startswith("-----BEGIN CERTIFICATE-----"):
        raise Refusal("unexpected_public_certificate_response")
    with destination.open("x", encoding="utf-8") as stream:
        stream.write(pem)
        stream.flush()
        os.fsync(stream.fileno())
    base = [openssl, "verify", "-CAfile", ca, "-no-CApath", "-no-CAstore", "-purpose", "sslserver"]
    if subprocess.run([*base, str(destination)], capture_output=True, timeout=10, check=False).returncode:
        raise Refusal("desired_certificate_chain_invalid")
    if not subprocess.run([*base, "-verify_ip", address, str(destination)], capture_output=True, timeout=10, check=False).returncode:
        raise Refusal("desired_certificate_covers_negative_address")
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


def selected_management_certificate(client, certificate_id):
    """Bind the negative candidate to the live service-owned certificate row.

    Args:
        client: Authenticated appliance client used for this request.
        certificate_id: Certificate identifier to verify."""
    _, body = client.request("/ui/management/certificate-authority")
    rows = Page(body).certificates
    managed = [row for row in rows if isinstance(row, dict) and row.get("managed_owner") == "appliance:https"]
    if len(managed) != 1 or managed[0].get("id") != certificate_id:
        raise Refusal("management_certificate_selection_mismatch")
    row = managed[0]
    if row.get("status") != "issued" or not row.get("enabled") or not row.get("can_export_certificate"):
        raise Refusal("management_certificate_not_issued")
    fingerprint = row.get("fingerprint")
    if not isinstance(fingerprint, str) or not re.fullmatch(r"[A-Fa-f0-9]{64}", fingerprint):
        raise Refusal("management_certificate_fingerprint_invalid")
    return {"id": certificate_id, "managed_owner": "appliance:https", "fingerprint": fingerprint}


def admin_password():
    """Consume the supported SDK bridge result in this bounded child only."""
    password = os.environ.pop("ATLASO_NATIVE_ADMIN", None)
    if not password or len(password) < 12 or password != password.strip():
        raise Refusal("bounded_credential_bridge_required")
    return password


def peer_password():
    """Consume the separate client-SSH secret only after peer identity admission."""
    password = os.environ.pop("ATLASO_NATIVE_PEER", None)
    if not password or len(password) < 12 or password != password.strip():
        raise Refusal("bounded_peer_credential_bridge_required")
    return password


def clean_baseline(client):
    """Reject active, pending, malformed, or never-applied baselines.

    Args:
        client: Authenticated appliance client used for this request."""
    _, review = client.json("/ui/management/appliance-apply/review")
    if (review.get("active_task") is not None or review.get("units") != []
            or review.get("pending_count") != 0 or review.get("initial_apply_required") is not False):
        raise Refusal("requires_clean_applied_baseline")


def restore_original(clients, plan, fields, before, username, password, original_dns):
    """Restore desired state and prove trusted TLS for the original origin, allowing reissuance.

    Args:
        clients: Appliance clients for the original and candidate addresses.
        plan: Validated task plan bound to the owned test resources.
        fields: Physical interface fields to apply.
        before: Original interface values to restore.
        username: Account name for this request.
        password: Credential held in memory for this request.
        original_dns: Original DNS values to restore."""
    reachable = None
    for candidate in clients:
        try:
            candidate.login(username, password)
            reachable = candidate
            break
        except (Refusal, OSError, ValueError):
            continue
    if reachable is None:
        raise Refusal("restore_no_trusted_origin")
    edit(reachable, plan["interface"], fields, plan["mac"])
    _, review = reachable.json("/ui/management/appliance-apply/review")
    if review.get("active_task"):
        raise Refusal("restore_requires_terminal_task")
    job_id = None
    if review.get("units"):
        job_id, path = submit(reachable)
        task, _ = wait_task(clients, path, username, password)
        if task.get("status") != "succeeded":
            raise Refusal("restore_apply_failed")
    original = clients[0]
    original.login(username, password)
    row, _ = original.interface(plan["interface"])
    if saved_fields(row) != fields:
        raise Refusal("restore_desired_mismatch")
    clean_baseline(original)
    if dns_baseline(original) != original_dns:
        raise Refusal("restore_dns_mismatch")
    original.json("/openapi.json")
    after = original.tls_identity()
    hostname = urllib.parse.urlsplit(plan["url"]).hostname
    try:
        address = str(ipaddress.ip_address(hostname))
    except ValueError:
        # Client's CERT_REQUIRED context already checked a DNS hostname.
        address = None
    if address is not None and address not in after["ip_sans"]:
        raise Refusal("restored_certificate_missing_original_ip_san")
    return {"restore_job_id": job_id, "restored_tls": after,
            "original_tls_sha256": before["sha256"], "restored_tls_sha256": after["sha256"],
            "restored_tls_fingerprint_changed": after["sha256"] != before["sha256"]}


def bound_json(reference):
    """Read a bounded evidence artifact whose original digest is in the plan.

    Args:
        reference: Receipt reference to validate."""
    path = Path(reference["path"])
    if not path.is_absolute() or path.is_symlink() or not path.is_file() or path.stat().st_size > 262144:
        raise Refusal("unsafe_evidence_reference")
    payload = path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != reference["sha256"].lower():
        raise Refusal("evidence_digest_changed")
    return json.loads(payload)


def admit_predeployment_binding(plan, ownership, source, runtime):
    """Require the routing-absence readback from this exact owned VM and runtime.

    Args:
        plan: Validated task plan bound to the owned test resources.
        ownership: Original resource ownership record.
        source: Source resource bound to the test plan.
        runtime: Observed runtime identity for the test appliance."""
    if (source.get("task_id") != plan["task_id"]
            or source.get("vmx_path") != plan["vmx_path"]
            or source.get("source_commit") != ownership["source_commit"]
            or runtime.get("predeployment_sha256") != plan["predeployment_evidence"]["sha256"]):
        raise Refusal("predeployment_runtime_binding_mismatch")


def admit_execution(plan):
    """Bind canonical creation, predeployment and exact installed-runtime evidence.

    Args:
        plan: Validated task plan bound to the owned test resources."""
    deployed_commit = plan.get("deployed_commit", "")
    git_environment = os.environ.copy()
    git_environment.pop("ATLASO_NATIVE_ADMIN", None)
    git_environment.pop("ATLASO_NATIVE_PEER", None)
    current_head = subprocess.run(
        ["git", "-C", str(Path(__file__).resolve().parents[2]), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True, env=git_environment,
    ).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", deployed_commit) or deployed_commit != current_head:
        raise Refusal("wrong_deployed_commit")
    intent = bound_json(plan["vm_creation_intent"])
    ownership = bound_json(plan["vm_ownership"])
    if (ownership.get("schema") != 1 or ownership.get("kind") != "vm"
            or ownership.get("repository") != "mdaneri/Atlaso" or ownership.get("pr") != 871
            or ownership.get("task_id") != plan["task_id"]
            or ownership.get("path") != plan["vmx_path"]
            or ownership.get("root_path") != plan["vm_root_path"]
            or ownership.get("intent_sha256") != plan["vm_creation_intent"]["sha256"]
            or not re.fullmatch(r"[0-9a-f]{40}", ownership.get("source_commit", ""))):
        raise Refusal("vm_original_ownership_mismatch")
    if (intent.get("kind") != "vm-creation-intent" or intent.get("task_id") != plan["task_id"]
            or intent.get("path") != plan["vmx_path"]
            or intent.get("root_path") != plan["vm_root_path"]
            or intent.get("source_commit") != ownership["source_commit"]):
        raise Refusal("vm_creation_intent_mismatch")
    # Use the canonical original identity tuple, not a new ownership snapshot.
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from scripts.completed_task_files import WindowsFiles
    with WindowsFiles().opened(Path(plan["vm_root_path"]), directory=True) as (_, identity, _):
        if list(identity) != ownership["root_identity"]:
            raise Refusal("vm_original_identity_changed")
    source = bound_json(plan["predeployment_evidence"])
    route_snapshot = source.get("route_snapshot", {})
    expected_counts = {
        "routes", "routing_rules", "nat_rules", "port_forwards", "wan_policies",
        "route_physical_interfaces", "route_vlan_interfaces",
    }
    expected_settings = {
        "routes_wan.routing_enabled", "routes_wan.wan_simulation_enabled",
        "routes_wan.nat_enabled", "traffic_publishing.nat_enabled",
    }
    if (source.get("phase") != "before-lifecycle-deployment" or source.get("schema") != 1
            or source.get("routing_intent_state") != "proven-absent"
            or source.get("routing_intent") is not None
            or source.get("app_service", {}).get("LoadState") != "loaded"
            or source.get("app_service", {}).get("ActiveState") != "active"
            or route_snapshot.get("schema") != 1
            or route_snapshot.get("database") != "/var/lib/atlaso/atlaso.db"
            or route_snapshot.get("state") != "proven-absent"
            or set(route_snapshot.get("counts", {})) != expected_counts
            or any(value != 0 for value in route_snapshot["counts"].values())
            or set(route_snapshot.get("settings", {})) != expected_settings
            or any(value is True for value in route_snapshot["settings"].values())
            or route_snapshot.get("routing_service") not in (None, {"enabled": False, "running": False})
            or not re.fullmatch(r"[a-f0-9]{64}", route_snapshot.get("probe_sha256", ""))):
        raise Refusal("source_route_domain_ownership_present_or_unproven")
    runtime = bound_json(plan["runtime_evidence"])
    admit_predeployment_binding(plan, ownership, source, runtime)
    if (runtime.get("schema") != 1 or runtime.get("vmx_path") != plan["vmx_path"]
            or runtime.get("vm_ownership_sha256") != plan["vm_ownership"]["sha256"]
            or runtime.get("deployed_commit") != deployed_commit
            or runtime.get("url") != plan["url"] or runtime.get("interface") != plan["interface"]
            or not same_mac(runtime.get("mac"), plan["mac"])):
        raise Refusal("installed_runtime_binding_mismatch")
    for name in ("wheel_sha256", "helper_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", runtime.get(name, "")) or runtime[name] != plan[name]:
            raise Refusal("installed_runtime_digest_mismatch")
    if runtime.get("address_ownership_state") != "proven-controlled":
        raise Refusal("task_address_ownership_unproven")
    if (runtime.get("kind") != "certificate-controlled-runtime"
            or runtime.get("rewired_runtime_sha256") != plan["rewired_runtime"]["sha256"]
            or runtime.get("address_proof_sha256") != plan["address_evidence"]["sha256"]):
        raise Refusal("controlled_runtime_proof_binding_mismatch")
    try:
        fixture, _ = admit_private_receipts(plan)
    except (PeerProofRefusal, OSError, KeyError, ValueError, TypeError, RuntimeError):
        raise Refusal("private_original_receipts_unproven") from None
    actual_helper = hashlib.sha256((Path(__file__).resolve().parents[2] / "scripts/appliance/atlaso-helper").read_bytes()).hexdigest()
    if actual_helper != runtime["helper_sha256"]:
        raise Refusal("reviewed_helper_digest_mismatch")
    address = str(ipaddress.ip_interface(plan["candidate_cidr"]).ip) if plan["scenario"] == "static-success" else str(ipaddress.IPv4Address(plan["expected_dhcp_address"]))
    reservation = bound_json(plan["address_evidence"])
    if (reservation.get("schema") != 1 or reservation.get("kind") != "certificate-private-address-proof"
            or reservation.get("exclusive_attachment_state") != "verified-current"
            or reservation.get("candidate_conflict_state") != "clear-current"
            or reservation.get("phase") != "static-baseline-preflight"
            or reservation.get("task_id") != plan["task_id"]
            or reservation.get("vmx_path") != plan["vmx_path"]
            or reservation.get("peer_fixture_sha256") != plan["peer_fixture"]["sha256"]
            or reservation.get("rewired_runtime_sha256") != plan["rewired_runtime"]["sha256"]
            or reservation.get("lan_segment_receipt_sha256") != fixture["lan_segment_receipt_sha256"]
            or reservation.get("ca_sha256") != hashlib.sha256(Path(plan["ca_path"]).read_bytes()).hexdigest()
            or reservation.get("peer_routed_baseline_https") != "explicit-ca-and-ip-hostname-verified"
            or address not in reservation.get("addresses", [])):
        raise Refusal("task_address_ownership_unproven")
    peer_plan = plan["peer_transport"]
    baseline = ipaddress.IPv4Address(peer_plan["baseline_address"])
    private = ipaddress.IPv4Network(peer_plan["private_subnet"])
    if (baseline not in private or address not in reservation["addresses"]
            or urllib.parse.urlsplit(plan["url"]).hostname != str(baseline)
            or reservation.get("baseline_address") != str(baseline)):
        raise Refusal("peer_private_origin_mismatch")
    return {"creation_source_commit": ownership["source_commit"], "deployed_commit": deployed_commit,
            "wheel_sha256": runtime["wheel_sha256"], "helper_sha256": runtime["helper_sha256"],
            "vm_ownership_sha256": plan["vm_ownership"]["sha256"],
            "predeployment_sha256": plan["predeployment_evidence"]["sha256"],
            "runtime_sha256": plan["runtime_evidence"]["sha256"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    evidence = {"schema": 1, "pr": 871, "mode": "execute" if args.execute else "inspect", "stage": "preflight", "success": False}
    password = None
    peer_transport = None
    mutation_started = False
    task_terminal = False
    try:
        plan = json.loads(Path(args.plan).read_text())
        if plan.get("pr") != 871 or not plan.get("source_commit") or plan.get("scenario") not in ("static-success", "dhcp-reject"):
            raise Refusal("plan_contract")
        if Path(args.evidence).exists() or Path(args.evidence + ".original.json").exists():
            raise Refusal("evidence_destination_exists")
        evidence["admission"] = admit_execution(plan)
        evidence["no_publication_evidence_basis"] = "reviewed exact helper ordering and unit assertions plus native prerequisite failure and rollback"
        evidence["native_observation_limit"] = "TLS before and after; individual transient nginx generations are not directly observed"
        if args.preflight_only:
            evidence.update(success=True, stage="admitted_no_credentials_or_network")
            return
        password = admin_password()
        peer_secret = peer_password()
        peer_plan = plan["peer_transport"]
        peer_transport = PinnedPeerTransport(
            peer_plan["host"], peer_plan["user"], peer_secret,
            peer_plan["ssh_host_key"], peer_plan["private_subnet"],
        )
        peer_transport.__enter__()
        try:
            fixture, _ = admit_private_receipts(plan)
            with PinnedApplianceSession(
                peer_transport, peer_plan["baseline_address"], plan["appliance_user"],
                password, plan["appliance_ssh_host_key"],
            ) as appliance_session:
                live_reservation = read_private_native(plan, fixture, peer_transport, appliance_session)
            if live_reservation != bound_json(plan["address_evidence"]):
                raise Refusal("private_live_preflight_changed")
        except (PeerProofRefusal, PeerTransportRefusal, OSError, KeyError, ValueError, RuntimeError):
            raise Refusal("private_live_preflight_unproven") from None
        client = Client(plan["url"], plan["ca_path"], peer=peer_transport,
                        connect_ip=peer_plan["baseline_address"])
        client.login(plan.get("username", "admin"), password)
        original, _ = client.interface(plan["interface"])
        fields = saved_fields(original)
        if fields["role"] != "management" or fields["ipv6_enabled"] or not same_mac(original.get("mac_address"), plan["mac"]):
            raise Refusal("requires_exact_ipv4_management_interface")
        clean_baseline(client)
        original_dns = dns_baseline(client)
        before = client.tls_identity()
        selected_certificate = None
        if plan["scenario"] == "dhcp-reject":
            selected_certificate = selected_management_certificate(
                client, int(plan["management_certificate_id"]),
            )
            evidence["selected_management_certificate"] = selected_certificate
        evidence["ca_sha256"] = hashlib.sha256(Path(plan["ca_path"]).read_bytes()).hexdigest()
        evidence.update(original_dns=original_dns, original_fields=fields, interface=plan["interface"], mac=plan["mac"], original_tls=before)
        if not args.execute:
            evidence.update(success=True, stage="inspection_complete_no_mutation")
            return
        # Commit rollback inputs before the first production mutation, not only
        # in the terminal evidence writer (the process may be interrupted).
        with Path(args.evidence + ".original.json").open("x", encoding="utf-8") as stream:
            json.dump({"schema": 1, "pr": 871, "source_commit": plan["source_commit"],
                       "url": plan["url"], "interface": plan["interface"], "mac": plan["mac"],
                       "original_fields": fields, "original_tls": before, "original_dns": original_dns}, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        changed = dict(fields)
        clients = [client]
        if plan["scenario"] == "static-success":
            candidate = ipaddress.ip_interface(plan["candidate_cidr"])
            if candidate.version != 4:
                raise Refusal("requires_ipv4_candidate")
            changed.update(ipv4_method="static", ip_cidr=str(candidate), gateway=plan["candidate_gateway"])
            candidate_client = Client(
                f"https://{candidate.ip}:{urllib.parse.urlsplit(plan['url']).port or 443}",
                plan["ca_path"], peer=peer_transport, connect_ip=str(candidate.ip),
            )
            clients.append(candidate_client)
        else:
            if fields["ipv4_method"] != "static":
                raise Refusal("negative_case_requires_static_baseline")
            address = str(ipaddress.IPv4Address(plan["expected_dhcp_address"]))
            if address in before["ip_sans"]:
                raise Refusal("negative_address_already_covered")
            changed.update(ipv4_method="dhcp", ip_cidr="", gateway="")
        evidence["stage"] = "desired_edit"
        mutation_started = True
        task_terminal = True
        edit(client, plan["interface"], changed, plan["mac"])
        if plan["scenario"] == "dhcp-reject":
            if selected_management_certificate(client, selected_certificate["id"]) != selected_certificate:
                raise Refusal("management_certificate_changed_after_desired_edit")
            evidence["desired_certificate_sha256"] = public_certificate_excludes(
                client, int(plan["management_certificate_id"]), address, plan["ca_path"],
                Path(args.evidence + ".public-leaf.pem"), plan["openssl_path"],
            )
            if evidence["desired_certificate_sha256"] != selected_certificate["fingerprint"].lower():
                raise Refusal("selected_certificate_public_leaf_mismatch")
        evidence["stage"] = "apply_submission"
        task_terminal = False
        job_id, status_path = submit(client)
        evidence.update(job_id=job_id, stage="apply_wait")
        task, _ = wait_task(clients, status_path, plan.get("username", "admin"), password)
        task_terminal = True
        if True in evidence_values(task, "dry_run"):
            raise Refusal("dry_run_not_native_evidence")
        evidence["status"] = task.get("status")
        if hashlib.sha256(Path(plan["ca_path"]).read_bytes()).hexdigest() != evidence["ca_sha256"]:
            raise Refusal("trusted_ca_changed_during_run")
        if plan["scenario"] == "static-success":
            if task.get("status") != "succeeded":
                raise Refusal("static_handoff_failed")
            candidate_client.login(plan.get("username", "admin"), password)
            candidate_client.json("/openapi.json")
            final_row, _ = candidate_client.interface(plan["interface"])
            if saved_fields(final_row) != changed:
                raise Refusal("candidate_desired_state_mismatch")
            if dns_baseline(candidate_client) != original_dns:
                raise Refusal("candidate_dns_drift")
            evidence["candidate_tls"] = candidate_client.tls_identity()
            task_terminal = False
            evidence.update(restore_original(clients, plan, fields, before, plan.get("username", "admin"), password, original_dns))
            mutation_started = False
            evidence.update(stage="static_success_and_original_restored", success=True)
        else:
            layers = evidence_values(task, "failing_layer")
            outcomes = evidence_values(task, "management_handoff")
            if task.get("status") != "failed" or "certificate prerequisite" not in layers or "rolled back" not in outcomes:
                raise Refusal("expected_certificate_rollback_not_proven")
            after = client.tls_identity()
            client.json("/openapi.json")
            if after != before:
                raise Refusal("old_tls_identity_changed")
            evidence.update(failing_layer="certificate prerequisite", management_handoff="rolled back", rollback_tls=after)
            errors = evidence_values(task, "error")
            expected_error = f"management HTTPS certificate does not authenticate candidate address {address};"
            if not any(isinstance(error, str) and expected_error in error for error in errors):
                raise Refusal("expected_acquired_address_not_proven")
            evidence["rejected_acquired_address"] = address
            evidence["stage"] = "restore_desired_static"
            task_terminal = False
            evidence.update(restore_original(clients, plan, fields, before, plan.get("username", "admin"), password, original_dns))
            mutation_started = False
            evidence.update(stage="negative_case_and_desired_restore_complete", success=True)
    except (Refusal, PeerTransportRefusal, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        evidence["failure"] = str(exc) if isinstance(exc, Refusal) else type(exc).__name__
        if mutation_started:
            if not task_terminal:
                evidence["recovery"] = "task_outcome_unproven_do_not_resubmit_use_original_snapshot"
            else:
                try:
                    evidence.update(restore_original(clients, plan, fields, before, plan.get("username", "admin"), password, original_dns))
                    evidence["recovery"] = "original_restored"
                except (Refusal, OSError, ValueError, KeyError, TypeError):
                    evidence["recovery"] = "requires_reconciliation_use_original_snapshot"
    finally:
        if peer_transport is not None:
            peer_transport.__exit__(None, None, None)
        password = None
        peer_secret = None
        os.environ.pop("ATLASO_NATIVE_ADMIN", None)
        os.environ.pop("ATLASO_NATIVE_PEER", None)
        # Never serialize task bodies, response text, sessions, credentials, or exception text.
        path = Path(args.evidence)
        with path.open("x", encoding="utf-8") as stream:
            json.dump(evidence, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        print(json.dumps({"success": evidence["success"], "stage": evidence["stage"], "evidence": str(path)}))
    if not evidence["success"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
