"""Initialize only the fresh ISO fixture prerequisites through normal UI Apply."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from certificate_handoff_native import (
    Client,
    Page,
    clean_baseline,
    dns_baseline,
    saved_fields,
    wait_task,
)
from certificate_iso_bootstrap import (
    guest_identity,
    sudo_read,
    tls_name,
    watched_topology,
)
from certificate_peer_proof import admit_fixture, admit_output, bound_json, publish
from certificate_peer_time import verify_peer_time
from certificate_peer_transport import PinnedApplianceSession, PinnedPeerTransport
from certificate_retirement import verify_peer_isolation, verify_peer_tunnel_scope
from certificate_trusted_host import inspect_trusted_host
from time_source_guest import (
    FormParser,
    apply_review_fields,
    apply_review_path,
    assert_clock,
)

ROOTS = {"appliance_settings", "network", "ca", "firewall", "public_services", "dnsmasq", "ntpd"}
# A first network baseline can require disabled WAN/NAT enforcement. The
# original routing-absence proof is mandatory; no routing desired state is edited.
CLOSURE = ROOTS | {"wan", "nat"}


class Refusal(Exception):
    """Fixed public refusal without response bodies or credentials."""


class FixtureForm(FormParser):
    """Reuse successful-control parsing for one exact existing POST action."""

    def __init__(self, body: str, action: str):
        """Read one existing settings form, retaining its CSRF only in memory.

        Args:
            body: Authenticated server-rendered page.
            action: Exact management form action to select.
        """
        self.expected_action = action
        self.matches = 0
        super().__init__()
        self.feed(body)
        if self.matches != 1 or self.form_action != action:
            raise Refusal("fixture_form_ambiguous")
        tokens = [value for key, value in self.fields if key == "csrf"]
        if len(tokens) != 1 or not tokens[0]:
            raise Refusal("fixture_form_csrf_missing")

    def handle_starttag(self, tag, attrs):
        """Adapt exact-action ownership while preserving browser checkbox values.

        Args:
            tag: Server-rendered HTML tag.
            attrs: Its parsed attribute pairs.
        """
        values = dict(attrs)
        if tag == "form":
            # The source wizard shares the NTP POST action. Select only its
            # existing settings form, whose external fallback controls use this ID.
            matched = (values.get("action") == self.expected_action
                       and (not self.expected_action.endswith("/ntp/settings")
                            or values.get("id") == "ntp-settings-form"))
            if matched:
                if values.get("method", "get").lower() != "post":
                    raise Refusal("fixture_form_method_invalid")
                self.matches += 1
            attrs = [(key, value) for key, value in attrs if key != "id"]
            attrs.append(("id", "ntp-settings-form" if matched else "unselected-fixture-form"))
        if tag == "input" and values.get("type", "text").lower() in {"checkbox", "radio"} and "value" not in values:
            attrs = [*attrs, ("value", "on")]
        if (tag == "input" and values.get("type", "").lower() == "password"
                and (self.in_form or values.get("form") == "ntp-settings-form")):
            raise Refusal("fixture_secret_form_refused")
        super().handle_starttag(tag, attrs)


def replace_fields(fields: list[tuple[str, str]], changes: dict[str, str], remove: set[str] | None = None) -> list[tuple[str, str]]:
    """Change declared controls while preserving all other successful controls.

    Args:
        fields: Parsed browser form fields, including the current CSRF.
        changes: Explicit fixture values to replace or add.
        remove: Additional controls superseded by a structured field.
    """
    omitted = set(changes) | (remove or set())
    return [(key, value) for key, value in fields if key not in omitted] + list(changes.items())


def prepare_forms(client, peer_address: str) -> tuple[dict, dict]:
    """Prepare the existing DNS, appliance-settings and NTP forms without edits.

    Args:
        client: Authenticated, CA-validated management client.
        peer_address: Admitted private peer providing real NTP.
    """
    forms = {}
    public = {}
    for page, action in (("dns", "dns/settings"), ("settings", "settings"), ("ntp", "ntp/settings")):
        _, body = client.request("/ui/management/" + page)
        form = FixtureForm(body, "/ui/management/" + action)
        forms[page] = form
        # Tokens and private-material selectors never enter a receipt, including
        # its digest. Keep opaque controls in memory only for browser submission.
        visible = [(key, value) for key, value in form.fields
                   if key not in {"csrf", "nts_server_key_path", "nts_server_cert_path"}]
        public[page] = {"form_sha256": hashlib.sha256(json.dumps(visible, separators=(",", ":")).encode()).hexdigest()}
    settings = dict(forms["settings"].fields)
    if settings.get("management_https_enabled") not in {"on", "true", "1"}:
        raise Refusal("fixture_management_https_required")
    ntp = dict(forms["ntp"].fields)
    if ntp.get("nts_server_enabled") in {"on", "true", "1"}:
        raise Refusal("fixture_existing_nts_server_refused")
    try:
        sources = json.loads(ntp["upstream_sources_json"])
    except (KeyError, ValueError):
        raise Refusal("fixture_ntp_source_form_invalid") from None
    if not isinstance(sources, list) or not all(isinstance(row, dict) for row in sources):
        raise Refusal("fixture_ntp_source_form_invalid")
    for page, key in (("dns", "upstream_servers"), ("settings", "external_dns_servers")):
        value = dict(forms[page].fields).get(key, "")
        try:
            public[page][key] = [str(ipaddress.ip_address(item.strip())) for item in value.splitlines() if item.strip()]
        except ValueError:
            raise Refusal("fixture_original_resolver_invalid") from None
    public["dns"]["enabled"] = dict(forms["dns"].fields).get("enabled") == "on"
    public["ntp"].update(enabled=ntp.get("enabled") == "on", time_source=ntp.get("time_source"),
                         nts_server_enabled=ntp.get("nts_server_enabled") == "on",
                         upstream_count=len(sources), enabled_upstream_count=sum(bool(row.get("enabled")) for row in sources))
    sources = [dict(row, enabled=False) for row in sources if row.get("source") != peer_address]
    sources.append({"id": "certificate-fixture-peer", "source": peer_address, "enabled": True,
                    "use_nts": False, "description": "Isolated certificate fixture peer"})
    prepared = {
        "dns": replace_fields(forms["dns"].fields, {"enabled": "", "upstream_servers": peer_address}),
        "settings": replace_fields(forms["settings"].fields, {"external_dns_servers": peer_address}),
        "ntp": replace_fields(forms["ntp"].fields, {
            "enabled": "", "nts_server_enabled": "", "time_source": "ntp_client",
            "upstream_servers": peer_address, "upstream_sources_json": json.dumps(sources, separators=(",", ":")),
        }, {"upstream_source", "upstream_enabled", "upstream_use_nts", "upstream_description"}),
    }
    return {page: (forms[page].form_action, fields) for page, fields in prepared.items()}, public


def validate_review(review: dict) -> None:
    """Refuse active jobs or changes outside this initialization's fixed scope.

    Args:
        review: Normal server-side Appliance Apply review.
    """
    if review.get("active_task"):
        raise Refusal("fixture_apply_already_active")
    units = review.get("units")
    if not isinstance(units, list) or not units:
        raise Refusal("fixture_review_invalid")
    if any(unit.get("changed", True) and unit.get("id") not in ROOTS for unit in units):
        raise Refusal("fixture_unrelated_pending_units")


def submit_initialization(client) -> tuple[str, str]:
    """Submit only the server-reviewed fixed initialization roots and dependencies.

    Args:
        client: Authenticated, CA-validated management client.
    """
    _, review = client.json("/ui/management/appliance-apply/review")
    validate_review(review)
    _, review = client.json(apply_review_path("/ui/management/appliance-apply/review", sorted(ROOTS)))
    try:
        fields = apply_review_fields(review)
    except ValueError:
        raise Refusal("fixture_review_invalid") from None
    if set(review.get("requested_units", [])) != ROOTS or any(
        unit.get("id") not in CLOSURE for unit in review.get("units", []) if unit.get("selected")
    ):
        raise Refusal("fixture_review_scope_changed")
    _, body = client.request("/ui/management/physical-interfaces")
    csrf = Page(body).csrf
    if not csrf:
        raise Refusal("fixture_form_csrf_missing")
    form = {"csrf": csrf, "reviewed_plan": review["plan_token"], "requested_units": review["requested_units"],
            "selected_units": [value for key, value in fields if key == "selected_units"]}
    status, result = client.json("/ui/management/appliance-apply", form)
    job = result.get("job_id")
    path = result.get("status_url")
    if status != 202 or not isinstance(job, str) or path not in (f"/tasks/{job}/status", f"/ui/management/tasks/{job}/status"):
        raise Refusal("fixture_apply_not_admitted")
    return job, path


def clock_readback(client) -> dict:
    """Require a real synchronized NTP client with no competing clock controller.

    Args:
        client: Authenticated, CA-validated management client.
    """
    _, payload = client.json("/ui/management/ntp/source-health")
    raw = payload.get("status", {})
    controller = raw.get("selected_controller", {})
    conflicts = raw.get("daemon_conflicts", {})
    clock = {"mode": raw.get("mode"), "healthy": raw.get("synchronization", {}).get("healthy"),
             "controller": {key: controller.get(key) for key in ("name", "active", "enabled")},
             "conflicts": {name: {key: state.get(key) for key in ("active", "enabled")}
                           for name, state in conflicts.items() if isinstance(state, dict)},
             "client_packet_guard": raw.get("client_packet_guard", {}).get("active")}
    try:
        assert_clock(clock, "ntp_client", "healthy")
    except Exception:  # noqa: BLE001 - The shared assertion carries diagnostics unsuitable for evidence.
        raise Refusal("fixture_clock_not_verified") from None
    return clock


def wait_clock(client, timeout: float = 120) -> dict:
    """Allow genuine source selection to settle without changing clock state.

    Args:
        client: Authenticated, CA-validated management client.
        timeout: Maximum elapsed seconds for read-only health observations.
    """
    deadline = time.monotonic() + timeout
    while True:
        try:
            return clock_readback(client)
        except Refusal:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


def admit_initialization(plan: dict, output: Path) -> tuple[dict, str]:
    """Admit original resource bindings and the fixed scope before credentials.

    Args:
        plan: Receipt-bound original ISO plan.
        output: Existing task-owned evidence directory.
    """
    admit_output(plan, output / "source.json", output / "bootstrap-runtime.json")
    fixture = admit_fixture(plan)
    network = ipaddress.ip_interface(fixture["peer_cidr"])
    peer_address = str(network.ip)
    requested = plan.get("fixture_initialization")
    if (plan.get("trust_model") != "trusted-host" or plan.get("interface") != "eth0"
            or plan.get("vmx_path") != fixture["appliance_vmx"]
            or plan.get("mac", "").replace("-", ":").lower() != fixture["appliance_mac"].lower()
            or bound_json(plan["appliance_ownership"]).get("phase") != "original-installation-vm-created"
            or requested != {"peer_time_address": peer_address, "resolver_address": peer_address,
                             "disable_dns_server": True, "disable_ntp_server": True}
            or any(type(requested.get(key)) is not bool for key in ("disable_dns_server", "disable_ntp_server"))
            or plan.get("current_address") != fixture["lease_address"]):
        raise Refusal("fixture_initialization_plan_invalid")
    addresses = [ipaddress.IPv4Address(plan[key]) for key in ("current_address", "baseline_address", "static_candidate_address")]
    if len(set(addresses)) != 3 or any(value not in network.network or value in (
        network.ip, network.network.network_address, network.network.broadcast_address,
    ) for value in addresses):
        raise Refusal("fixture_initialization_plan_invalid")
    return fixture, peer_address


def initialize(plan: dict, output: Path, password: str, *, execute: bool) -> dict:
    """Inspect or initialize one original ISO fixture before certificate cases.

    Args:
        plan: Current source- and receipt-bound trusted-host plan.
        output: Original task-owned evidence directory.
        password: Administrator credential confined to this bounded child.
        execute: Explicit permission to edit the three forms and submit one Apply.
    """
    fixture, peer_address = admit_initialization(plan, output)
    requested = plan.get("fixture_initialization")
    if execute and any((output / name).exists() for name in (
        "fixture-mutation-started.json", "fixture-apply-submitted.json", "fixture-initialization-result.json",
    )):
        raise Refusal("fixture_prior_execution_requires_reconciliation")
    result = {"schema": 1, "kind": "certificate-fixture-initialization", "source_commit": plan["source_commit"],
              "task_id": plan["task_id"], "success": False, "stage": "admission"}
    mutation = False
    terminal = True
    try:
        topology = inspect_trusted_host(plan)
        p = plan["peer_transport"]
        with watched_topology(plan, topology) as monitor, PinnedPeerTransport(
            p["host"], p["user"], p["ssh_public_key"], p["ssh_host_key"], p["private_subnet"],
            **({"authentication_mode": p["authentication_mode"]} if "authentication_mode" in p else {}),
        ) as peer:
            peer.topology_guard = monitor.check
            verify_peer_isolation(peer)
            addresses = [plan["current_address"], plan["baseline_address"], plan["static_candidate_address"]]
            verify_peer_tunnel_scope(peer, addresses)
            result["stage"] = "peer_time_verification"
            result["peer_time"] = verify_peer_time(peer, peer_address, addresses)
            leases = [line.split() for line in peer.command("cat /var/lib/misc/dnsmasq.leases").decode("ascii").splitlines()]
            matching = [row for row in leases if len(row) >= 3 and row[1].lower() == fixture["appliance_mac"].lower()]
            if len(matching) != 1 or matching[0][2] != plan["current_address"] or int(matching[0][0]) <= time.time():
                raise Refusal("fixture_original_lease_unproven")
            with PinnedApplianceSession(peer, plan["current_address"], plan["appliance_user"], password,
                                        plan["appliance_ssh_host_key"]) as appliance:
                facts = guest_identity(appliance, plan, password)
                mac = appliance.command("cat /sys/class/net/eth0/address").decode("ascii").strip().lower()
                if mac != fixture["appliance_mac"].lower():
                    raise Refusal("fixture_original_mac_changed")
                ca = appliance.command("cat /etc/atlaso/ca/root.crt")
                if hashlib.sha256(ca).hexdigest() != plan["ca_sha256"]:
                    raise Refusal("fixture_original_ca_changed")
            client = Client("https://" + tls_name(peer, plan["current_address"], plan["ca_path"]),
                            plan["ca_path"], peer=peer, connect_ip=plan["current_address"])
            client.login(plan.get("username", "admin"), password)
            _, review = client.json("/ui/management/appliance-apply/review")
            validate_review(review)
            original, _ = client.interface("eth0")
            original = saved_fields(original)
            if original["role"] != "management" or original["ipv4_method"] != "dhcp" or original["ipv6_enabled"]:
                raise Refusal("fixture_original_interface_invalid")
            prepared, public = prepare_forms(client, peer_address)
            result.update(stage="inspected_no_mutation", original_interface=original, original_forms=public,
                          original_tls=client.tls_identity(), guest_identity=facts)
            if not execute:
                result["success"] = True
                return result
            inspection = bound_json(plan["fixture_initialization_inspection"])
            if (inspection.get("kind") != "certificate-fixture-initialization"
                    or inspection.get("stage") != "inspected_no_mutation" or inspection.get("success") is not True
                    or inspection.get("task_id") != plan["task_id"]
                    or inspection.get("source_commit") != plan["source_commit"]
                    or inspection.get("guest_identity") != facts
                    or inspection.get("peer_time", {}).get("configuration_sha256") != result["peer_time"]["configuration_sha256"]
                    or inspection.get("original_forms") != public
                    or inspection.get("original_interface") != original):
                raise Refusal("fixture_inspected_state_changed")
            publish(output / "fixture-mutation-started.json", {**result, "requested_initialization": requested})
            mutation = True
            for page in ("dns", "settings", "ntp"):
                result["stage"] = "desired_" + page
                # Refresh the settings form after DNS is disabled: its resolver
                # control can switch from a preserved hidden input to a textarea.
                if page == "settings":
                    _, body = client.request("/ui/management/settings")
                    form = FixtureForm(body, "/ui/management/settings")
                    prepared[page] = (form.form_action, replace_fields(form.fields, {"external_dns_servers": peer_address}))
                path, fields = prepared[page]
                _, saved = client.json(path, fields, autosave=True)
                if saved.get("valid") is False:
                    raise Refusal("fixture_saved_settings_invalid")
            terminal = False
            result["stage"] = "apply_submission"
            job, status_path = submit_initialization(client)
            publish(output / "fixture-apply-submitted.json", {"job_id": job, "status_path": status_path})
            result.update(job_id=job, stage="apply_wait")
            task, _ = wait_task([client], status_path, plan.get("username", "admin"), password)
            terminal = True
            if task.get("status") != "succeeded":
                raise Refusal("fixture_initialization_apply_failed")
            client.login(plan.get("username", "admin"), password)
            clean_baseline(client)
            row, _ = client.interface("eth0")
            if saved_fields(row) != original:
                raise Refusal("fixture_management_interface_changed")
            dns = dns_baseline(client)
            if dns != {"external_dns_servers": [peer_address], "upstream_servers": [peer_address]}:
                raise Refusal("fixture_dns_readback_changed")
            result["clock"] = wait_clock(client)
            with PinnedApplianceSession(peer, plan["current_address"], plan["appliance_user"], password,
                                        plan["appliance_ssh_host_key"]) as appliance:
                after = guest_identity(appliance, plan, password)
                if any(after.get(key) != facts.get(key) for key in ("app_service", "helper_sha256", "wheel_sha256")):
                    raise Refusal("fixture_payload_or_routing_changed")
                # The shared probe independently refuses any routing intent.
                # First-run readers may normalize an absent default to false.
                result["routing_after_initialization"] = after["route_snapshot"]
                if hashlib.sha256(appliance.command("cat /etc/atlaso/ca/root.crt")).hexdigest() != plan["ca_sha256"]:
                    raise Refusal("fixture_original_ca_changed")
                peers = sudo_read(appliance, "ntpq -pn", password).decode("ascii").splitlines()
                if [line.split()[0] for line in peers if line.startswith("*")] != ["*" + peer_address]:
                    raise Refusal("fixture_clock_upstream_changed")
            result.update(stage="initialized_clean_baseline", success=True, dns=dns, final_tls=client.tls_identity())
        mutation = False
        return result
    except Exception:
        result.update(success=False, recovery=("preserve_unknown_apply_do_not_resubmit" if not terminal
                      else "preserve_and_reconcile") if mutation else "no_desired_mutation_started")
        raise
    finally:
        publish(output / ("fixture-initialization-result.json" if execute else "fixture-initialization-inspection.json"), result)


def main() -> int:
    """Use the canonical bounded credential bridge; never print exception text."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--output-directory", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    try:
        plan = json.loads(Path(args.plan).read_text())
        output = Path(args.output_directory).resolve(strict=True)
        admit_initialization(plan, output)
        if args.preflight_only:
            return 0
        password = os.environ.pop("ATLASO_NATIVE_ADMIN", "")
        if len(password) < 12 or password != password.strip():
            raise Refusal("fixture_bounded_credential_bridge_required")
        initialize(plan, output, password, execute=args.execute)
        return 0
    except Exception:  # noqa: BLE001 - Nothing from credentials, guest responses or parser errors may escape.
        print(json.dumps({"success": False, "reason": "fixture_initialization_refused"}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
