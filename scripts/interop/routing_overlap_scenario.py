"""Exercise native DHCP/SLAAC isolation through an admitted private fixture."""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import time
import urllib.parse
from collections.abc import Callable
from typing import Any

import paramiko

from scripts.interop.lifecycle_test import extract_csrf
from scripts.interop.routing_overlap import (
    AdmittedTopology,
    OverlapPrerequisiteError,
    verify_expired_sources,
    verify_route_selection,
    verify_source_rules,
)
from scripts.interop.routing_overlap_transport import FixtureHttpClient

FIELDS = (
    "role", "mode", "ipv4_method", "ip_cidr", "gateway", "ipv6_enabled",
    "ipv6_cidr", "ipv6_gateway", "mtu", "admin_state",
    "check_duplicate_ip_addresses", "access_management_ui_enabled",
)


class ApplyOutcomeUnknown(OverlapPrerequisiteError):
    """Preserve an uncertain Apply identity and prohibit competing restoration."""

# Fixed, read-only guest program. No files, services, route edits, or credentials.
SNAPSHOT_PROGRAM = '''
import json, subprocess, time, ipaddress
def command(args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=10)
    if p.returncode:
        raise RuntimeError("native observation failed")
    return json.loads(p.stdout)
def snapshot():
    links = command(["ip", "-j", "address", "show"])
    rules = {str(f): command(["ip", "-j", "-N", "-details", "-"+str(f), "rule", "show"])
             for f in (4,6)}
    routes = {str(f): [row for row in command(["ip", "-j", "-N", "-"+str(f),
                                               "route", "show", "table", "all"])
                       if str(row.get("table")) == "100"] for f in (4,6)}
    return {"links": links, "rules": rules, "management_routes": routes}
'''


def _command(program: str) -> str:
    """Encode a fixed guest program without shell interpolation.

    Args:
        program: Python source containing only admitted public observations.
    """
    encoded = base64.b64encode(program.encode()).decode()
    return f"python3 -c 'import base64;exec(base64.b64decode(\"{encoded}\"))'"


def _observe(connect: Callable[[], paramiko.SSHClient], program: str) -> dict[str, Any]:
    """Read bounded native evidence and close the dedicated pinned SSH session.

    Args:
        connect: Factory for a fresh admitted root SSH session.
        program: Fixed read-only guest program.
    """
    ssh = connect()
    try:
        _stdin, stdout, _stderr = ssh.exec_command(_command(program), timeout=45)
        raw = stdout.read(262145)
        if len(raw) > 262144 or stdout.channel.recv_exit_status() != 0:
            raise OverlapPrerequisiteError("native observation failed or exceeded its bound")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise OverlapPrerequisiteError("native observation is not an object")
        return value
    finally:
        ssh.close()


def _snapshot(connect: Callable[[], paramiko.SSHClient]) -> dict[str, Any]:
    """Capture both complete native rule families and interface addresses.

    Args:
        connect: Factory for a fresh pinned SSH session.
    """
    return _observe(connect, SNAPSHOT_PROGRAM + "\nprint(json.dumps(snapshot()))\n")


def _addresses(snapshot: dict[str, Any], interface: str) -> list[dict[str, Any]]:
    """Select exactly one admitted native interface observation.

    Args:
        snapshot: Complete native observation.
        interface: Independently admitted NIC name.
    """
    matches = [row for row in snapshot["links"] if row.get("ifname") == interface]
    if len(matches) != 1:
        raise OverlapPrerequisiteError("native interface identity is ambiguous")
    return list(matches[0].get("addr_info", []))


def _rules(snapshot: dict[str, Any]) -> dict[int, list[dict[str, Any]]]:
    """Normalize JSON family keys without changing rule evidence.

    Args:
        snapshot: Complete native observation.
    """
    return {int(key): value for key, value in snapshot["rules"].items()}


def _prove(snapshot: dict[str, Any], topology: AdmittedTopology) -> dict[str, int]:
    """Require acquired DHCP/SLAAC sources and their exact isolation rules.

    Args:
        snapshot: Complete native observation.
        topology: Independently admitted isolated fixture.
    """
    management = topology.link("appliance", 0).interface
    lab = topology.link("appliance", 1).interface
    dynamic = _addresses(snapshot, management)
    dhcp = [row for row in dynamic if row.get("local") == "192.0.2.10"
            and row.get("dynamic") is True and isinstance(row.get("valid_life_time"), int)
            and 0 < row["valid_life_time"] <= 180]
    slaac = [row for row in dynamic if row.get("family") == "inet6"
             and ipaddress.ip_address(row["local"]) in ipaddress.ip_network("fd74:1::/64")
             and row.get("dynamic") is True and not row.get("tentative") and not row.get("dadfailed")
             and isinstance(row.get("valid_life_time"), int) and 0 < row["valid_life_time"] <= 120]
    static = {row["local"] for row in _addresses(snapshot, lab)
              if not row.get("tentative") and not row.get("dadfailed")}
    if len(dhcp) != 1 or not slaac or not {"192.0.2.20", "fd74:1::20"} <= static:
        raise OverlapPrerequisiteError("native DHCP/SLAAC and static overlap are not ready")
    if not any(row.get("dst") == "default" and row.get("dev") == management
               and str(row.get("protocol")) in {"ra", "9"}
               for row in snapshot["management_routes"]["6"]):
        raise OverlapPrerequisiteError("native RA default is absent from management table")
    sources = {"192.0.2.10": 100, "192.0.2.20": 200, "fd74:1::20": 200}
    sources.update({row["local"]: 100 for row in slaac})
    return verify_source_rules(sources, _rules(snapshot))


def _ready(connect: Callable[[], paramiko.SSHClient], topology: AdmittedTopology) -> dict[str, Any]:
    """Wait within a fixed convergence bound for independently proven sources.

    Args:
        connect: Fresh pinned SSH factory.
        topology: Admitted interface identities.
    """
    deadline = time.monotonic() + 120
    while True:
        snapshot = _snapshot(connect)
        try:
            _prove(snapshot, topology)
            return snapshot
        except OverlapPrerequisiteError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _apply(
    client: FixtureHttpClient, units: list[str] | None = None, *, stage: str = "unspecified",
) -> dict[str, Any]:
    """Submit changed networking units through the ordinary audited global Apply.

    Args:
        client: Authenticated private pinned HTTPS client.
        units: Explicit reviewed initial units, or the scenario's networking units.
        stage: Fixed scenario stage label for safe failure diagnostics.
    """
    status, body, _headers = client.request("GET", "/ui/management/appliance-apply")
    if status != 200:
        raise OverlapPrerequisiteError("global Apply page unavailable")
    selected = units if units is not None else ["network", "firewall", "wan"]
    form = [("csrf", extract_csrf(body)), *(("selected_units", unit) for unit in selected)]
    try:
        status, body, _headers = client.request(
            "POST", "/ui/management/appliance-apply", form=form,
            headers={"Accept": "application/json"}, follow_redirects=False,
        )
    except Exception:  # noqa: BLE001 - submission may have reached the server; never retry or expose request details.
        raise ApplyOutcomeUnknown("Apply submission outcome unknown; preserve fixture and reconcile active task") from None
    if status != 202:
        if not 400 <= status < 500:
            raise ApplyOutcomeUnknown(f"Apply submission returned ambiguous HTTP {status}; preserve fixture")
        # The server's detail and preview can contain appliance configuration.
        # Retain only exact public validation labels and invalid unit IDs.
        reason = "unclassified"
        try:
            detail = json.loads(body).get("detail")
            known = {
                "Select at least one appliance change to submit.": "no-selection",
                "Resolve validation errors before submitting appliance changes.": "unit-validation",
                "Cannot verify applied forwarding intent; restore helper readiness before submitting appliance changes.":
                    "forwarding-intent",
            }
            if isinstance(detail, str):
                reason = known.get(detail, "unclassified")
        except (AttributeError, ValueError, TypeError):
            pass
        invalid: list[str] = []
        causes: list[str] = []
        try:
            review = client.json_request("GET", "/ui/management/appliance-apply/review")
            rows = review.get("units")
            if isinstance(rows, list):
                invalid = sorted({row["id"] for row in rows if isinstance(row, dict)
                                  and row.get("valid") is False and isinstance(row.get("id"), str)
                                  and re.fullmatch(r"[a-z_]+", row["id"])})
                settings = next((row for row in rows if isinstance(row, dict)
                                 and row.get("id") == "appliance_settings"), None)
                if settings is not None and isinstance(settings.get("validation_errors"), list):
                    labels = (
                        ("Local DNS registration requires", "local-dns-address"),
                        ("External DNS servers are required", "external-dns"),
                        ("Management UI HTTPS requires", "https-certificate"),
                        ("Web terminal interfaces are unavailable", "web-terminal-address"),
                        ("Web terminal access requires", "web-terminal-policy"),
                    )
                    causes = sorted({label for error in settings["validation_errors"]
                                     if isinstance(error, str) for prefix, label in labels
                                     if error.startswith(prefix)})
        except Exception:  # noqa: BLE001 - diagnostics never replace the known submission refusal.
            pass
        raise OverlapPrerequisiteError(
            f"global Apply submission failed at {stage} with HTTP {status} "
            f"({reason}; invalid_units={invalid}; known_causes={causes})"
        )
    try:
        submission = json.loads(body)
    except ValueError:
        raise ApplyOutcomeUnknown("accepted Apply returned an unreadable task identity; preserve fixture") from None
    job = submission.get("job_id") if isinstance(submission, dict) else None
    if not isinstance(job, str) or not re.fullmatch(r"job_[0-9a-f]+", job):
        raise ApplyOutcomeUnknown("accepted Apply did not return a canonical task identity; preserve fixture")
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            task = client.json_request("GET", f"/tasks/{job}/status").get("task", {})
        except Exception:  # noqa: BLE001 - reconcile this same known job until the bounded deadline without a second mutation.
            time.sleep(1)
            continue
        if task.get("status") == "succeeded":
            result = task.get("result")
            if not isinstance(result, dict) or not isinstance(result.get("units"), list):
                raise OverlapPrerequisiteError("native Apply lacks component execution evidence")
            dry_units = [unit.get("unit_id") for unit in result["units"]
                         if isinstance(unit, dict) and unit.get("dry_run") is True]
            if result.get("dry_run") and (not dry_units or {"network", "firewall", "wan"}.intersection(dry_units)):
                raise OverlapPrerequisiteError(f"native networking Apply unexpectedly reported dry-run ({dry_units})")
            return {"job_id": job, "status": "succeeded", "dry_run_units": dry_units}
        if task.get("status") in {"failed", "cancelled"}:
            result = task.get("result")
            units = result.get("units", []) if isinstance(result, dict) else []
            def safe_excerpt(command: dict[str, Any]) -> str:
                """Return bounded, credential-redacted WAN helper diagnostics.

                Args:
                    command: Command or command result under test.
                """
                stderr = str(command.get("stderr", ""))
                value = stderr if len(stderr) <= 768 else stderr[:512] + " ... " + stderr[-256:]
                for secret in (getattr(client, "diagnostic_secret", ""), client.bearer_token):
                    if secret:
                        value = value.replace(secret, "[redacted]")
                return re.sub(r"(?i)\b(password|token|secret)\s*[:=]\s*\S+", r"\1=[redacted]", value)

            failed_units = [
                {
                    "unit_id": unit.get("unit_id"),
                    "steps": [
                        {"index": index, "returncode": command.get("returncode"),
                         "stderr_markers": [marker for marker in (
                             "No such device", "No such file", "Invalid argument", "File exists",
                             "Network is unreachable", "Permission denied", "route-domain",
                             "routing-domain", "capacity", "timeout", "failed",
                         ) if marker.casefold() in str(command.get("stderr", "")).casefold()]}
                         | {"stderr_excerpt": safe_excerpt(command) if command.get("returncode") else ""}
                        for index, command in enumerate(unit.get("commands", [])) if isinstance(command, dict)
                    ],
                }
                for unit in units if isinstance(unit, dict) and unit.get("success") is False
            ] if isinstance(units, list) else []
            raise OverlapPrerequisiteError(
                f"native Apply {job} did not succeed (failed units: {failed_units})"
            )
        time.sleep(1)
    raise ApplyOutcomeUnknown(f"Apply {job} did not reach a known terminal state; preserve fixture before restoration")


def _clean(client: FixtureHttpClient) -> dict[str, Any]:
    """Require established applied state without pending units or an active task.

    Args:
        client: Pinned authenticated HTTPS client.
    """
    review = client.json_request("GET", "/ui/management/appliance-apply/review")
    status = client.json_request("GET", "/ui/management/appliance-apply/status?refresh=true")
    if (review.get("pending_count") != 0 or review.get("units") != []
            or review.get("initial_apply_required") is not False or review.get("active_task") is not None
            or status.get("pending_count") != 0 or status.get("locked") is not False
            or status.get("active_task") is not None):
        units = review.get("units")
        unit_count = len(units) if isinstance(units, list) else -1
        unit_ids = sorted({unit.get("id") for unit in units if isinstance(unit, dict)
                           and isinstance(unit.get("id"), str) and re.fullmatch(r"[a-z_]+", unit["id"])}) if isinstance(units, list) else []
        review_pending = review.get("pending_count")
        status_pending = status.get("pending_count")
        initial = review.get("initial_apply_required")
        locked = status.get("locked")
        raise OverlapPrerequisiteError(
            "scenario requires a clean established applied baseline "
            f"(review_pending={review_pending if type(review_pending) is int else 'invalid'}, "
            f"units={unit_count}, unit_ids={unit_ids}, "
            f"initial={initial if type(initial) is bool else 'invalid'}, "
            f"review_active={review.get('active_task') is not None}, "
            f"status_pending={status_pending if type(status_pending) is int else 'invalid'}, "
            f"locked={locked if type(locked) is bool else 'invalid'}, "
            f"status_active={status.get('active_task') is not None})"
        )
    return {"pending_count": 0, "active_task": None, "initial_apply_required": False}


def _settle_dependent_dns(client: FixtureHttpClient) -> dict[str, Any]:
    """Admit at most two reviewed DNS deltas before requiring stable clean reads.

    Args:
        client: Authenticated test client.
    """
    applications: list[dict[str, Any]] = []
    for attempt in range(3):
        try:
            # Two consecutive uncached reads are required. A single clean
            # projection can precede a dependent generated DNS delta.
            _clean(client)
            clean = _clean(client)
            return {"dependent_dnsmasq_applies": applications, "clean": clean}
        except OverlapPrerequisiteError as failure:
            if attempt == 2:
                raise OverlapPrerequisiteError(
                    f"dependent DNS baseline did not stabilize after {len(applications)} audited Applies: {failure}"
                ) from None
        # Deployment or the first Apply can change the generated DNS preview.
        # Admit only that reviewed, non-formatting unit for up to two Applies;
        # any other pending state remains a hard failure.
        pending = client.json_request("GET", "/ui/management/appliance-apply/review")
        status = client.json_request("GET", "/ui/management/appliance-apply/status?refresh=true")
        remaining = pending.get("units")
        if (pending.get("initial_apply_required") is not False or pending.get("active_task") is not None
                or pending.get("pending_count") != 1 or not isinstance(remaining, list)
                or len(remaining) != 1 or not isinstance(remaining[0], dict)
                or remaining[0].get("id") != "dnsmasq"
                or remaining[0].get("valid") is not True or remaining[0].get("format_volumes")
                or status.get("pending_count") != 1 or status.get("active_task") is not None
                or status.get("locked") is not False):
            valid = remaining[0].get("valid") if isinstance(remaining, list) and len(remaining) == 1 and isinstance(remaining[0], dict) else None
            raise OverlapPrerequisiteError(
                "scenario requires a clean established baseline; unadmitted dependent DNS state "
                f"(unit_valid={valid if type(valid) is bool else 'invalid'}, "
                f"review_pending={pending.get('pending_count') if type(pending.get('pending_count')) is int else 'invalid'}, "
                f"status_pending={status.get('pending_count') if type(status.get('pending_count')) is int else 'invalid'})"
            ) from None
        applications.append(_apply(client, ["dnsmasq"], stage="dependent-dns"))
    raise AssertionError("bounded DNS setup loop did not terminate")


def _setup(client: FixtureHttpClient) -> dict[str, Any]:
    """Establish the fresh owned clone's baseline through reviewed global Apply.

    Args:
        client: Pinned authenticated HTTPS client for the admitted fresh appliance.
    """
    review = client.json_request("GET", "/ui/management/appliance-apply/review")
    if review.get("initial_apply_required") is not True:
        settled = _settle_dependent_dns(client)
        return {"already_applied": settled.pop("clean"), **settled}
    units = review.get("units")
    if (review.get("active_task") is not None or not isinstance(units, list) or not units
            or any(unit.get("valid") is not True or unit.get("format_volumes") for unit in units)):
        raise OverlapPrerequisiteError("initial fixture Apply requires valid non-formatting units and no active task")
    ids = [unit.get("id") for unit in units]
    if any(not isinstance(unit, str) or not re.fullmatch(r"[a-z_]+", unit) for unit in ids):
        raise OverlapPrerequisiteError("initial fixture Apply unit identity is invalid")
    applied = _apply(client, ids, stage="baseline")
    return {"initial_apply": applied, **_settle_dependent_dns(client)}


def _expiry(
    connect: Callable[[], paramiko.SSHClient], server_action: Callable[[str], dict[str, Any]],
    *, kind: str, addresses: list[str], interface: str, wait_seconds: int,
) -> dict[str, Any]:
    """Observe actual expiry in guest memory while control addressing is withdrawn.

    Args:
        connect: Fresh pinned SSH factory.
        server_action: Admitted server controller.
        kind: DHCP or RA service selector.
        addresses: Previously proven acquired sources expected to expire.
        interface: Independently admitted management interface.
        wait_seconds: Finite lease or advertisement lifetime plus convergence grace.
    """
    if kind not in {"dhcp", "ra"} or not 1 <= wait_seconds <= 180 or not addresses:
        raise OverlapPrerequisiteError("invalid bounded expiry request")
    program = SNAPSHOT_PROGRAM + f'''
expected = {addresses!r}
interface = {interface!r}
print("ready", flush=True)
deadline = time.monotonic() + {wait_seconds + 20}
result = None
while time.monotonic() < deadline:
    current = snapshot()
    links = [r for r in current["links"] if r.get("ifname") == interface]
    if len(links) != 1:
        raise RuntimeError("interface identity missing")
    active = [r["local"] for r in links[0].get("addr_info", [])]
    rule_sources = [str(ipaddress.ip_interface(r["src"]).ip)
                    for rows in current["rules"].values() for r in rows if r.get("src", "all") != "all"]
    if not set(expected).intersection(active + rule_sources):
        result = current
        break
    time.sleep(1)
if result is None:
    raise RuntimeError("expiry not observed")
print(json.dumps(result), flush=True)
'''
    ssh = connect()
    try:
        _stdin, stdout, _stderr = ssh.exec_command(_command(program), timeout=wait_seconds + 50)
        if stdout.readline(16).strip() != "ready":
            raise OverlapPrerequisiteError("native expiry observer did not start")
        try:
            server_action(f"pause-{kind}")
            # A DHCP withdrawal can temporarily prevent delivery of SSH output.
            # Resume first, then require the original channel's real observation.
            time.sleep(wait_seconds)
        finally:
            server_action(f"resume-{kind}")
        raw = stdout.read(262145)
        if len(raw) > 262144 or stdout.channel.recv_exit_status() != 0:
            raise OverlapPrerequisiteError("native expiry observer failed")
        snapshot = json.loads(raw)
        if not isinstance(snapshot, dict):
            raise OverlapPrerequisiteError("expiry observer returned invalid evidence")
        verify_expired_sources(addresses, [row["local"] for row in _addresses(snapshot, interface)], _rules(snapshot))
        return snapshot
    finally:
        ssh.close()


def _lease(status: dict[str, Any], topology: AdmittedTopology) -> dict[str, Any]:
    """Require an actual finite lease bound to this appliance's original MAC.

    Args:
        status: Live admitted dnsmasq controller observation.
        topology: Independently admitted fixture identities.
    """
    matches = [row for row in status.get("leases", [])
               if row.get("mac") == topology.link("appliance", 0).mac
               and row.get("address") == "192.0.2.10" and row.get("unexpired") is True
               and type(row.get("expires_at")) is int and 0 < row["expires_at"] - time.time() <= 125]
    if len(matches) != 1:
        raise OverlapPrerequisiteError("actual bounded appliance DHCP lease is missing")
    return dict(matches[0])


def _restore(
    client: FixtureHttpClient, connect: Callable[[], paramiko.SSHClient],
    server_action: Callable[[str], dict[str, Any]], baseline: dict[str, dict[str, Any]],
    baseline_dns_servers: list[str],
) -> dict[str, Any]:
    """Attempt every safe recovery step and require applied baseline readback.

    Args:
        client: Pinned authenticated HTTPS client.
        connect: Fresh pinned SSH factory.
        server_action: Admitted private server controller.
        baseline: Supported desired fields captured before the first mutation.
        baseline_dns_servers: Original external resolver settings.
    """
    errors = []
    for action in ("resume-dhcp", "resume-ra"):
        try:
            server_action(action)
        except Exception:  # noqa: BLE001 - continue independent restoration without logging secret-bearing errors.
            errors.append(action)
    try:
        client.json_request("PATCH", "/api/v1/settings", json_body={"external_dns_servers": baseline_dns_servers})
    except Exception:  # noqa: BLE001 - continue independent interface recovery.
        errors.append("restore-dns")
    for name, desired in baseline.items():
        try:
            client.json_request("PATCH", f"/api/v1/interfaces/physical/{name}", json_body=desired)
        except Exception:  # noqa: BLE001 - attempt the other original interface before reporting bounded recovery failure.
            errors.append("restore-interface")
    if errors:
        raise OverlapPrerequisiteError("baseline restoration incomplete: " + ", ".join(errors))
    applied = _apply(client, stage="restoration")
    for name, desired in baseline.items():
        actual = client.json_request("GET", f"/api/v1/interfaces/physical/{name}")
        if any(actual[key] != value for key, value in desired.items()):
            raise OverlapPrerequisiteError("baseline desired state was not restored")
    native = _snapshot(connect)
    for name, desired in baseline.items():
        active = {row["local"] for row in _addresses(native, name) if row.get("scope") == "global"}
        expected = {str(ipaddress.ip_interface(desired[key]).ip)
                    for key in ("ip_cidr", "ipv6_cidr") if desired[key]}
        if desired["ipv4_method"] == "dhcp" and desired["admin_state"] == "up":
            expected.add("192.0.2.10")
        if desired["admin_state"] == "down" or desired["role"] == "unused":
            expected = set()
        if active != expected:
            raise OverlapPrerequisiteError("native baseline addresses were not restored")
    settled = _settle_dependent_dns(client)
    return {"apply": applied, "native": native, **settled}


def _same_address_native(
    connect: Callable[[], paramiko.SSHClient], topology: AdmittedTopology,
) -> dict[str, Any]:
    """Require current client-side lease proof without relabeling a static address.

    Args:
        connect: Fresh pinned root SSH factory for the measured installed helper.
        topology: Independently admitted original interface and MAC identities.
    """
    evidence = _observe(connect, SNAPSHOT_PROGRAM + '''
p = subprocess.run(["/opt/atlaso/bin/atlaso-helper", "network", "address-status", "--real"],
                   capture_output=True, text=True, timeout=20)
if p.returncode or len(p.stdout) > 262144:
    raise RuntimeError("native lease observation failed")
print(json.dumps({"address_status": json.loads(p.stdout), "native": snapshot()}))
''')
    native, status = evidence.get("native"), evidence.get("address_status")
    if not isinstance(native, dict) or not isinstance(status, dict) or status.get("complete") is not True:
        raise OverlapPrerequisiteError("complete native client lease observation is required")
    admitted = topology.link("appliance", 0)
    links = [row for row in status.get("links", []) if row.get("name") == admitted.interface]
    kernel = [row for row in native.get("links", []) if row.get("ifname") == admitted.interface]
    if len(links) != 1 or len(kernel) != 1:
        raise OverlapPrerequisiteError("native client lease interface is ambiguous")
    link, raw = links[0], kernel[0]
    if (link.get("configured") is not True or link.get("mac") != admitted.mac
            or raw.get("address") != admitted.mac or type(link.get("ifindex")) is not int
            or link["ifindex"] <= 0 or link["ifindex"] != raw.get("ifindex")):
        raise OverlapPrerequisiteError("native client lease interface identity or readiness differs")
    records = [row for row in link.get("addresses", []) if row.get("address") == "192.0.2.10"]
    addresses = [row for row in _addresses(native, admitted.interface) if row.get("local") == "192.0.2.10"]
    if (len(records) != 1 or records[0].get("cidr") != "192.0.2.10/24"
            or records[0].get("state") != "assigned" or records[0].get("dhcp4_lease") is not True
            or len(addresses) != 1 or addresses[0].get("prefixlen") != 24
            or addresses[0].get("tentative") or addresses[0].get("dadfailed")):
        raise OverlapPrerequisiteError("same-address activation lacks a current assigned native DHCP lease")
    verify_source_rules({"192.0.2.10": 100}, _rules(native))
    return evidence


def _same_address_lease(
    client: FixtureHttpClient, connect: Callable[[], paramiko.SSHClient],
    topology: AdmittedTopology, server_action: Callable[[str], dict[str, Any]],
    baseline_dns_servers: list[str],
) -> dict[str, Any]:
    """Prove DHCP activation against a live lease for the same static address.

    Args:
        client: Pinned authenticated HTTPS client.
        connect: Fresh pinned root SSH factory.
        topology: Independently admitted fixture identities.
        server_action: Admitted DHCP server status controller.
        baseline_dns_servers: Original external resolvers to restore before DHCP activation.
    """
    before = _lease(server_action("status"), topology)
    interface = topology.link("appliance", 0).interface
    path = f"/api/v1/interfaces/physical/{interface}"
    # The private DHCP offer intentionally has no DNS option. A static
    # management phase uses the owned peer's private-only resolver, then
    # restores the original resolver settings with the DHCP phase.
    client.json_request("PATCH", "/api/v1/settings", json_body={"external_dns_servers": ["192.0.2.1"]})
    client.json_request("PATCH", path, json_body={
        "ipv4_method": "static", "ip_cidr": "192.0.2.10/24", "gateway": "192.0.2.1",
    })
    static_apply = _apply(client, ["network", "firewall", "wan", "appliance_settings"], stage="same-address-static")
    static = _snapshot(connect)
    static_rows = [row for row in _addresses(static, interface) if row.get("local") == "192.0.2.10"]
    if len(static_rows) != 1 or static_rows[0].get("dynamic") is True:
        raise OverlapPrerequisiteError("same-address phase did not establish native static ownership")
    retained = _lease(server_action("status"), topology)
    # The same admitted MAC/address must still have a live server lease. Its
    # expiry may move when the DHCP client renews during static Apply.
    client.json_request("PATCH", path, json_body={"ipv4_method": "dhcp", "ip_cidr": None, "gateway": None})
    client.json_request("PATCH", "/api/v1/settings", json_body={"external_dns_servers": baseline_dns_servers})
    # Record the actual still-unexpired server lease immediately before activation.
    activation_lease = _lease(server_action("status"), topology)
    dhcp_apply = _apply(client, ["network", "firewall", "wan", "appliance_settings"], stage="same-address-dhcp")
    acquired = _same_address_native(connect, topology)
    desired = client.json_request("GET", path)
    if desired.get("ipv4_method") != "dhcp" or desired.get("ip_cidr"):
        raise OverlapPrerequisiteError("same-address activation did not retain desired DHCP")
    return {"original_lease": before, "static_phase_lease": retained,
            "lease_before_activation": activation_lease,
            "static_apply": static_apply, "static_native": static,
            "dhcp_apply": dhcp_apply, "acquired_native": acquired,
            "acquired_lease": _lease(server_action("status"), topology)}


def run_scenario(
    *, client: FixtureHttpClient, connect_appliance: Callable[[], paramiko.SSHClient],
    topology: AdmittedTopology, server_action: Callable[[str], dict[str, Any]],
    username: str, password: str,
) -> dict[str, Any]:
    """Apply overlapping domains, prove native lease lifecycles, and restore desired state.

    Args:
        client: Already admitted CA-validating private HTTPS transport.
        connect_appliance: Factory returning fresh pinned root SSH sessions.
        topology: Independently admitted original fixture topology.
        server_action: Bound controller for the admitted private DHCP/RA server.
        username: Appliance administrator username, never included in evidence.
        password: In-memory administrator password, never included in evidence.
    """
    status, body, _headers = client.request("GET", "/ui/management/login")
    if status != 200:
        raise OverlapPrerequisiteError("canonical UI login unavailable")
    status, _body, _headers = client.request(
        "POST", "/ui/management/login",
        form={"username": username, "password": password, "csrf": extract_csrf(body)}, follow_redirects=False,
    )
    if status not in {302, 303}:
        raise OverlapPrerequisiteError("canonical UI authentication failed")
    token = client.json_request(
        "POST", "/api/v1/auth/login?" + urllib.parse.urlencode({"username": username, "password": password}),
        json_body={"name": "private routing overlap lifecycle",
                   "scopes": ["admin:all", "read:dashboard", "read:interfaces", "write:interfaces"]},
    )
    client.bearer_token = token["raw_token"]
    client.diagnostic_secret = password
    unknown_outcome: ApplyOutcomeUnknown | None = None
    try:
        return _run_authenticated(client, connect_appliance, topology, server_action)
    except ApplyOutcomeUnknown as failure:
        unknown_outcome = failure
        raise
    finally:
        try:
            client.json_request("POST", f'/api/v1/api-tokens/{int(token["token"]["id"])}/revoke')
        except Exception:
            if unknown_outcome is None:
                raise
            # Keep exit-code 3 and the running fixture even if HTTPS is down.
            # Never attach the transport exception, which may contain secrets.
            unknown_outcome.add_note("Temporary token revocation failed; retain the fixture for recovery.")
        finally:
            client.bearer_token = ""
            client.diagnostic_secret = ""


def _run_authenticated(
    client: FixtureHttpClient, connect_appliance: Callable[[], paramiko.SSHClient],
    topology: AdmittedTopology, server_action: Callable[[str], dict[str, Any]],
) -> dict[str, Any]:
    """Run the scenario after authentication while preserving all baseline fields.

    Args:
        client: Pinned authenticated HTTPS client.
        connect_appliance: Fresh pinned root SSH factory.
        topology: Independently admitted fixture topology.
        server_action: Admitted private DHCP/RA server controller.
    """
    management, lab = (topology.link("appliance", index).interface for index in (0, 1))
    setup = _setup(client)
    clean = setup.get("clean", setup.get("already_applied"))
    if not isinstance(clean, dict) or clean.get("pending_count") != 0:
        raise OverlapPrerequisiteError("scenario setup did not produce a clean applied baseline")
    baseline = {
        name: {key: row[key] for key in FIELDS}
        for name in (management, lab)
        for row in [client.json_request("GET", f"/api/v1/interfaces/physical/{name}")]
    }
    settings = client.json_request("GET", "/api/v1/settings")
    baseline_dns_servers = settings.get("external_dns_servers")
    if (not isinstance(baseline_dns_servers, list)
            or any(not isinstance(server, str) for server in baseline_dns_servers)):
        raise OverlapPrerequisiteError("original external DNS settings are unavailable")
    evidence: dict[str, Any] = {"schema": 1, "setup": setup, "baseline": clean,
                                "covered": ["native-dhcp", "native-slaac", "expiry", "source-domains",
                                            "unbound-source-selection",
                                            "retained-static-same-address-lease"],
                                "not_covered": ["dad-conflict"]}
    if baseline[management]["ipv6_enabled"] or baseline[lab]["role"] != "unused":
        raise OverlapPrerequisiteError("scenario requires original IPv4 management and unused lab baseline")
    restore_allowed = True
    try:
        client.json_request("PATCH", f"/api/v1/interfaces/physical/{management}", json_body={
            "role": "management", "mode": "access", "ipv4_method": "dhcp", "ip_cidr": None,
            "gateway": None, "ipv6_enabled": True, "ipv6_cidr": None, "ipv6_gateway": None, "admin_state": "up",
        })
        client.json_request("PATCH", f"/api/v1/interfaces/physical/{lab}", json_body={
            "role": "access", "mode": "access", "ipv4_method": "static", "ip_cidr": "192.0.2.20/24",
            "gateway": None, "ipv6_enabled": True, "ipv6_cidr": "fd74:1::20/64", "ipv6_gateway": None,
            "admin_state": "up", "access_management_ui_enabled": False,
        })
        evidence["apply"] = _apply(client, stage="route-activation")
        initial = _ready(connect_appliance, topology)
        evidence["lease"] = _lease(server_action("status"), topology)
        sources = _prove(initial, topology)
        routes = {}
        for source, table in sources.items():
            interface = management if table == 100 else lab
            family = ipaddress.ip_address(source).version
            peer = "192.0.2.1" if family == 4 else "fd74:1::1"
            observed = _observe(connect_appliance, SNAPSHOT_PROGRAM +
                                f'\nprint(json.dumps({{"routes": command(["ip","-j","-N","-{family}",'
                                f'"route","get","{peer}","from","{source}"])}}))\n')["routes"]
            verify_route_selection(source, table, interface, observed)
            routes[source] = observed
        unbound = {}
        # The IPv4 default is available to an unbound query. The RA default is
        # intentionally isolated in table 100, so use a link-local destination
        # on the management device to check unbound IPv6 source selection.
        for family, peer in ((4, "203.0.113.1"), (6, "fe80::1")):
            device = f',"dev","{management}"' if family == 6 else ""
            observed = _observe(connect_appliance, SNAPSHOT_PROGRAM +
                                f'\nprint(json.dumps({{"routes": command(["ip","-j","-N","-{family}",'
                                f'"route","get","{peer}"{device}])}}))\n')["routes"]
            allowed = ({row["local"] for row in _addresses(initial, management)
                        if row.get("family") == "inet6" and row.get("scope") == "link"
                        and not row.get("tentative") and not row.get("dadfailed")}
                       if family == 6 else
                       {source for source, table in sources.items()
                        if table == 100 and ipaddress.ip_address(source).version == family})
            selected = (observed[0].get("prefsrc") or observed[0].get("from")
                        or observed[0].get("src")) if len(observed) == 1 else None
            if (len(observed) != 1 or observed[0].get("dev") != management
                    or selected not in allowed):
                detail = {"family": family, "dev": observed[0].get("dev") if observed else None,
                          "selected": selected, "allowed": sorted(allowed)}
                raise OverlapPrerequisiteError(f"unbound source selection cannot use management routing: {detail}")
            unbound[str(family)] = observed
        evidence["acquired"] = initial
        evidence["route_selection"] = routes
        evidence["unbound_route_selection"] = unbound
        slaac = [source for source, table in sources.items() if table == 100 and ":" in source]
        evidence["ra_expired"] = _expiry(connect_appliance, server_action, kind="ra", addresses=slaac,
                                          interface=management, wait_seconds=90)
        evidence["ra_reacquired"] = _ready(connect_appliance, topology)
        evidence["dhcp_expired"] = _expiry(connect_appliance, server_action, kind="dhcp", addresses=["192.0.2.10"],
                                            interface=management, wait_seconds=155)
        evidence["dhcp_reacquired"] = _ready(connect_appliance, topology)
        evidence["same_address_lease"] = _same_address_lease(
            client, connect_appliance, topology, server_action, baseline_dns_servers,
        )
    except ApplyOutcomeUnknown:
        restore_allowed = False
        raise
    finally:
        if restore_allowed:
            evidence["restored"] = _restore(
                client, connect_appliance, server_action, baseline, baseline_dns_servers,
            )
    return evidence
