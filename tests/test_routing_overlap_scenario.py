"""Keep native routing evidence and recovery gates fail-closed."""

import copy
import io
import json
import subprocess
import time
from types import SimpleNamespace

import pytest

from scripts.interop import routing_overlap_scenario as scenario
from scripts.interop.routing_overlap import (
    AdmittedTopology,
    FixtureLink,
    FixtureOwner,
    OverlapPrerequisiteError,
)


def test_native_snapshot_accepts_empty_management_route_table(monkeypatch):
    """A missing table 100 remains an empty native route inventory.

    Args:
        monkeypatch: Reversible native iproute observation boundary.
    """
    def run(args, **_kwargs):
        """Return numeric JSON from the table-all query without mutating routes.

        Args:
            args: Command arguments under test.
            **_kwargs: Unused keyword arguments accepted by the test double.
        """
        if "route" in args:
            assert args[-2:] == ["table", "all"]
            rows = [{"dst": "default", "table": "main"}]
            if "-4" in args:
                rows.append({"dst": "192.0.2.0/24", "table": 100})
        else:
            rows = []
        return subprocess.CompletedProcess(args, 0, json.dumps(rows), "")

    monkeypatch.setattr(subprocess, "run", run)
    namespace = {}
    exec(scenario.SNAPSHOT_PROGRAM, namespace)
    result = namespace["snapshot"]()
    assert result["management_routes"] == {"4": [{"dst": "192.0.2.0/24", "table": 100}], "6": []}


@pytest.mark.parametrize(("stderr", "reason"), [
    ("RTNETLINK answers: Network is unreachable", "network-unreachable"),
    ("Error: Invalid argument", "invalid-argument"),
    ("private guest diagnostic", "other"),
])
def test_native_observation_failure_reports_only_whitelisted_reason(monkeypatch, stderr, reason):
    """Classify a failed read-only route query without copying guest stderr."""
    monkeypatch.setattr(subprocess, "run", lambda args, **kwargs:
                        subprocess.CompletedProcess(args, 2, "", stderr))
    namespace = {}
    exec(scenario.SNAPSHOT_PROGRAM, namespace)
    with pytest.raises(RuntimeError, match=f"native observation failed: {reason}") as failure:
        namespace["command"](["ip", "-6", "route", "get", "fe80::1"])
    assert stderr not in str(failure.value)


@pytest.fixture
def topology():
    """Supply already admitted independent fixture interface identities."""
    return AdmittedTopology(
        FixtureOwner("task", "mdaneri/Atlaso", "a" * 40, 868, "E:/owned"), "management", "lab",
        (FixtureLink("appliance", 0, "eth0", "00:50:56:00:00:10", "pvn", "management"),
         FixtureLink("appliance", 1, "eth1", "00:50:56:00:00:20", "pvn", "lab")),
        "192.0.2.0/24", "fd74:1::/64",
    )


@pytest.fixture
def native():
    """Use native iproute JSON spellings, including numeric protocol/action strings."""
    sources = {"192.0.2.10": 100, "fd74:1::abcd": 100, "192.0.2.20": 200, "fd74:1::20": 200}
    rules = {"4": [], "6": []}
    for index, (source, table) in enumerate(sources.items()):
        family = "6" if ":" in source else "4"
        shared = {"src": source, "iif": "lo", "protocol": "2"}
        rules[family].extend([{**shared, "priority": 5000 + index * 2, "table": table},
                              {**shared, "priority": 5001 + index * 2, "action": "7"}])
    for family in ("4", "6"):
        prefixes = (("0.0.0.0", 32), ("169.254.0.0", 16), ("127.0.0.0", 8)) if family == "4" else (
            ("::", 128), ("fe80::", 10), ("::1", 128))
        rules[family].extend({"src": source, "srclen": length, "iif": "lo", "protocol": "2",
                              "priority": 6000 + offset, "table": "254"}
                             for offset, (source, length) in enumerate(prefixes))
        destination = ("169.254.0.0", 16) if family == "4" else ("fe80::", 10)
        rules[family].append({"dst": destination[0], "dstlen": destination[1], "iif": "lo",
                              "protocol": "2", "priority": 6003, "table": "254"})
        rules[family].append({"src": "all", "srclen": 0, "iif": "lo", "protocol": "2",
                              "priority": 6004, "action": "7"})
    return {
        "links": [{"ifname": "eth0", "addr_info": [
            {"family": "inet", "local": "192.0.2.10", "dynamic": True, "valid_life_time": 100, "scope": "global"},
            {"family": "inet6", "local": "fd74:1::abcd", "dynamic": True, "valid_life_time": 60, "scope": "global"}]},
            {"ifname": "eth1", "addr_info": [{"local": "192.0.2.20", "scope": "global"},
                                               {"local": "fd74:1::20", "scope": "global"}]}],
        "rules": rules,
        "management_routes": {"4": [], "6": [{"dst": "default", "dev": "eth0", "protocol": "9"}]},
    }


def test_native_proof_requires_acquired_sources_and_ra_default(native, topology):
    """Accept observed dynamic sources only with exact guards and a native RA default.

    Args:
        native: Complete iproute observations.
        topology: Admitted fixture identities.
    """
    assert scenario._prove(native, topology)["fd74:1::abcd"] == 100
    native["management_routes"]["6"] = []
    with pytest.raises(OverlapPrerequisiteError, match="RA default"):
        scenario._prove(native, topology)


@pytest.mark.parametrize("field,value", [("dynamic", False), ("valid_life_time", 0),
                                        ("valid_life_time", 4294967295), ("tentative", True), ("dadfailed", True)])
def test_slaac_proof_rejects_static_expired_or_unusable_address(native, topology, field, value):
    """Do not count configured or unusable IPv6 addresses as native acquisition.

    Args:
        native: Complete iproute observations.
        topology: Admitted fixture identities.
        field: Native address property under test.
        value: Invalid property value.
    """
    native["links"][0]["addr_info"][1][field] = value
    with pytest.raises(OverlapPrerequisiteError, match="not ready"):
        scenario._prove(native, topology)


def test_source_proof_rejects_foreign_lookup(native, topology):
    """A same-prefix main-table lookup must not satisfy isolated source proof.

    Args:
        native: Complete iproute observations.
        topology: Admitted fixture identities.
    """
    native["rules"]["4"][0]["table"] = 254
    with pytest.raises(OverlapPrerequisiteError, match="lacks exact"):
        scenario._prove(native, topology)


def test_lease_requires_actual_finite_original_mac(topology):
    """Reject expired leases and another appliance's otherwise identical address.

    Args:
        topology: Admitted fixture identities.
    """
    row = {"mac": topology.link("appliance", 0).mac, "address": "192.0.2.10",
           "unexpired": True, "expires_at": int(time.time()) + 100}
    assert scenario._lease({"leases": [row]}, topology) == row
    for bad in ({**row, "mac": "00:50:56:00:00:ff"}, {**row, "expires_at": 0},
                {**row, "unexpired": False}, {**row, "expires_at": int(time.time()) + 500}):
        with pytest.raises(OverlapPrerequisiteError, match="actual bounded"):
            scenario._lease({"leases": [bad]}, topology)


class FakeClient:
    """Capture ordinary authenticated API operations without networking."""

    def __init__(self):
        """Initialize sanitized synthetic desired state and operation history."""
        shared = {"mode": "access", "ipv4_method": "static", "gateway": None, "ipv6_enabled": False,
                  "ipv6_cidr": None, "ipv6_gateway": None, "mtu": 1500,
                  "check_duplicate_ip_addresses": True, "access_management_ui_enabled": False}
        self.rows = {"eth0": {**shared, "role": "management", "ip_cidr": "192.0.2.10/24", "admin_state": "up"},
                     "eth1": {**shared, "role": "unused", "ip_cidr": None, "admin_state": "down"}}
        self.calls = []
        self.bearer_token = ""
        self.external_dns_servers = []

    def json_request(self, method, path, *, json_body=None):
        """Return synthetic API data and capture supported desired mutations.

        Args:
            method: HTTP method.
            path: Canonical origin-relative path.
            json_body: Supported mutation fields.
        """
        self.calls.append((method, path, copy.deepcopy(json_body)))
        if path.startswith("/api/v1/auth/login?"):
            return {"raw_token": "synthetic", "token": {"id": 1}}
        if path.endswith("/revoke"):
            return {}
        if path.startswith("/ui/management/appliance-apply/"):
            return {"units": [], "pending_count": 0, "initial_apply_required": False,
                    "active_task": None, "locked": False}
        if path == "/api/v1/settings":
            if method == "PATCH":
                self.external_dns_servers = list(json_body["external_dns_servers"])
            return {"external_dns_servers": list(self.external_dns_servers)}
        name = path.rsplit("/", 1)[1]
        if method == "PATCH":
            self.rows[name].update(json_body)
        return copy.deepcopy(self.rows[name])

    def request(self, method, path, **kwargs):
        """Return canonical synthetic login pages without echoing credentials.

        Args:
            method: HTTP method.
            path: Canonical origin-relative path.
            **kwargs: In-memory request options.
        """
        return (200, '<input name="csrf" value="synthetic">', {}) if method == "GET" else (303, "", {})


def test_failed_acquisition_restores_both_interfaces_and_revokes(monkeypatch, topology):
    """A failed native proof still restores and applies every captured desired field.

    Args:
        monkeypatch: Isolate native and apply boundaries.
        topology: Admitted fixture identities.
    """
    client = FakeClient()
    before = copy.deepcopy(client.rows)
    actions, applies = [], []

    def fail_ready(connect, admitted):
        """Simulate actual acquisition failure after desired mutation.

        Args:
            connect: Unused injected SSH factory.
            admitted: Admitted fixture identity.
        """
        raise OverlapPrerequisiteError("native acquisition failed")

    monkeypatch.setattr(scenario, "_ready", fail_ready)
    monkeypatch.setattr(scenario, "_apply", lambda current, units=None, **kwargs: applies.append(copy.deepcopy(current.rows)) or {"status": "succeeded"})
    monkeypatch.setattr(scenario, "_snapshot", lambda connect: {"links": [
        {"ifname": "eth0", "addr_info": [{"local": "192.0.2.10", "scope": "global"}]},
        {"ifname": "eth1", "addr_info": []}]})
    with pytest.raises(OverlapPrerequisiteError, match="initial-native-readiness: native acquisition failed"):
        scenario.run_scenario(client=client, connect_appliance=lambda: None, topology=topology,
                              server_action=lambda action: actions.append(action) or {}, username="test", password="synthetic")
    assert client.rows == before
    assert client.external_dns_servers == []
    assert len(applies) == 2 and applies[-1] == before
    assert actions == ["resume-dhcp", "resume-ra"]
    assert client.calls[-1][:2] == ("POST", "/api/v1/api-tokens/1/revoke")
    assert client.bearer_token == ""


def test_restore_attempts_both_interfaces_after_server_failure(monkeypatch):
    """One recovery failure must not skip independent restoration attempts.

    Args:
        monkeypatch: Isolate native and apply boundaries.
    """
    client = FakeClient()
    baseline = copy.deepcopy(client.rows)
    client.external_dns_servers = ["192.0.2.1"]
    actions = []

    def server(action):
        """Fail the first server action but allow the second.

        Args:
            action: Exact admitted controller action.
        """
        actions.append(action)
        if action == "resume-dhcp":
            raise RuntimeError("synthetic failure")
        return {}

    with pytest.raises(OverlapPrerequisiteError, match="resume-dhcp"):
        scenario._restore(client, lambda: None, server, baseline, [])
    assert actions == ["resume-dhcp", "resume-ra"]
    assert client.external_dns_servers == []
    assert [path for method, path, _body in client.calls if method == "PATCH"] == [
        "/api/v1/settings", "/api/v1/interfaces/physical/eth0", "/api/v1/interfaces/physical/eth1"]


def test_expiry_resumes_server_and_closes_ssh_when_pause_fails(monkeypatch):
    """Never leave DHCP withdrawn or a pinned session open after controller failure.

    Args:
        monkeypatch: Isolate sleeping from the failure path.
    """
    closed, actions = [], []
    ssh = SimpleNamespace(exec_command=lambda *args, **kwargs: (None, io.StringIO("ready\n"), None),
                          close=lambda: closed.append(True))

    def server(action):
        """Raise during pause after recording the requested action.

        Args:
            action: Exact admitted server action.
        """
        actions.append(action)
        if action == "pause-dhcp":
            raise RuntimeError("pause failed")
        return {}

    with pytest.raises(RuntimeError, match="pause failed"):
        scenario._expiry(lambda: ssh, server, kind="dhcp", addresses=["192.0.2.10"], interface="eth0", wait_seconds=155)
    assert actions == ["pause-dhcp", "resume-dhcp"] and closed == [True]


@pytest.mark.parametrize("field,value", [("pending_count", 1), ("initial_apply_required", True),
                                        ("active_task", {"id": "job_abc"}), ("locked", True)])
def test_dirty_baseline_blocks_interface_mutation(monkeypatch, topology, field, value):
    """Never apply unrelated pending work or overlap another active Apply.

    Args:
        monkeypatch: Isolate native operations.
        topology: Admitted fixture identities.
        field: Dirty baseline field.
        value: Non-clean observation.
    """
    client = FakeClient()
    original = client.json_request

    def dirty(method, path, **kwargs):
        """Substitute one dirty baseline field.

        Args:
            method: HTTP method.
            path: Canonical path.
            **kwargs: Supported request options.
        """
        result = original(method, path, **kwargs)
        if path.startswith("/ui/management/appliance-apply/"):
            result[field] = value
        return result

    monkeypatch.setattr(client, "json_request", dirty)
    with pytest.raises(OverlapPrerequisiteError, match="clean established|initial fixture Apply"):
        scenario._run_authenticated(client, lambda: None, topology, lambda action: {})
    assert not any(method == "PATCH" for method, _path, _body in client.calls)


def test_unknown_apply_outcome_does_not_start_restoration(monkeypatch, topology):
    """Retain the original job identity without a competing second mutation.

    Args:
        monkeypatch: Substitute an uncertain Apply boundary.
        topology: Admitted fixture identities.
    """
    client = FakeClient()

    def uncertain(current, **kwargs):
        """Report the accepted task whose terminal status is unknown.

        Args:
            current: Authenticated client.
            **kwargs: Value used by this operation.
        """
        raise scenario.ApplyOutcomeUnknown("Apply job_abc still running")

    monkeypatch.setattr(scenario, "_apply", uncertain)
    with pytest.raises(scenario.ApplyOutcomeUnknown, match="job_abc"):
        scenario._run_authenticated(client, lambda: None, topology, lambda action: {})
    assert len([call for call in client.calls if call[0] == "PATCH"]) == 2
    assert client.rows["eth0"]["ipv4_method"] == "dhcp"


def test_failed_restoration_requires_fixture_preservation(monkeypatch, topology):
    """A definite failed baseline Apply still needs running DHCP and RA peers."""
    client = FakeClient()

    def failed_apply(_client, **_kwargs):
        raise OverlapPrerequisiteError("candidate Apply failed")

    def failed_restoration(*_args):
        raise OverlapPrerequisiteError("baseline Apply failed")

    monkeypatch.setattr(scenario, "_apply", failed_apply)
    monkeypatch.setattr(scenario, "_restore", failed_restoration)
    with pytest.raises(scenario.RestorationIncomplete, match="restoration: baseline Apply failed"):
        scenario._run_authenticated(client, lambda: None, topology, lambda action: {})


def test_apply_deadline_preserves_identity(monkeypatch):
    """An accepted but still-running master task is explicitly indeterminate.

    Args:
        monkeypatch: Bound the fake job clock and HTTP transport.
    """
    client = FakeClient()
    clock = iter((0, 1, 181))
    monkeypatch.setattr(scenario.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(scenario.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(client, "request", lambda method, path, **kwargs:
                        (200, '<input name="csrf" value="synthetic">', {}) if method == "GET"
                        else (202, '{"job_id":"job_abc"}', {}))
    monkeypatch.setattr(client, "json_request", lambda method, path: {"task": {"status": "running"}})
    with pytest.raises(scenario.ApplyOutcomeUnknown, match="job_abc"):
        scenario._apply(client)


@pytest.mark.parametrize("dry_unit,accepted", [("dns", True), ("network", False), ("wan", False)])
def test_apply_requires_real_networking_units(monkeypatch, dry_unit, accepted):
    """An unrelated simulated unit must not mask real network execution.

    Args:
        monkeypatch: Replace the bounded task transport.
        dry_unit: Component reported as simulated by the appliance.
        accepted: Whether native networking evidence remains valid.
    """
    client = FakeClient()
    monkeypatch.setattr(client, "request", lambda method, path, **kwargs:
                        (200, '<input name="csrf" value="synthetic">', {}) if method == "GET"
                        else (202, '{"job_id":"job_abc"}', {}))
    monkeypatch.setattr(client, "json_request", lambda method, path: {"task": {
        "status": "succeeded", "result": {"dry_run": True, "units": [
            {"unit_id": "network", "dry_run": dry_unit == "network"},
            {"unit_id": "wan", "dry_run": dry_unit == "wan"},
            {"unit_id": "dns", "dry_run": dry_unit == "dns"},
        ]}}})
    if accepted:
        assert scenario._apply(client)["dry_run_units"] == [dry_unit]
    else:
        with pytest.raises(OverlapPrerequisiteError, match="networking Apply unexpectedly reported dry-run"):
            scenario._apply(client)


@pytest.mark.parametrize("status,body", [(202, "null"), (202, '{"job_id":null}'), (202, "[]"),
                                       (202, "not-json"), (503, "unavailable")])
def test_ambiguous_submission_prohibits_recovery_mutation(monkeypatch, topology, status, body):
    """Malformed accepted responses and server errors cannot establish a rejected job.

    Args:
        monkeypatch: Substitute the ambiguous transport result.
        topology: Admitted fixture identities.
        status: HTTP submission status.
        body: Non-authoritative response content.
    """
    client = FakeClient()
    monkeypatch.setattr(client, "request", lambda method, path, **kwargs:
                        (200, '<input name="csrf" value="synthetic">', {}) if method == "GET"
                        else (status, body, {}))
    with pytest.raises(scenario.ApplyOutcomeUnknown):
        scenario._run_authenticated(client, lambda: None, topology, lambda action: {})
    assert len([call for call in client.calls if call[0] == "PATCH"]) == 2


def test_rejected_apply_reports_only_bounded_validation_identity(monkeypatch):
    """A known 422 exposes the invalid unit without echoing the server preview.

    Args:
        monkeypatch: Pytest fixture replacing external dependencies.
    """
    client = FakeClient()
    monkeypatch.setattr(client, "request", lambda method, path, **kwargs:
                        (200, '<input name="csrf" value="synthetic">', {}) if method == "GET" else
                        (422, json.dumps({"detail": "Resolve validation errors before submitting appliance changes.",
                                          "preview": "private appliance address"}), {}))
    monkeypatch.setattr(client, "json_request", lambda method, path: {
        "units": [{"id": "wan", "valid": False, "validation_errors": ["private appliance address"]},
                  {"id": "appliance_settings", "valid": False,
                   "validation_errors": ["Web terminal interfaces are unavailable or have no address: private"]}]})
    with pytest.raises(OverlapPrerequisiteError, match="unit-validation; invalid_units=\\['appliance_settings', 'wan'\\]") as error:
        scenario._apply(client)
    assert "private appliance address" not in str(error.value)
    assert "known_causes=['web-terminal-address']" in str(error.value)


def test_initial_setup_uses_reviewed_nonformatting_units(monkeypatch):
    """Initial setup uses the ordinary Apply then requires clean applied readback.

    Args:
        monkeypatch: Supply a fresh owned fixture review and successful Apply.
    """
    client, selected = FakeClient(), []
    monkeypatch.setattr(client, "json_request", lambda method, path: {
        "initial_apply_required": True, "active_task": None,
        "units": [{"id": "network", "valid": True, "format_volumes": []}],
    })
    monkeypatch.setattr(scenario, "_apply", lambda current, units, **kwargs: selected.extend(units) or {"job_id": "job_abc"})
    monkeypatch.setattr(scenario, "_clean", lambda current: {"pending_count": 0})
    assert scenario._setup(client)["initial_apply"]["job_id"] == "job_abc"
    assert selected == ["network"]


def test_initial_setup_applies_only_one_reviewed_dependent_dnsmasq_unit(monkeypatch):
    """An initial Apply may expose one generated DNS change, then must become clean.

    Args:
        monkeypatch: Pytest fixture replacing external dependencies.
    """
    client = FakeClient()
    calls = []
    reviews = iter([
        {"initial_apply_required": True, "active_task": None,
         "units": [{"id": "network", "valid": True, "format_volumes": []}]},
        {"initial_apply_required": False, "active_task": None, "pending_count": 1,
         "units": [{"id": "dnsmasq", "valid": True, "format_volumes": []}]},
    ])
    monkeypatch.setattr(client, "json_request", lambda method, path: (
        next(reviews) if path.endswith("/review") else
        {"pending_count": 1, "active_task": None, "locked": False}))
    monkeypatch.setattr(scenario, "_apply", lambda current, units, **kwargs: calls.append(units) or {"job_id": "job_abc"})
    clean_calls = iter([scenario.OverlapPrerequisiteError("pending"),
                        {"pending_count": 0}, {"pending_count": 0}])

    def clean(_client):
        """Return a clean desired-state projection for this test.

        Args:
            _client: Unused client supplied by the scenario.
        """
        outcome = next(clean_calls)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(scenario, "_clean", clean)
    result = scenario._setup(client)
    assert calls == [["network"], ["dnsmasq"]]
    assert result["clean"] == {"pending_count": 0}


def test_established_setup_applies_only_reviewed_dependent_dnsmasq_unit(monkeypatch):
    """A deployed baseline may have one DNS delta before the scenario starts.

    Args:
        monkeypatch: Pytest fixture replacing external dependencies.
    """
    client = FakeClient()
    calls = []
    review = {"initial_apply_required": False, "active_task": None, "pending_count": 1,
              "units": [{"id": "dnsmasq", "valid": True, "format_volumes": []}]}
    monkeypatch.setattr(client, "json_request", lambda method, path: review if path.endswith("/review") else
                        {"pending_count": 1, "active_task": None, "locked": False})
    monkeypatch.setattr(scenario, "_apply", lambda current, units, **kwargs: calls.append(units) or {"job_id": "job_dns"})
    outcomes = iter([scenario.OverlapPrerequisiteError("pending"),
                     {"pending_count": 0}, {"pending_count": 0}])

    def clean(_client):
        """Return a clean desired-state projection for this test.

        Args:
            _client: Unused client supplied by the scenario.
        """
        outcome = next(outcomes)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(scenario, "_clean", clean)
    result = scenario._setup(client)
    assert calls == [["dnsmasq"]]
    assert result == {"already_applied": {"pending_count": 0},
                      "dependent_dnsmasq_applies": [{"job_id": "job_dns"}]}


def test_established_setup_rechecks_clean_projection_before_acceptance(monkeypatch):
    """A clean first read followed by DNS drift still needs audited Apply.

    Args:
        monkeypatch: Pytest fixture replacing external dependencies.
    """
    client = FakeClient()
    review = {"initial_apply_required": False, "active_task": None, "pending_count": 1,
              "units": [{"id": "dnsmasq", "valid": True, "format_volumes": []}]}
    monkeypatch.setattr(client, "json_request", lambda method, path: review if path.endswith("/review") else
                        {"pending_count": 1, "active_task": None, "locked": False})
    applies = []
    monkeypatch.setattr(scenario, "_apply", lambda current, units, **kwargs: applies.append(units) or {"job_id": "job_dns"})
    outcomes = iter([{"pending_count": 0}, scenario.OverlapPrerequisiteError("pending"),
                     {"pending_count": 0}, {"pending_count": 0}])

    def clean(_client):
        """Return a clean desired-state projection for this test.

        Args:
            _client: Unused client supplied by the scenario.
        """
        outcome = next(outcomes)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(scenario, "_clean", clean)
    assert scenario._setup(client)["already_applied"] == {"pending_count": 0}
    assert applies == [["dnsmasq"]]


@pytest.mark.parametrize("renewed", [False, True])
def test_same_address_requires_live_server_lease(monkeypatch, topology, native, renewed):
    """A renewed live lease plus native static then dynamic ownership proves the case.

    Args:
        monkeypatch: Substitute native observations and ordinary Apply.
        topology: Admitted original fixture identities.
        native: Acquired address and rule evidence.
        renewed: Whether the server lease renews during the static phase.
    """
    client, applies = FakeClient(), []
    lease = {"mac": topology.link("appliance", 0).mac, "address": "192.0.2.10",
             "expires_at": int(time.time()) + 100, "unexpired": True}
    current = {**lease, "expires_at": lease["expires_at"] + int(renewed)}
    observations = iter([lease, current, current, current])
    static = copy.deepcopy(native)
    static["links"][0]["addr_info"][0].pop("dynamic")
    monkeypatch.setattr(scenario, "_snapshot", lambda connect: static)
    monkeypatch.setattr(scenario, "_same_address_native", lambda connect, admitted: {"native": native})
    monkeypatch.setattr(scenario, "_apply", lambda current, units=None, **kwargs: applies.append(copy.deepcopy(current.rows)) or {"status": "succeeded"})
    result = scenario._same_address_lease(client, lambda: None, topology, lambda action: {"leases": [next(observations)]}, [])
    assert result["original_lease"] == lease
    assert result["static_phase_lease"] == current
    assert result["lease_before_activation"] == current
    assert [rows["eth0"]["ipv4_method"] for rows in applies] == ["static", "dhcp"]
    assert client.external_dns_servers == []
    assert [body["external_dns_servers"] for method, path, body in client.calls
            if method == "PATCH" and path == "/api/v1/settings"] == [["192.0.2.1"], []]


@pytest.fixture
def lease_native(native, topology):
    """Keep the installed helper's client lease verdict and raw kernel state distinct.

    Args:
        native: Complete kernel address and rule observations.
        topology: Independently admitted original NIC identity.
    """
    raw = native["links"][0]
    raw.update(ifindex=2, address=topology.link("appliance", 0).mac)
    raw["addr_info"][0].update(prefixlen=24, valid_life_time=4294967295)
    raw["addr_info"][0].pop("dynamic")
    return {"native": native, "address_status": {"complete": True, "links": [{
        "name": "eth0", "ifindex": 2, "mac": raw["address"], "configured": True,
        "addresses": [{"address": "192.0.2.10", "cidr": "192.0.2.10/24", "source": "static",
                       "state": "assigned", "dhcp4_lease": True}],
    }]}}


@pytest.mark.parametrize("source", ["static", "DHCPv4"])
def test_same_address_accepts_current_native_client_lease(monkeypatch, topology, lease_native, source):
    """A measured helper can prove current DHCP ownership without the kernel dynamic flag.

    Args:
        monkeypatch: Replace only the bounded guest observation boundary.
        topology: Independently admitted original NIC identity.
        lease_native: Helper proof plus unchanged raw kernel evidence.
        source: Networkd's truthful classification of the address object.
    """
    programs = []
    lease_native["address_status"]["links"][0]["addresses"][0]["source"] = source

    def observe(connect, program):
        """Capture the fixed read-only command and return independently generated evidence.

        Args:
            connect: Unused pinned SSH factory.
            program: Fixed guest observation source.
        """
        programs.append(program)
        return lease_native

    monkeypatch.setattr(scenario, "_observe", observe)
    assert scenario._same_address_native(lambda: None, topology) is lease_native
    assert '"network", "address-status", "--real"' in programs[0]
    assert '"apply"' not in programs[0]
    with pytest.raises(OverlapPrerequisiteError, match="not ready"):
        scenario._prove(lease_native["native"], topology)


@pytest.mark.parametrize("invalid", ["stale-lease", "incomplete", "wrong-mac", "wrong-index", "configuring",
                                    "wrong-prefix", "conflict", "kernel-conflict", "missing-guard"])
def test_same_address_rejects_missing_or_mismatched_client_proof(monkeypatch, topology, lease_native, invalid):
    """A server lease or retained address cannot substitute for live identity-bound helper proof.

    Args:
        monkeypatch: Replace the bounded read-only native observation.
        topology: Independently admitted original NIC identity.
        lease_native: Helper proof plus raw kernel evidence.
        invalid: Missing, stale, conflicting, or foreign native evidence.
    """
    status = lease_native["address_status"]
    link = status["links"][0]
    record = link["addresses"][0]
    if invalid == "stale-lease":
        record["dhcp4_lease"] = False
    elif invalid == "incomplete":
        status["complete"] = False
    elif invalid == "wrong-mac":
        link["mac"] = "00:50:56:00:00:ff"
    elif invalid == "wrong-index":
        link["ifindex"] = 3
    elif invalid == "configuring":
        link["configured"] = False
    elif invalid == "wrong-prefix":
        record["cidr"] = "192.0.2.10/25"
    elif invalid == "conflict":
        record["state"] = "conflict"
    elif invalid == "kernel-conflict":
        lease_native["native"]["links"][0]["addr_info"][0]["dadfailed"] = True
    else:
        lease_native["native"]["rules"]["4"].pop(1)
    monkeypatch.setattr(scenario, "_observe", lambda connect, program: lease_native)
    with pytest.raises(OverlapPrerequisiteError):
        scenario._same_address_native(lambda: None, topology)


@pytest.mark.parametrize("unknown", [False, True])
def test_revocation_failure_preserves_unknown_apply_outcome(monkeypatch, topology, unknown):
    """Revocation failure cannot downgrade the running-fixture recovery signal.

    Args:
        monkeypatch: Replace scenario and transport failure boundaries.
        topology: Admitted fixture identities.
        unknown: Whether the accepted Apply outcome remains unknown.
    """
    client = FakeClient()
    original_request = client.json_request
    sentinel = scenario.ApplyOutcomeUnknown("Apply job_abc still running")

    def revoke_fails(method, path, *, json_body=None):
        """Fail only revocation after recording its attempt.

        Args:
            method: Requested HTTP method.
            path: Canonical relative endpoint.
            json_body: Optional request body.
        """
        result = original_request(method, path, json_body=json_body)
        if path.endswith("/revoke"):
            raise OSError("synthetic transport failure")
        return result

    def run_authenticated(*_args):
        """Return success or preserve the exact accepted-Apply sentinel.

        Args:
            *_args: Admitted scenario dependencies.
        """
        if unknown:
            raise sentinel
        return {"status": "succeeded"}

    monkeypatch.setattr(client, "json_request", revoke_fails)
    monkeypatch.setattr(scenario, "_run_authenticated", run_authenticated)
    expected = scenario.ApplyOutcomeUnknown if unknown else OSError
    with pytest.raises(expected) as caught:
        scenario.run_scenario(client=client, connect_appliance=lambda: None, topology=topology,
                              server_action=lambda _action: {}, username="test", password="synthetic")
    if unknown:
        assert caught.value is sentinel
        assert sentinel.__notes__ == ["Temporary token revocation failed; retain the fixture for recovery."]
    assert client.calls[-1][:2] == ("POST", "/api/v1/api-tokens/1/revoke")
    assert client.bearer_token == ""
