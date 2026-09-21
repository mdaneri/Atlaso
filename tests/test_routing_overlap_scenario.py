"""Keep native routing evidence and recovery gates fail-closed."""

import copy
import io
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
    monkeypatch.setattr(scenario, "_apply", lambda current: applies.append(copy.deepcopy(current.rows)) or {"status": "succeeded"})
    monkeypatch.setattr(scenario, "_snapshot", lambda connect: {"links": [
        {"ifname": "eth0", "addr_info": [{"local": "192.0.2.10", "scope": "global"}]},
        {"ifname": "eth1", "addr_info": []}]})
    with pytest.raises(OverlapPrerequisiteError, match="native acquisition failed"):
        scenario.run_scenario(client=client, connect_appliance=lambda: None, topology=topology,
                              server_action=lambda action: actions.append(action) or {}, username="test", password="synthetic")
    assert client.rows == before
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
        scenario._restore(client, lambda: None, server, baseline)
    assert actions == ["resume-dhcp", "resume-ra"]
    assert [path for method, path, _body in client.calls if method == "PATCH"] == [
        "/api/v1/interfaces/physical/eth0", "/api/v1/interfaces/physical/eth1"]


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

    def uncertain(current):
        """Report the accepted task whose terminal status is unknown.

        Args:
            current: Authenticated client.
        """
        raise scenario.ApplyOutcomeUnknown("Apply job_abc still running")

    monkeypatch.setattr(scenario, "_apply", uncertain)
    with pytest.raises(scenario.ApplyOutcomeUnknown, match="job_abc"):
        scenario._run_authenticated(client, lambda: None, topology, lambda action: {})
    assert len([call for call in client.calls if call[0] == "PATCH"]) == 2
    assert client.rows["eth0"]["ipv4_method"] == "dhcp"


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
    monkeypatch.setattr(scenario, "_apply", lambda current, units: selected.extend(units) or {"job_id": "job_abc"})
    monkeypatch.setattr(scenario, "_clean", lambda current: {"pending_count": 0})
    assert scenario._setup(client)["initial_apply"]["job_id"] == "job_abc"
    assert selected == ["network"]
