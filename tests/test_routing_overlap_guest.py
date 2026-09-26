"""Exercise guest fixture ownership and restoration without real guest effects."""

import copy
import json
import os
import signal
import subprocess

import pytest

from scripts.interop import routing_overlap_guest as guest


def request(action="start", role="client-a"):
    """Build one host-admitted public command.

    Args:
        action: Desired fixture action.
        role: Admitted private client role.
    """
    return {"schema": 1, "action": action, "role": role,
            "task_id": "01a0bf3d-6787-76e0-a71a-600d3af9494e", "repository": "mdaneri/Atlaso",
            "source_commit": "a" * 40, "pr": 868, "topology_sha256": "b" * 64,
            "control": {"name": "eth0", "mac": "00:0c:29:00:00:01"},
            "private": {"name": "eth1", "mac": "00:0c:29:00:00:02"},
            "appliance_mac": "00:0c:29:00:00:03", "ipv4_prefix": "192.0.2.0/24", "ipv6_prefix": "fd74:1::/64"}


class FakeNative(guest.Native):
    """In-memory NICs/processes; subprocess and signals are never invoked."""

    def __init__(self):
        """Initialize one control NIC and an empty stopped private NIC."""
        self.links = [{"ifname": "eth0", "address": "00:0c:29:00:00:01", "flags": ["UP"],
                       "addr_info": [{"local": "198.51.100.4", "prefixlen": 24}]},
                      {"ifname": "eth1", "address": "00:0c:29:00:00:02", "flags": [], "addr_info": []},
                      {"ifname": "lo", "flags": ["UP"], "addr_info": []}]
        self.processes = {}
        self.calls = []
        self.fail_add = False
        self.fail_stop = False
        self.before_use = lambda: None
        self.settings = {f"net.ipv6.conf.{name}.{setting}": value
                         for name in ("all", "default", "lo", "eth0", "eth1")
                         for setting, value in (("forwarding", 0), ("accept_ra", 1))}
        self.nft_guard = None
        self.lro_disabled = True
        self.fail_setting = None

    def network_settings(self, names):
        """Return isolated modeled sysctls.

        Args:
            names: Admitted interface scope.
        """
        assert names == ["lo", "eth0", "eth1"]
        return dict(self.settings)

    def require_lro_disabled(self, names):
        """Refuse any original offload state that a global toggle would alter.

        Args:
            names: Admitted non-loopback interfaces.
        """
        assert names == ["eth0", "eth1"]
        if not self.lro_disabled:
            raise guest.Refusal("LRO is enabled")

    def write_setting(self, key, value):
        """Model Linux global propagation and require the drop guard first.

        Args:
            key: Exact sysctl key.
            value: Candidate value.
        """
        self.before_use()
        assert self.nft_guard is not None
        self.calls.append(["sysctl", key, value])
        if self.fail_setting == (key, value):
            raise guest.Refusal("injected sysctl failure")
        if key == "net.ipv6.conf.all.forwarding":
            if value == 1:
                assert self.settings["net.ipv6.conf.eth0.accept_ra"] == 2
            for existing in self.settings:
                if existing.endswith(".forwarding"):
                    self.settings[existing] = value
        self.settings[key] = value

    def guard(self):
        """Observe immutable native handles and the complete owned table."""
        return copy.deepcopy(self.nft_guard)

    def create_guard(self, comment):
        """Create one exact table before any forwarding setting changes.

        Args:
            comment: Topology-bound public ownership marker.
        """
        self.before_use()
        assert self.nft_guard is None
        self.calls.append(["guard-create"])
        self.nft_guard = [{"table": {"family": "ip6", "name": guest.GUARD_TABLE, "handle": 1, "comment": comment}},
                          {"chain": {"family": "ip6", "table": guest.GUARD_TABLE, "name": "forward", "handle": 2,
                                     "type": "filter", "hook": "forward", "prio": -300, "policy": "drop"}}]

    def delete_guard(self, handle):
        """Require forwarding restoration before original-handle retirement.

        Args:
            handle: Exact original native table identity.
        """
        assert all(value == 0 for key, value in self.settings.items() if key.endswith("forwarding"))
        assert self.nft_guard[0]["table"]["handle"] == handle
        self.calls.append(["guard-delete"])
        self.nft_guard = None

    def inventory(self):
        """Return an independent observation snapshot."""
        return copy.deepcopy(self.links)

    def run(self, arguments):
        """Model only exact private address and link changes.

        Args:
            arguments: Controller-produced argv.
        """
        self.before_use()
        self.calls.append(arguments)
        assert "eth0" not in arguments
        if arguments[1] == "link":
            self.links[1]["flags"] = ["UP"] if arguments[-1] == "up" else []
        else:
            value, prefix = arguments[3].split("/")
            row = {"local": value, "prefixlen": int(prefix)}
            if arguments[2] == "add":
                if self.fail_add and ":" in value:
                    raise guest.Refusal("injected address failure")
                self.links[1]["addr_info"].append(row)
            else:
                self.links[1]["addr_info"].remove(row)
        return ""

    def spawn(self, arguments, publish):
        """Check identity publication precedes modeled server execution.

        Args:
            arguments: Fixed server argv.
            publish: Durable original ownership callback.
        """
        pid = 100 + len(self.processes)
        receipt = {"pid": pid, "start_time": pid * 10, "argv": arguments}
        publish(receipt)
        self.before_use()
        self.processes[pid] = {**receipt, "state": "S", "group": pid, "session": pid}
        return receipt

    def process(self, pid):
        """Observe a modeled identity.

        Args:
            pid: Exact expected process.
        """
        return self.processes.get(pid)

    def signal(self, process, number):
        """Model only an original process pause/resume.

        Args:
            process: Original receipt.
            number: Requested signal.
        """
        self.require_live(process)
        self.processes[process["pid"]]["state"] = "T" if number == signal.SIGSTOP else "S"

    def stop(self, process):
        """Refuse replacement PIDs or injected uncertainty.

        Args:
            process: Original receipt.
        """
        if self.fail_stop:
            raise guest.Refusal("quiescence unproven")
        if process["pid"] not in self.processes:
            return
        self.require_live(process)
        del self.processes[process["pid"]]


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    """Replace Linux-only filesystem durability with a sandbox identity boundary.

    Args:
        tmp_path: Task-owned pytest temporary directory.
        monkeypatch: Pytest isolated overrides.
    """
    monkeypatch.setattr(signal, "SIGSTOP", 19, raising=False)
    monkeypatch.setattr(signal, "SIGCONT", 18, raising=False)
    monkeypatch.setattr(guest, "identity", lambda path, directory=False: [path.lstat().st_dev, path.lstat().st_ino])
    monkeypatch.setattr(guest, "durable_json", lambda path, value: path.write_text(json.dumps(value)))
    native = FakeNative()
    root = tmp_path / "fixture"
    controller = guest.Controller(request(), native, root)

    def require_receipt():
        """Every guest effect requires original ownership already on disk."""
        data = json.loads(controller.receipt.read_text())
        assert data["root_identity"] == guest.identity(root, True)
        assert data["binding"] == guest.binding(request())

    native.before_use = require_receipt
    return controller, native


@pytest.mark.parametrize("override", [{"action": []}, {"schema": True}, {"pr": True}, {"topology_sha256": "unknown"},
                                      {"ipv4_prefix": "192.168.1.0/24"}, {"appliance_mac": "ff:ff:ff:ff:ff:ff"}])
def test_request_rejects_unbound_or_shared_inputs(override):
    """Malformed admission never reaches a native boundary.

    Args:
        override: One invalid input field.
    """
    with pytest.raises(guest.Refusal):
        guest.validate_request({**request(), **override})


def test_request_accepts_uppercase_task_uuid_without_changing_binding():
    """Human lifecycle task IDs retain their original case through guest admission."""
    incoming = request()
    incoming["task_id"] = incoming["task_id"].upper()
    admitted = guest.validate_request(incoming)
    assert guest.binding(admitted)["task_id"] == incoming["task_id"]


def test_request_still_rejects_uppercase_source_commit():
    """Only task UUID casing is relaxed; digest bindings remain canonical."""
    with pytest.raises(guest.Refusal, match="invalid ownership binding"):
        guest.validate_request({**request(), "source_commit": "A" * 40})


def test_start_pause_resume_stop_preserves_control_and_records_originals(fixture):
    """Server and address use follows receipts; restoration leaves control intact.

    Args:
        fixture: Sandboxed controller/native pair.
    """
    controller, native = fixture
    control = copy.deepcopy(native.links[0])
    result = controller.execute()
    assert result["phase"] == "active" and len(result["processes"]) == 2
    assert not result["leases"]
    for action, daemon, expected in (("pause-dhcp", "dnsmasq", "T"), ("resume-dhcp", "dnsmasq", "S"),
                                     ("pause-ra", "radvd", "T"), ("resume-ra", "radvd", "S")):
        controller.request["action"] = action
        assert controller.execute()["processes"][daemon]["state"] == expected
    controller.request["action"] = "stop"
    assert controller.execute()["phase"] == "stopped"
    assert not native.processes and not native.links[1]["addr_info"] and not native.links[1]["flags"]
    assert native.links[0] == control
    assert controller.receipt.exists() and controller.root.exists()


def test_partial_start_restores_prior_private_link(fixture):
    """A failed IPv6 addition retires the earlier IPv4 address and restores down.

    Args:
        fixture: Sandboxed controller/native pair.
    """
    controller, native = fixture
    native.fail_add = True
    with pytest.raises(guest.Refusal, match="injected"):
        controller.execute()
    assert not native.links[1]["addr_info"] and not native.links[1]["flags"]
    assert json.loads(controller.receipt.read_text())["phase"] == "stopped"


def test_reuse_and_binding_changes_refuse_before_mutation(fixture):
    """An existing root cannot be adopted even after successful stop.

    Args:
        fixture: Sandboxed controller/native pair.
    """
    controller, native = fixture
    controller.execute()
    count = len(native.calls)
    with pytest.raises(guest.Refusal, match="reuse"):
        controller.execute()
    controller.request["action"] = "stop"
    controller.request["topology_sha256"] = "c" * 64
    with pytest.raises(guest.Refusal, match="ownership"):
        controller.execute()
    assert len(native.calls) == count and len(native.processes) == 2


@pytest.mark.parametrize("change", ["mac", "address", "duplicate"])
def test_live_identity_and_unowned_address_changes_preserve_state(fixture, change):
    """Foreign link state must never be repaired or cleaned automatically.

    Args:
        fixture: Sandboxed controller/native pair.
        change: Independent foreign mutation being modeled.
    """
    controller, native = fixture
    controller.execute()
    if change == "mac":
        native.links[1]["address"] = "00:0c:29:ff:ff:ff"
    elif change == "address":
        native.links[1]["addr_info"].append({"local": "192.0.2.99", "prefixlen": 24})
    else:
        native.links.append(copy.deepcopy(native.links[1]))
    controller.request["action"] = "stop"
    before = copy.deepcopy(native.links)
    with pytest.raises(guest.Refusal):
        controller.execute()
    assert native.links == before and len(native.processes) == 2


def test_stop_preserves_addresses_when_process_quiescence_unproven(fixture):
    """Cleanup does not remove network state beneath an unproven live server.

    Args:
        fixture: Sandboxed controller/native pair.
    """
    controller, native = fixture
    controller.execute()
    native.fail_stop = True
    controller.request["action"] = "stop"
    with pytest.raises(guest.Refusal, match="quiescence"):
        controller.execute()
    assert len(native.links[1]["addr_info"]) == 2


def test_recycled_process_identity_is_never_signalled(fixture):
    """A PID is insufficient without the original start-time identity.

    Args:
        fixture: Sandboxed controller/native pair.
    """
    controller, native = fixture
    controller.execute()
    native.processes[100]["start_time"] += 1
    controller.request["action"] = "pause-dhcp"
    with pytest.raises(guest.Refusal, match="changed"):
        controller.execute()
    assert native.processes[100]["state"] == "S"


def test_server_config_is_private_only_and_leases_are_observed():
    """Configured reservations never masquerade as an observed live DHCP lease."""
    config = guest.configurations(request())
    assert "interface=eth1\n" in config["dnsmasq"] and "except-interface=eth0" in config["dnsmasq"]
    assert "port=53" in config["dnsmasq"] and "interface=eth1" in config["dnsmasq"]
    assert "address=/fixture.test/192.0.2.1" in config["dnsmasq"]
    assert "dhcp-option=6" in config["dnsmasq"] and "dhcp-ignore=tag:!fixture" in config["dnsmasq"]
    assert "AdvValidLifetime 60" in config["radvd"] and "AdvPreferredLifetime 30" in config["radvd"]
    assert "AdvDefaultLifetime 30" in config["radvd"]
    assert guest.parse_leases("", request()["appliance_mac"], 100) == []
    text = "120 00:0c:29:00:00:03 192.0.2.10 appliance *\n"
    assert guest.parse_leases(text, request()["appliance_mac"], 100)[0]["unexpired"]
    assert not guest.parse_leases(text, request()["appliance_mac"], 121)[0]["unexpired"]
    with pytest.raises(guest.Refusal):
        guest.parse_leases(text.replace("00:03", "00:04"), request()["appliance_mac"], 100)


def test_client_b_starts_no_server(fixture):
    """The lab peer has addresses only and cannot acquire server capabilities.

    Args:
        fixture: Sandboxed controller/native pair.
    """
    controller, native = fixture
    native.before_use = lambda: None
    controller = guest.Controller(request(role="client-b"), native, controller.root)
    assert controller.execute()["processes"] == {}
    controller.request["action"] = "pause-ra"
    with pytest.raises(guest.Refusal, match="client-a"):
        controller.execute()


def test_native_stops_privsep_children_before_address_cleanup(monkeypatch):
    """Foreground radvd still forks; quiescence must cover its private session.

    Args:
        monkeypatch: Isolated native process mocks.
    """
    native = guest.Native()
    leader = {"pid": 100, "start_time": 1000, "state": "S", "group": 100, "session": 100}
    child = {"pid": 101, "start_time": 1001, "state": "S", "group": 100, "session": 100}
    processes = {100: leader, 101: child}
    calls = []
    monkeypatch.setattr(signal, "SIGSTOP", 19, raising=False)
    monkeypatch.setattr(signal, "SIGKILL", 9, raising=False)
    monkeypatch.setattr(native, "process", lambda pid: processes.get(pid))
    monkeypatch.setattr(native, "members", lambda _receipt: list(processes.values()))

    def send(row, number):
        """Model pinned signals without sending any real signal.

        Args:
            row: Individually observed session member.
            number: Controller signal.
        """
        calls.append((row["pid"], number))
        if number == signal.SIGKILL:
            del processes[row["pid"]]

    monkeypatch.setattr(native, "signal_one", send)
    native.stop(leader)
    assert (101, signal.SIGKILL) in calls and not processes


def test_native_orphan_session_is_preserved(monkeypatch):
    """Missing original leader cannot authorize adoption of surviving children.

    Args:
        monkeypatch: Isolated native observation mocks.
    """
    native = guest.Native()
    monkeypatch.setattr(native, "process", lambda _pid: None)
    monkeypatch.setattr(native, "members", lambda _row: [{"pid": 101}])
    with pytest.raises(guest.Refusal, match="orphan"):
        native.stop({"pid": 100, "start_time": 1000})


def test_spawn_early_reaped_exit_never_reads_or_signals_reused_pid(monkeypatch):
    """An already reaped child cannot authorize a later process with its PID.

    Args:
        monkeypatch: Mocked fork/pidfd/wait boundary; no process is created.
    """
    calls = []
    native = guest.Native()
    monkeypatch.setattr(os, "fork", lambda: 100, raising=False)
    monkeypatch.setattr(os, "pidfd_open", lambda pid: calls.append(("pin", pid)) or 55, raising=False)
    monkeypatch.setattr(signal, "pidfd_send_signal", lambda *_args: pytest.fail("must not signal"), raising=False)
    monkeypatch.setattr(os, "WUNTRACED", 2, raising=False)
    monkeypatch.setattr(os, "WNOHANG", 1, raising=False)
    monkeypatch.setattr(os, "WIFSTOPPED", lambda _status: False, raising=False)
    monkeypatch.setattr(os, "waitpid", lambda *_args: (100, 0))
    monkeypatch.setattr(os, "close", lambda fd: calls.append(("close", fd)))
    monkeypatch.setattr(native, "process", lambda _pid: pytest.fail("must not inspect reused PID"))
    with pytest.raises(guest.Refusal, match="exited before"):
        native.spawn(["radvd", "-n"], lambda _row: pytest.fail("must not publish"))
    assert calls == [("pin", 100), ("close", 55)]


def test_spawn_timeout_kills_pinned_child_not_numeric_pid(monkeypatch):
    """The timeout boundary signals the original pidfd despite PID reuse risks.

    Args:
        monkeypatch: Mocked fork/pidfd/time boundary; no process is created.
    """
    calls = []
    ticks = iter([0, 4])
    monkeypatch.setattr(os, "fork", lambda: 100, raising=False)
    monkeypatch.setattr(os, "pidfd_open", lambda _pid: 55, raising=False)
    monkeypatch.setattr(signal, "pidfd_send_signal", lambda fd, number: calls.append((fd, number)), raising=False)
    monkeypatch.setattr(signal, "SIGKILL", 9, raising=False)
    monkeypatch.setattr(os, "waitpid", lambda *_args: (100, 9))
    monkeypatch.setattr(os, "kill", lambda *_args: pytest.fail("numeric signal forbidden"))
    monkeypatch.setattr(os, "close", lambda _fd: None)
    monkeypatch.setattr(guest.time, "monotonic", lambda: next(ticks))
    with pytest.raises(guest.Refusal, match="timeout"):
        guest.Native().spawn(["radvd", "-n"], lambda _row: pytest.fail("must not publish"))
    assert calls == [(55, 9)]


def test_forwarding_guard_precedes_changes_and_control_state_is_restored(fixture):
    """Enable the radvd global prerequisite without allowing guest transit.

    Args:
        fixture: Sandboxed controller/native pair.
    """
    controller, native = fixture
    original = dict(native.settings)
    controller.execute()
    assert native.calls[0] == ["guard-create"]
    assert native.settings == {**original, "net.ipv6.conf.all.forwarding": 1}
    assert native.nft_guard[1]["chain"]["policy"] == "drop"
    assert native.settings["net.ipv6.conf.eth0.forwarding"] == 0
    assert native.settings["net.ipv6.conf.eth0.accept_ra"] == 1
    receipt = json.loads(controller.receipt.read_text())
    assert receipt["forwarding"]["original"] == original
    assert receipt["forwarding"]["guard"][0]["table"]["handle"] == 1
    controller.request["action"] = "stop"
    controller.execute()
    assert native.settings == original and native.nft_guard is None
    assert native.calls.index(["guard-delete"]) > native.calls.index(["sysctl", "net.ipv6.conf.all.forwarding", 0])


@pytest.mark.parametrize("condition", ["foreign-table", "lro", "forwarding", "extra-nic"])
def test_forwarding_admission_preserves_unowned_baseline(fixture, condition):
    """Unexpected existing capabilities prevent every fixture mutation.

    Args:
        fixture: Sandboxed controller/native pair.
        condition: Independently observed unsupported baseline.
    """
    controller, native = fixture
    if condition == "foreign-table":
        native.nft_guard = [{"table": {"handle": 99}}]
    elif condition == "lro":
        native.lro_disabled = False
    elif condition == "forwarding":
        native.settings["net.ipv6.conf.eth0.forwarding"] = 1
    else:
        native.links.append({"ifname": "eth9", "address": "00:0c:29:00:00:09", "addr_info": []})
    with pytest.raises(guest.Refusal):
        controller.execute()
    assert not native.calls and not controller.root.exists()


def test_partial_forwarding_enable_restores_values_before_guard_removal(fixture):
    """A failure after RA protection but before global enable is fully restored.

    Args:
        fixture: Sandboxed controller/native pair.
    """
    controller, native = fixture
    original = dict(native.settings)
    native.fail_setting = ("net.ipv6.conf.all.forwarding", 1)
    with pytest.raises(guest.Refusal, match="injected"):
        controller.execute()
    assert native.settings == original and native.nft_guard is None
    assert not native.processes and not native.links[1]["addr_info"]


def test_failed_forwarding_restore_retains_guard_after_server_quiescence(fixture):
    """Unproven sysctl restoration must never remove the forwarding drop guard.

    Args:
        fixture: Sandboxed controller/native pair.
    """
    controller, native = fixture
    controller.execute()
    native.fail_setting = ("net.ipv6.conf.all.forwarding", 0)
    controller.request["action"] = "stop"
    with pytest.raises(guest.Refusal, match="injected"):
        controller.execute()
    assert not native.processes and native.nft_guard is not None
    assert ["guard-delete"] not in native.calls


def test_replaced_nft_handle_is_never_removed(fixture):
    """A table with changed native identity cannot be claimed from its name.

    Args:
        fixture: Sandboxed controller/native pair.
    """
    controller, native = fixture
    controller.execute()
    native.nft_guard[0]["table"]["handle"] = 99
    controller.request["action"] = "stop"
    with pytest.raises(guest.Refusal, match="guard changed"):
        controller.execute()
    assert native.nft_guard[0]["table"]["handle"] == 99
    assert ["guard-delete"] not in native.calls


def test_status_rechecks_actual_forwarding_prerequisite(fixture):
    """A running radvd process alone cannot prove nonzero router advertisements.

    Args:
        fixture: Sandboxed controller/native pair.
    """
    controller, native = fixture
    controller.execute()
    native.settings["net.ipv6.conf.all.forwarding"] = 0
    controller.request["action"] = "status"
    with pytest.raises(guest.Refusal, match="runtime changed"):
        controller.execute()


def test_native_guard_create_is_exclusive_and_delete_uses_original_handle(monkeypatch):
    """A racing same-name table cannot be adopted or targeted for deletion.

    Args:
        monkeypatch: Mocked nft subprocess boundary.
    """
    calls = []

    def run(arguments, **kwargs):
        """Capture the atomic public nft transaction without executing it.

        Args:
            arguments: Fixed nft argv.
            **kwargs: Fixed subprocess options and public rule source.
        """
        calls.append((arguments, kwargs))
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(subprocess, "run", run)
    native = guest.Native()
    native.create_guard("atlaso-overlap:" + "b" * 64)
    assert calls[0][0] == ["nft", "-f", "-"]
    assert calls[0][1]["input"].startswith("create table ip6 ")
    assert "policy drop" in calls[0][1]["input"]
    monkeypatch.setattr(native, "run", lambda arguments: calls.append((arguments, {})) or "")
    native.delete_guard(123)
    assert calls[-1][0] == ["nft", "delete", "table", "ip6", "handle", "123"]
