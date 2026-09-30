"""Bounded Linux guest controller for the host-admitted private overlap fixture.

Read one schema-1 JSON request from stdin and emit one public JSON result. The
host must independently admit LAN receipts, VMX ownership and live NIC mappings;
the digest in this protocol binds that admission but cannot establish it itself.
No paths or executable arguments are accepted from the request. Retained receipt
and fixture files belong to whole-VM lifecycle cleanup, never recursive deletion.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

ROOT = Path("/run/atlaso-routing-overlap")
ACTIONS = {"start", "status", "pause-dhcp", "resume-dhcp", "pause-ra", "resume-ra", "stop"}
ADDRESSES = ("192.0.2.1/24", "fd74:1::1/64")
GUARD_TABLE = "atlaso_routing_overlap"


class Refusal(ValueError):
    """A fixed public prerequisite or preservation failure."""


def linux_value(module: Any, name: str) -> Any:
    """Resolve a required Linux API while keeping host-side tests importable.

    Args:
        module: Standard-library platform module.
        name: Fixed controller-selected Linux API or signal name.
    """
    value = getattr(module, name, None)
    if value is None:
        raise Refusal("required Linux process API is unavailable")
    return value


def validate_request(request: Any) -> dict[str, Any]:
    """Validate the complete host-bound public command.

    Args:
        request: Untrusted decoded stdin object.
    """
    keys = {"schema", "action", "role", "task_id", "repository", "source_commit", "pr",
            "topology_sha256", "control", "private", "ipv4_prefix", "ipv6_prefix", "appliance_mac"}
    if not isinstance(request, dict) or set(request) != keys:
        raise Refusal("invalid request fields")
    if (type(request["schema"]) is not int or request["schema"] != 1
            or not isinstance(request["action"], str) or request["action"] not in ACTIONS
            or not isinstance(request["role"], str) or request["role"] not in {"client-a", "client-b"}
            or request["repository"] != "mdaneri/Atlaso" or type(request["pr"]) is not int or request["pr"] <= 0
            or request["ipv4_prefix"] != "192.0.2.0/24" or request["ipv6_prefix"] != "fd74:1::/64"):
        raise Refusal("invalid fixture contract")
    for key, pattern in (("task_id", r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"),
                         ("source_commit", r"[0-9a-f]{40}"), ("topology_sha256", r"[0-9a-f]{64}")):
        flags = re.IGNORECASE if key == "task_id" else 0
        if not isinstance(request[key], str) or not re.fullmatch(pattern, request[key], flags=flags):
            raise Refusal("invalid ownership binding")
    macs = []
    for key in ("control", "private"):
        link = request[key]
        if (not isinstance(link, dict) or set(link) != {"name", "mac"}
                or not isinstance(link["name"], str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,14}", link["name"])
                or link["name"] == "lo"):
            raise Refusal("invalid interface identity")
        macs.append(link["mac"])
    macs.append(request["appliance_mac"])
    for mac in macs:
        if (not isinstance(mac, str) or not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac)
                or int(mac[:2], 16) & 1 or mac == "00:00:00:00:00:00"):
            raise Refusal("invalid MAC identity")
    if len(set(macs)) != 3 or request["control"]["name"] == request["private"]["name"]:
        raise Refusal("fixture and control identities overlap")
    return request


def binding(request: dict[str, Any]) -> dict[str, Any]:
    """Return immutable admission fields independent of the requested action.

    Args:
        request: Fully validated command.
    """
    return {key: value for key, value in request.items() if key != "action"}


def configurations(request: dict[str, Any]) -> dict[str, str]:
    """Render private-only foreground server inputs from the admitted identities.

    Args:
        request: Fully validated command.
    """
    private, control = request["private"]["name"], request["control"]["name"]
    dnsmasq = "\n".join([
        "port=53", "user=root", "bind-interfaces", f"interface={private}", f"except-interface={control}", "except-interface=lo",
        "no-resolv", "no-hosts", "local=/fixture.test/", "address=/fixture.test/192.0.2.1",
        "dhcp-authoritative", "dhcp-ignore=tag:!fixture",
        "dhcp-range=192.0.2.10,192.0.2.10,255.255.255.0,2m",
        f"dhcp-host=set:fixture,{request['appliance_mac']},192.0.2.10,2m",
        "dhcp-option=3,192.0.2.1", "dhcp-option=6", f"dhcp-leasefile={ROOT}/leases", "log-facility=-", "",
    ])
    radvd = (f"interface {private} {{\n  AdvSendAdvert on;\n  AdvCurHopLimit 0;\n  MinRtrAdvInterval 3;\n"
             "  MaxRtrAdvInterval 10;\n  AdvDefaultLifetime 30;\n"
             "  prefix fd74:1::/64 {\n    AdvOnLink on;\n    AdvAutonomous on;\n"
             "    AdvValidLifetime 60;\n    AdvPreferredLifetime 30;\n  };\n};\n")
    return {"dnsmasq": dnsmasq, "radvd": radvd}


def parse_leases(text: str, appliance_mac: str, now: int) -> list[dict[str, Any]]:
    """Read actual finite dnsmasq lease records without inferring an offer.

    Args:
        text: Bounded lease-file content.
        appliance_mac: Only admitted DHCP client.
        now: Current Unix timestamp for expiry classification.
    """
    if len(text) > 65536:
        raise Refusal("lease inventory exceeds bound")
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        parts = line.split()
        if (len(parts) != 5 or not parts[0].isdigit() or int(parts[0]) <= 0
                or parts[1].lower() != appliance_mac or parts[2] != "192.0.2.10" or rows):
            raise Refusal("unexpected DHCP lease record")
        expires = int(parts[0])
        rows.append({"mac": appliance_mac, "address": parts[2], "expires_at": expires, "unexpired": expires > now})
    return rows


class Native:
    """Small injectable boundary for bounded Linux commands and owned processes."""

    def run(self, arguments: list[str]) -> str:
        """Run a fixed argv without a shell or inherited interactive input.

        Args:
            arguments: Controller-generated native argv.
        """
        result = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10, check=False)
        if result.returncode or len(result.stdout) > 1048576 or len(result.stderr) > 65536:
            raise Refusal("native command failed or exceeded output bound")
        return result.stdout

    def inventory(self) -> list[dict[str, Any]]:
        """Return bounded live link/address inventory."""
        value = json.loads(self.run(["ip", "-j", "address", "show"]))
        if not isinstance(value, list) or len(value) > 128:
            raise Refusal("invalid guest NIC inventory")
        return value

    def network_settings(self, names: list[str]) -> dict[str, int]:
        """Read the exact IPv6 settings affected by global forwarding writes.

        Args:
            names: Independently admitted guest interfaces including loopback.
        """
        scopes = ["all", "default", *names]
        keys = [f"net.ipv6.conf.{name}.{setting}" for name in scopes for setting in ("forwarding", "accept_ra")]
        keys += [f"net.ipv6.conf.{name}.force_forwarding" for name in scopes
                 if Path(f"/proc/sys/net/ipv6/conf/{name}/force_forwarding").exists()]
        values = self.run(["sysctl", "-n", *keys]).splitlines()
        if len(values) != len(keys) or any(value not in {"0", "1", "2"} for value in values):
            raise Refusal("invalid guest IPv6 settings inventory")
        return dict(zip(keys, map(int, values), strict=True))

    def require_lro_disabled(self, names: list[str]) -> None:
        """Refuse offload changes that a global forwarding toggle cannot undo.

        Args:
            names: Admitted non-loopback guest interfaces.
        """
        for name in names:
            output = self.run(["ethtool", "-k", name])
            if len(re.findall(r"^large-receive-offload: off(?: \[fixed\])?$", output, re.MULTILINE)) != 1:
                raise Refusal("fixture requires existing LRO-off interfaces")

    def write_setting(self, key: str, value: int) -> None:
        """Write a controller-generated sysctl without shell interpolation.

        Args:
            key: Exact validated original snapshot key.
            value: Admitted IPv6 forwarding or RA value.
        """
        self.run(["sysctl", "-q", "-w", f"{key}={value}"])

    def guard(self) -> list[dict[str, Any]] | None:
        """Read only the fixed fixture table, retaining native object handles."""
        rows = json.loads(self.run(["nft", "-j", "list", "tables"]))["nftables"]
        matches = [row["table"] for row in rows if "table" in row
                   and row["table"].get("family") == "ip6" and row["table"].get("name") == GUARD_TABLE]
        if not matches:
            return None
        if len(matches) != 1:
            raise Refusal("ambiguous fixture forwarding guard")
        value = json.loads(self.run(["nft", "-j", "list", "table", "ip6", GUARD_TABLE]))["nftables"]
        return [row for row in value if "metainfo" not in row]

    def create_guard(self, comment: str) -> None:
        """Atomically create an owned drop-only IPv6 forwarding table.

        Args:
            comment: Controller-generated immutable topology ownership marker.
        """
        commands = (f'create table ip6 {GUARD_TABLE} {{ comment "{comment}"; }}\n'
                    f"create chain ip6 {GUARD_TABLE} forward {{ type filter hook forward priority -300; policy drop; }}\n")
        result = subprocess.run(["nft", "-f", "-"], input=commands, capture_output=True, text=True, timeout=10, check=False)
        if result.returncode:
            raise Refusal("fixture forwarding guard creation failed")

    def delete_guard(self, handle: int) -> None:
        """Delete by original handle, never a concurrently reused table name.

        Args:
            handle: Exact native table handle recorded before forwarding changed.
        """
        self.run(["nft", "delete", "table", "ip6", "handle", str(handle)])

    def process(self, pid: int) -> dict[str, Any] | None:
        """Read exact Linux process identity and state without adopting a PID.

        Args:
            pid: Previously journaled process identifier.
        """
        try:
            fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
        except FileNotFoundError:
            return None
        return {"pid": pid, "start_time": int(fields[19]), "state": fields[0],
                "group": int(fields[2]), "session": int(fields[3])}

    def signal_one(self, process: dict[str, Any], number: int) -> None:
        """Signal through a pidfd after verifying the original start identity.

        Args:
            process: Original pre-execution process receipt.
            number: Fixed controller signal.
        """
        try:
            descriptor = linux_value(os, "pidfd_open")(process["pid"])
        except ProcessLookupError:
            return
        try:
            current = self.process(process["pid"])
            if current is None or current["start_time"] != process["start_time"]:
                raise Refusal("process identity changed; preserve replacement")
            linux_value(signal, "pidfd_send_signal")(descriptor, number)
        finally:
            os.close(descriptor)

    def members(self, process: dict[str, Any]) -> list[dict[str, Any]]:
        """Observe descendants confined to the originally created private session.

        Args:
            process: Original session-leader receipt, recorded before daemon exec.
        """
        result = []
        entries = list(Path("/proc").iterdir())
        if len(entries) > 16384:
            raise Refusal("process inventory exceeds bound")
        for entry in entries:
            if not entry.name.isdigit():
                continue
            row = self.process(int(entry.name))
            if row and row["group"] == process["pid"] and row["session"] == process["pid"] and row["state"] != "Z":
                result.append(row)
        return result

    def signal(self, process: dict[str, Any], number: int) -> None:
        """Pause/resume all members while preserving original session ownership.

        Args:
            process: Original foreground leader and private-session receipt.
            number: Controller-selected pause or resume signal.
        """
        self.require_live(process)
        # radvd creates a privsep child even in foreground mode. Freeze the
        # original leader before inventory so it cannot create further children.
        self.signal_one(process, linux_value(signal, "SIGSTOP"))
        for member in self.members(process):
            self.signal_one(member, number)

    def spawn(self, arguments: list[str], publish: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
        """Hold a forked child before exec until its original identity is durable.

        Args:
            arguments: Fixed foreground server argv.
            publish: Durable sibling-journal callback, invoked before execution.
        """
        open_pidfd = linux_value(os, "pidfd_open")
        send_pidfd = linux_value(signal, "pidfd_send_signal")
        pid = linux_value(os, "fork")()
        if pid == 0:
            try:
                linux_value(os, "setsid")()
                null = os.open("/dev/null", os.O_RDWR)
                for descriptor in (0, 1, 2):
                    os.dup2(null, descriptor)
                os.kill(os.getpid(), linux_value(signal, "SIGSTOP"))
                os.execvp(arguments[0], arguments)
            finally:
                os._exit(126)
        # The child remains ours and unreaped here, so its PID cannot yet be
        # reused. Pin it before the first waitpid, which could reap an early exit.
        try:
            descriptor = open_pidfd(pid)
        except OSError:
            os.kill(pid, linux_value(signal, "SIGKILL"))
            os.waitpid(pid, 0)
            raise
        try:
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                waited, status = os.waitpid(pid, linux_value(os, "WUNTRACED") | linux_value(os, "WNOHANG"))
                if waited == pid:
                    if not linux_value(os, "WIFSTOPPED")(status):
                        raise Refusal("fixture child exited before admission")
                    current = self.process(pid)
                    if current is None or current["state"] != "T":
                        raise Refusal("fixture child stop identity unproven")
                    break
                time.sleep(0.01)
            else:
                send_pidfd(descriptor, linux_value(signal, "SIGKILL"))
                os.waitpid(pid, 0)
                raise Refusal("fixture child admission timeout")
            receipt = {"pid": pid, "start_time": current["start_time"], "argv": arguments}
            try:
                publish(receipt)
                send_pidfd(descriptor, linux_value(signal, "SIGCONT"))
            except (OSError, ValueError):
                send_pidfd(descriptor, linux_value(signal, "SIGKILL"))
                os.waitpid(pid, 0)
                raise
            time.sleep(0.2)
            self.require_live(receipt)
            return receipt
        finally:
            os.close(descriptor)

    def require_live(self, process: dict[str, Any]) -> dict[str, Any]:
        """Require a non-zombie process with unchanged start identity.

        Args:
            process: Original receipt.
        """
        current = self.process(process["pid"])
        if current is None or current["start_time"] != process["start_time"] or current["state"] == "Z":
            raise Refusal("fixture process is absent or changed")
        return current

    def stop(self, process: dict[str, Any]) -> None:
        """Terminate only an original process and prove quiescence before return.

        Args:
            process: Original receipt.
        """
        current = self.process(process["pid"])
        members = self.members(process)
        if current is None:
            if members:
                raise Refusal("orphan fixture descendants require whole-VM cleanup")
            return
        if current["start_time"] != process["start_time"]:
            raise Refusal("process identity changed; preserve replacement")
        if current["state"] == "Z" and not members:
            return
        if current["state"] != "Z":
            self.signal_one(process, linux_value(signal, "SIGSTOP"))
        # The original leader still anchors the private session. Pin every
        # observed member with pidfd/start time; never signal a numeric group.
        for member in self.members(process):
            self.signal_one(member, linux_value(signal, "SIGSTOP"))
        for member in self.members(process):
            self.signal_one(member, linux_value(signal, "SIGKILL"))
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            current = self.process(process["pid"])
            if not self.members(process) and (current is None or (current["start_time"] == process["start_time"] and current["state"] == "Z")):
                return
            if current is not None and current["start_time"] != process["start_time"]:
                raise Refusal("process identity changed during stop")
            time.sleep(0.02)
        raise Refusal("fixture process quiescence unproven")


def checked_link(request: dict[str, Any], rows: list[dict[str, Any]], allowed: set[str]) -> dict[str, Any]:
    """Recheck NIC identity and reject unowned global addresses before mutation.

    Args:
        request: Immutable host admission binding.
        rows: Fresh native address inventory.
        allowed: Exact fixture addresses already claimed by the original receipt.
    """
    found = {}
    for purpose in ("control", "private"):
        expected = request[purpose]
        matches = [row for row in rows if row.get("ifname") == expected["name"] or row.get("address", "").lower() == expected["mac"]]
        if len(matches) != 1 or matches[0].get("ifname") != expected["name"] or matches[0].get("address", "").lower() != expected["mac"]:
            raise Refusal("guest NIC identity changed")
        found[purpose] = matches[0]
    private = found["private"]
    for row in rows:
        if row.get("ifname") == request["private"]["name"]:
            continue
        for info in row.get("addr_info", []):
            address = ipaddress.ip_address(info["local"])
            prefix = ipaddress.ip_network(request["ipv4_prefix"] if address.version == 4 else request["ipv6_prefix"])
            if address in prefix:
                raise Refusal("fixture prefix appears on another guest interface")
    for info in private.get("addr_info", []):
        address = ipaddress.ip_interface(f"{info['local']}/{info['prefixlen']}")
        if not address.ip.is_link_local and str(address) not in allowed:
            raise Refusal("private interface has an unowned address")
    return private


def identity(path: Path, directory: bool = False) -> list[int]:
    """Require an ordinary root-owned private path and return its original identity.

    Args:
        path: Fixed controller-owned path.
        directory: Whether a directory is required.
    """
    item = path.lstat()
    correct = stat.S_ISDIR(item.st_mode) if directory else stat.S_ISREG(item.st_mode) and item.st_nlink == 1
    if not correct or item.st_uid != linux_value(os, "geteuid")() or item.st_mode & 0o077:
        raise Refusal("fixture path identity or permissions unsafe")
    return [item.st_dev, item.st_ino]


def durable_json(path: Path, value: dict[str, Any]) -> None:
    """Publish one bounded journal replacement and sync its parent directory.

    Args:
        path: Fixed sibling receipt path.
        value: Public identity and progress evidence.
    """
    temporary = path.with_suffix(".new")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class Controller:
    """Serialize fixture mutation under the CLI's fixed guest lock."""

    def __init__(self, request: dict[str, Any], native: Native, root: Path = ROOT) -> None:
        """Bind one validated request and a testable native boundary.

        Args:
            request: Complete public host command.
            native: Native effects implementation.
            root: Fixed production root; isolated sandbox injection for tests only.
        """
        self.request = validate_request(request)
        self.native = native
        self.root = root
        self.receipt = root.parent / f"atlaso-routing-overlap-{request['task_id']}-{request['role']}.json"
        self.journal: dict[str, Any] = {}

    def save(self) -> None:
        """Retain all original identities while advancing public progress."""
        durable_json(self.receipt, self.journal)

    def forwarding_names(self) -> list[str]:
        """Admit exactly the two bound NICs and loopback for a global toggle."""
        names = ["lo", self.request["control"]["name"], self.request["private"]["name"]]
        rows = self.native.inventory()
        checked_link(self.request, rows, set(ADDRESSES))
        if sorted(row.get("ifname", "") for row in rows) != sorted(names):
            raise Refusal("extra guest interfaces prohibit fixture forwarding")
        return names

    def forwarding_snapshot(self) -> dict[str, Any] | None:
        """Capture a non-forwarding baseline before any fixture resources are used."""
        if self.request["role"] != "client-a":
            return None
        names = self.forwarding_names()
        self.native.require_lro_disabled(names[1:])
        values = self.native.network_settings(names)
        if any(value != 0 for key, value in values.items() if key.endswith("forwarding")):
            raise Refusal("fixture requires an initially non-forwarding client")
        if self.native.guard() is not None:
            raise Refusal("fixture forwarding table already exists")
        return {"original": values, "guard": None, "changed": False}

    def enable_forwarding(self) -> None:
        """Satisfy radvd's global check while blocking transit and preserving control RA."""
        state = self.journal["forwarding"]
        if state is None:
            return
        names = self.forwarding_names()
        if self.native.network_settings(names) != state["original"] or self.native.guard() is not None:
            raise Refusal("fixture forwarding baseline changed")
        comment = "atlaso-overlap:" + self.request["topology_sha256"]
        self.native.create_guard(comment)
        observed = self.native.guard()
        if not observed or len(observed) != 2:
            raise Refusal("fixture forwarding guard publication unproven")
        table: dict[str, Any] = next((row["table"] for row in observed if "table" in row), {})
        chain: dict[str, Any] = next((row["chain"] for row in observed if "chain" in row), {})
        if (table.get("comment") != comment or table.get("name") != GUARD_TABLE
                or type(table.get("handle")) is not int or type(chain.get("handle")) is not int
                or chain.get("family") != "ip6" or chain.get("table") != GUARD_TABLE
                or chain.get("name") != "forward" or chain.get("hook") != "forward"
                or chain.get("type") != "filter" or chain.get("prio") != -300 or chain.get("policy") != "drop"):
            raise Refusal("fixture forwarding guard is not the exact owned drop chain")
        state["guard"] = observed
        state["changed"] = True
        self.save()  # Original table handles and sysctl values precede every write.
        # Kernel global forwarding propagates to every interface/default and
        # purges learned RA defaults unless accept_ra=2. Preserve reception first.
        for name in names:
            key = f"net.ipv6.conf.{name}.accept_ra"
            if state["original"][key] == 1:
                self.native.write_setting(key, 2)
        self.native.write_setting("net.ipv6.conf.all.forwarding", 1)
        for key, value in state["original"].items():
            if key != "net.ipv6.conf.all.forwarding":
                self.native.write_setting(key, value)
        expected = {**state["original"], "net.ipv6.conf.all.forwarding": 1}
        if self.native.network_settings(names) != expected or self.native.guard() != state["guard"]:
            raise Refusal("fixture forwarding activation readback failed")

    def restore_forwarding(self) -> None:
        """Restore and verify original sysctls before removing the exact owned guard."""
        state = self.journal["forwarding"]
        if state is None:
            return
        names = self.forwarding_names()
        guard = self.native.guard()
        if state["guard"] is None:
            if guard is not None:
                raise Refusal("unreceipted forwarding guard requires whole-VM cleanup")
            return
        if guard != state["guard"]:
            raise Refusal("fixture forwarding guard changed; preserve foreign state")
        self.native.write_setting("net.ipv6.conf.all.forwarding", state["original"]["net.ipv6.conf.all.forwarding"])
        for key, value in state["original"].items():
            if key != "net.ipv6.conf.all.forwarding":
                self.native.write_setting(key, value)
        if self.native.network_settings(names) != state["original"]:
            raise Refusal("forwarding restoration unproven; guard retained")
        self.native.require_lro_disabled(names[1:])
        if self.native.guard() != state["guard"]:
            raise Refusal("fixture forwarding guard changed before removal")
        handle = next(row["table"]["handle"] for row in state["guard"] if "table" in row)
        self.native.delete_guard(handle)
        if self.native.guard() is not None:
            raise Refusal("fixture forwarding guard removal unproven")
        state["guard"] = None
        state["changed"] = False
        self.save()

    def load(self) -> None:
        """Require exact original directory and host-admission ownership."""
        identity(self.receipt)
        if self.receipt.stat().st_size > 65536:
            raise Refusal("fixture receipt exceeds bound")
        self.journal = json.loads(self.receipt.read_text())
        if (not isinstance(self.journal, dict) or self.journal.get("binding") != binding(self.request)
                or self.journal.get("root_identity") != identity(self.root, True)):
            raise Refusal("fixture original ownership mismatch")
        if (type(self.journal.get("previous_up")) is not bool or self.journal.get("addresses") != list(ADDRESSES)
                or not isinstance(self.journal.get("phase"), str)
                or self.journal["phase"] not in {"prepared", "active", "stopped"}
                or not isinstance(self.journal.get("processes"), dict)
                or not set(self.journal["processes"]) <= {"dnsmasq", "radvd"}):
            raise Refusal("fixture ownership journal is malformed")
        for process in self.journal["processes"].values():
            if (not isinstance(process, dict) or type(process.get("pid")) is not int or process["pid"] <= 1
                    or type(process.get("start_time")) is not int or process["start_time"] <= 0):
                raise Refusal("fixture process receipt is malformed")
        state = self.journal.get("forwarding")
        if self.request["role"] == "client-a":
            if (not isinstance(state, dict) or set(state) != {"original", "guard", "changed"}
                    or not isinstance(state["original"], dict) or type(state["changed"]) is not bool):
                raise Refusal("fixture forwarding receipt is malformed")
            current = self.native.network_settings(self.forwarding_names())
            if (set(state["original"]) != set(current)
                    or any(type(value) is not int or value not in {0, 1, 2} for value in state["original"].values())
                    or any(value != 0 for key, value in state["original"].items() if key.endswith("forwarding"))):
                raise Refusal("fixture forwarding original values are invalid")
        elif state is not None:
            raise Refusal("peer cannot own forwarding state")
        checked_link(self.request, self.native.inventory(), set(ADDRESSES))

    def ready_addresses(self) -> None:
        """Wait boundedly for both assigned fixture addresses to finish DAD."""
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            private = checked_link(self.request, self.native.inventory(), set(ADDRESSES))
            ready = set()
            for row in private.get("addr_info", []):
                if row.get("dadfailed") or "dadfailed" in row.get("flags", []):
                    raise Refusal("fixture address duplicate detection failed")
                if row.get("tentative") or "tentative" in row.get("flags", []):
                    continue
                ready.add(str(ipaddress.ip_interface(f"{row['local']}/{row['prefixlen']}")))
            if set(ADDRESSES) <= ready:
                return
            time.sleep(0.05)
        raise Refusal("fixture addresses did not become ready")

    def start(self) -> dict[str, Any]:
        """Create a fresh admitted fixture, restoring owned state on failure."""
        if self.root.exists() or self.root.is_symlink() or self.receipt.exists() or self.receipt.is_symlink():
            raise Refusal("fixture reuse is forbidden")
        previous = checked_link(self.request, self.native.inventory(), set())
        forwarding = self.forwarding_snapshot()
        self.root.mkdir(mode=0o700)
        self.journal = {"binding": binding(self.request), "root_identity": identity(self.root, True),
                        "previous_up": "UP" in previous.get("flags", []), "addresses": list(ADDRESSES),
                        "processes": {}, "phase": "prepared", "forwarding": forwarding}
        self.save()  # Original directory and intended address ownership precede use.
        try:
            self.enable_forwarding()
            name = self.request["private"]["name"]
            self.native.run(["ip", "link", "set", "dev", name, "up"])
            for address in ADDRESSES:
                self.native.run(["ip", "address", "add", address, "dev", name])
            self.ready_addresses()
            if self.request["role"] == "client-a":
                for daemon, text in configurations(self.request).items():
                    path = self.root / f"{daemon}.conf"
                    with path.open("x", encoding="utf-8") as stream:
                        os.chmod(path, 0o600)
                        stream.write(text)
                        stream.flush()
                        os.fsync(stream.fileno())
                    arguments = (["dnsmasq", "--no-daemon", f"--conf-file={path}"] if daemon == "dnsmasq" else
                                 ["radvd", "-n", "-m", "stderr", "-C", str(path), "-p", str(self.root / "radvd.pid")])

                    def publish(process: dict[str, Any], daemon: str = daemon) -> None:
                        """Publish original process identity before it may execute.

                        Args:
                            process: Stopped child's original identity.
                            daemon: Fixed server name whose receipt is being added.
                        """
                        self.journal["processes"][daemon] = process
                        self.save()

                    self.native.spawn(arguments, publish)
            self.journal["phase"] = "active"
            self.save()
            return self.status()
        except (OSError, ValueError, subprocess.SubprocessError):
            self.stop()
            raise

    def status(self) -> dict[str, Any]:
        """Return live processes, actual leases, and admitted address observations."""
        private = checked_link(self.request, self.native.inventory(), set(ADDRESSES))
        processes = {name: self.native.require_live(process) for name, process in self.journal["processes"].items()
                     if self.journal["phase"] != "stopped"}
        leases = self.root / "leases"
        lease_rows = []
        forwarding_observed = None
        state = self.journal["forwarding"]
        if state is not None:
            forwarding_observed = self.native.network_settings(self.forwarding_names())
            expected = dict(state["original"])
            if self.journal["phase"] == "active":
                expected["net.ipv6.conf.all.forwarding"] = 1
            if forwarding_observed != expected or self.native.guard() != state["guard"]:
                raise Refusal("fixture forwarding runtime changed")
        if leases.exists() or leases.is_symlink():
            info = leases.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 65536:
                raise Refusal("unsafe DHCP lease file")
            lease_rows = parse_leases(leases.read_text(), self.request["appliance_mac"], int(time.time()))
        return {"schema": 1, "ok": True, "role": self.request["role"], "phase": self.journal["phase"],
                "topology_sha256": self.request["topology_sha256"], "receipt_path": str(self.receipt),
                "private_addresses": private.get("addr_info", []), "processes": processes, "leases": lease_rows,
                "forwarding": state, "forwarding_observed": forwarding_observed}

    def stop(self) -> dict[str, Any]:
        """Stop only original processes and restore the initially empty private link."""
        self.load()
        for process in self.journal["processes"].values():
            self.native.stop(process)
        self.restore_forwarding()
        name = self.request["private"]["name"]
        private = checked_link(self.request, self.native.inventory(), set(ADDRESSES))
        existing = {str(ipaddress.ip_interface(f"{row['local']}/{row['prefixlen']}")) for row in private.get("addr_info", [])}
        for address in ADDRESSES:
            if address in existing:
                self.native.run(["ip", "address", "del", address, "dev", name])
        if not self.journal["previous_up"]:
            self.native.run(["ip", "link", "set", "dev", name, "down"])
        restored = checked_link(self.request, self.native.inventory(), set())
        if ("UP" in restored.get("flags", [])) != self.journal["previous_up"]:
            raise Refusal("private link restoration unproven")
        self.journal["phase"] = "stopped"
        self.save()
        return self.status()

    def execute(self) -> dict[str, Any]:
        """Execute the one admitted action, preserving uncertain state."""
        action = self.request["action"]
        if action == "start":
            return self.start()
        self.load()
        if action == "stop":
            return self.stop()
        if action == "status":
            return self.status()
        daemon = "dnsmasq" if action.endswith("dhcp") else "radvd"
        if self.request["role"] != "client-a" or self.journal["phase"] != "active":
            raise Refusal("server action requires an active client-a fixture")
        process = self.journal["processes"][daemon]
        self.native.require_live(process)
        self.native.signal(process, linux_value(signal, "SIGSTOP") if action.startswith("pause") else linux_value(signal, "SIGCONT"))
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            current = self.native.require_live(process)
            if (current["state"] == "T") == action.startswith("pause"):
                return self.status()
            time.sleep(0.01)
        raise Refusal("server pause or resume unproven")


def main() -> int:
    """Run only as root on Linux, under a fixed non-replaced ownership lock."""
    if sys.platform != "linux" or linux_value(os, "geteuid")() != 0:
        raise Refusal("guest controller requires Linux root")
    import fcntl

    raw = sys.stdin.buffer.read(65537)
    if len(raw) > 65536:
        raise Refusal("request exceeds bound")
    request = validate_request(json.loads(raw))
    lock_path = ROOT.with_suffix(".lock")
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        identity(lock_path)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(json.dumps(Controller(request, Native()).execute(), sort_keys=True))
    finally:
        os.close(descriptor)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps({"schema": 1, "ok": False, "error": str(exc) if isinstance(exc, Refusal) else type(exc).__name__}))
        raise SystemExit(2) from None
