"""Exercise two owned Atlaso appliances on one existing NAT network."""

from __future__ import annotations

import hashlib
import importlib.util
import ipaddress
import json
import time
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

try:
    from scripts.interop.same_interface_gateway_acceptance import (
        guest_capture_program,
        run_pinned_ssh_command,
        validate_forward_capture,
    )
except ModuleNotFoundError:  # The isolated standalone runner admits this exact sibling only.
    _spec = importlib.util.spec_from_file_location("gateway_capture", Path(__file__).with_name("same_interface_gateway_acceptance.py"))
    if _spec is None or _spec.loader is None:
        raise RuntimeError("Gateway capture support is unavailable.") from None
    _capture = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_capture)
    guest_capture_program = _capture.guest_capture_program
    run_pinned_ssh_command = _capture.run_pinned_ssh_command
    validate_forward_capture = _capture.validate_forward_capture


class GatewayLifecycleError(RuntimeError):
    """Report a bounded acceptance failure without credential diagnostics."""


class _Rows(HTMLParser):
    def __init__(self, attribute: str) -> None:
        super().__init__(convert_charrefs=True)
        self.attribute, self.rows = attribute, []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "div" and self.attribute in values:
            self.rows = json.loads(values[self.attribute] or "[]")


def _active_nat_link(state: dict) -> dict:
    """Require eth0 as the only usable adapter, allowing inert inherited NICs.

    Args:
        state: Native address inventory from the exact owned guest.
    """
    links = [link for link in state["addresses"] if link["ifname"] != "lo"]
    primary = next((link for link in links if link["ifname"] == "eth0"), None)
    if primary is None or any(
        link["ifname"] != "eth0" and (link.get("addr_info") or "UP" in link.get("flags", []))
        for link in links
    ):
        raise GatewayLifecycleError("Only the NAT eth0 adapter may be active or addressed.")
    return primary


def run_same_interface_gateway_acceptance(lifecycle: Any, results: list, args: Any) -> None:
    """Use ordinary browser desired-state and global Apply on receipt-bound clones.

    The caller must first prove both VM receipts, sole-NIC NAT attachment,
    host-facing address ownership and guest-published SSH host keys. This consumer
    never clones, adopts or removes provider resources and never creates API keys.

    Args:
        lifecycle: Existing lifecycle HTTP, Apply, and result helpers.
        results: Lifecycle result collection, containing sanitized evidence only.
        args: Validated controller arguments and secret-stdin credentials.
    """
    router = str(ipaddress.IPv4Address(args.appliance_ssh_host))
    client_ip = str(ipaddress.IPv4Address(args.gateway_client_host))
    upstream = str(ipaddress.IPv4Address(args.gateway_upstream))
    probe = str(ipaddress.IPv4Address(args.gateway_probe_ip))
    if len({router, client_ip, upstream, probe}) != 4:
        raise GatewayLifecycleError("Gateway endpoints must have distinct identities.")
    interface = "eth0"
    fingerprints = {router: args.appliance_ssh_hostkey, client_ip: args.gateway_client_hostkey}
    clients: dict[str, Any] = {}

    def guest(host: str, program: str, *, timeout: int = 30, on_ready: Any = None) -> bytes:
        role = "appliance" if host == router else "client"
        username = lifecycle.ssh_username(args, role)
        command = ("" if username == "root" else "sudo -n ") + "/opt/atlaso/.venv/bin/python -I -"
        return run_pinned_ssh_command(host, username, lifecycle.ssh_password(args, role), fingerprints[host],
            command, stdin_data=program.encode(),
            timeout=timeout, on_ready=on_ready)

    def observe(host: str) -> dict:
        program = '''import json,subprocess,pathlib
def read(*args):
 p=subprocess.run(args,capture_output=True,text=True,timeout=10,check=True);return json.loads(p.stdout)
print(json.dumps({'addresses':read('ip','-j','addr'),'routes':read('ip','-j','route','show','table','all'),
 'rules':read('ip','-j','rule'),'neighbors':read('ip','-j','neigh'),
 'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
 'accept_redirects':{i:pathlib.Path('/proc/sys/net/ipv4/conf/'+i+'/accept_redirects').read_text().strip() for i in ('all','default','eth0')},
 'forward_chain':subprocess.run(['nft','list','chain','inet','atlaso','forward'],capture_output=True,text=True,timeout=10).stdout,
 'translations':subprocess.run(['nft','list','ruleset'],capture_output=True,text=True,timeout=10).stdout.count('masquerade'),
 'forwarding':pathlib.Path('/proc/sys/net/ipv4/ip_forward').read_text().strip()}))
'''
        return json.loads(guest(host, program))

    def rows(host: str, page: str, attribute: str) -> list:
        status, body, _ = clients[host].request("GET", page)
        if status != 200:
            raise GatewayLifecycleError("The desired-state page is unavailable.")
        parser = _Rows(attribute)
        parser.feed(body)
        return parser.rows

    def save(host: str, page: str, action: str, values: dict) -> None:
        status, body, _ = clients[host].request("GET", page)
        if status != 200:
            raise GatewayLifecycleError("The browser editor is unavailable.")
        status, _, _ = clients[host].request("POST", action,
            form={**values, "csrf": lifecycle.extract_csrf(body)}, follow_redirects=False)
        if status not in {200, 303}:
            raise GatewayLifecycleError(f"Browser desired-state save failed (HTTP {status}).")

    def apply(host: str, units: list[str]) -> dict:
        return lifecycle.apply_units(clients[host], units, args)

    def step(name: str, operation: Any) -> Any:
        def safe_operation() -> Any:
            try:
                return operation()
            except GatewayLifecycleError:
                raise
            except Exception:  # noqa: BLE001 - the public lifecycle result must never include credential-bearing transport diagnostics.
                raise GatewayLifecycleError(f"Same-interface acceptance failed at {name}.") from None
        return lifecycle.run_step(results, name, safe_operation)

    initial = {host: step("gateway-inventory-" + role, lambda host=host: observe(host))
               for host, role in ((router, "router"), (client_ip, "client"))}
    macs: dict[str, str] = {}
    cidrs: dict[str, str] = {}
    for host, state in initial.items():
        if state["forwarding"] != "0":
            raise GatewayLifecycleError("Fresh gateway fixtures must start with forwarding disabled.")
        primary = _active_nat_link(state)
        address = next(item for item in primary["addr_info"] if item["family"] == "inet" and item["local"] == host)
        cidrs[host] = f"{host}/{address['prefixlen']}"
        network = ipaddress.ip_interface(cidrs[host]).network
        if any(ipaddress.ip_address(value) not in network for value in (router, client_ip, upstream)):
            raise GatewayLifecycleError("The two appliances and upstream must share the actual NAT subnet.")
        macs[host] = primary["address"]
        client = lifecycle.HttpClient("https://" + host)
        lifecycle.ui_login(client, args)
        clients[host] = client

    expected_hashes = source_hashes(Path(__file__).resolve().parents[2])

    def deployed_source(host: str) -> dict:
        program = '''import atlaso,pathlib,hashlib,json
root=pathlib.Path(atlaso.__file__).parent
paths={'atlaso/app/services/firewall.py':root/'app/services/firewall.py',
'atlaso/app/services/routing_permissions.py':root/'app/services/routing_permissions.py',
'scripts/appliance/atlaso-helper':pathlib.Path('/opt/atlaso/bin/atlaso-helper')}
print(json.dumps({p:hashlib.sha256(f.read_text().encode()).hexdigest() for p,f in paths.items()}))'''
        observed = json.loads(guest(host, program))
        if observed != expected_hashes:
            raise GatewayLifecycleError("The deployed wheel/helper does not match admitted source.")
        return {"source_commit": args.gateway_expected_commit, "normalized_source_hashes": observed}

    step("gateway-router-deployed-source", lambda: deployed_source(router))
    step("gateway-client-deployed-source", lambda: deployed_source(client_ip))

    def fixture_clock(host: str) -> dict:
        status, body, _ = clients[host].request("GET", "/ntp")
        if status != 200:
            raise GatewayLifecycleError("The appliance clock settings are unavailable.")
        parser = lifecycle.NtpFormParser()
        parser.feed(body)
        fields = [(name, value) for name, value in parser.fields if name not in {"enabled", "nts_server_enabled", "time_source"}]
        if not any(name == "csrf" for name, _ in fields):
            raise GatewayLifecycleError("The clock settings form is incomplete.")
        fields.append(("time_source", "vmware_tools"))
        status, _, _ = clients[host].request("POST", parser.form_action, form=fields, follow_redirects=False)
        if status not in {200, 303}:
            raise GatewayLifecycleError("The fixture clock selection was rejected.")
        applied = apply(host, ["ntpd"])
        state = json.loads(guest(host, '''import subprocess,json
tools=subprocess.run(['vmware-toolbox-cmd','timesync','status'],capture_output=True,text=True,timeout=10)
services=subprocess.run(['systemctl','is-active','ntpd.service','chronyd.service','systemd-timesyncd.service'],capture_output=True,text=True,timeout=10)
print(json.dumps({'vmware_timesync':tools.stdout.strip(),'clock_services':services.stdout.splitlines()}))'''))
        if state["vmware_timesync"].lower() != "enabled" or "active" in state["clock_services"]:
            raise GatewayLifecycleError("The fixture must have one verified clock authority.")
        return {"apply": applied, "clock": state}

    step("gateway-router-fixture-clock", lambda: fixture_clock(router))
    step("gateway-client-fixture-clock", lambda: fixture_clock(client_ip))

    def configure(host: str, gateway: str, routing: bool) -> dict:
        # Protected management handoff requires desired and applied forwarding off.
        # Stage the lab route while off; an Access-management default still serves
        # appliance-local egress. Forwarding is a separate reviewed Apply below.
        save(host, "/routes-wan", "/routes-wan/settings", {"routing_enabled": ""})
        physical_rows = rows(host, "/physical-interfaces", "data-interfaces")
        physical = next(row for row in physical_rows if row["name"] == interface)
        for other in physical_rows:
            if other["name"] != interface and other.get("oper_state") != "missing":
                save(host, "/physical-interfaces", f"/physical-interfaces/{other['id']}/edit", {
                    "role": "unused", "mode": "unused", "ipv4_method": "static", "ip_cidr": "",
                    "gateway": "", "mtu": "1500", "admin_state": "down", "access_management_ui_enabled": "",
                })
        # Capture the current DHCP gateway in the first transition so the existing
        # management-to-Access service can preserve a reviewed local egress path.
        save(host, "/physical-interfaces", f"/physical-interfaces/{physical['id']}/edit", {
            "role": "access", "mode": "access", "ipv4_method": "static", "ip_cidr": cidrs[host],
            "gateway": upstream, "mtu": "1500", "admin_state": "up", "access_management_ui_enabled": "on",
        })
        defaults = [row for row in rows(host, "/routes-wan", "data-routes") if row["destination_cidr"] == "0.0.0.0/0"]
        action = f"/routes-wan/routes/{defaults[0]['id']}/edit" if defaults else "/routes-wan/routes"
        save(host, "/routes-wan", action, {"default_route": "on", "default_route_family": "4",
             "gateway": gateway, "interface_name": interface, "metric": "100", "enabled": "on", "wan_mode": "interface"})
        save(host, "/firewall", "/firewall/settings", {"enabled": "on", "default_input_policy": "drop",
            "default_forward_policy": "drop", "default_output_policy": "accept", "allow_established": "on",
            "allow_loopback": "on", "allow_icmp": "on"})
        network_result = apply(host, ["network", "wan", "firewall"])
        if routing:
            save(host, "/routes-wan", "/routes-wan/settings", {"routing_enabled": "on"})
            return {"network": network_result, "routing": apply(host, ["wan", "firewall"])}
        return {"network": network_result}

    step("gateway-configure-router", lambda: configure(router, upstream, True))
    step("gateway-configure-client", lambda: configure(client_ip, router, False))
    # This is client-side test instrumentation. Keep it separate from Atlaso
    # desired-state enforcement; prevent redirects from invalidating path proof.
    step("gateway-disable-client-redirects", lambda: json.loads(guest(client_ip, '''import pathlib,subprocess,json
p=pathlib.Path('/etc/sysctl.d/91-atlaso-gateway-acceptance.conf')
text=''.join('net.ipv4.conf.'+i+'.accept_redirects = 0\\n' for i in ('all','default','eth0'))
if p.exists(): raise RuntimeError('Fixture path already exists')
p.write_text(text)
subprocess.run(['sysctl','-p',str(p)],capture_output=True,check=True)
subprocess.run(['ip','route','flush','cache'],capture_output=True,check=True)
print(json.dumps({'redirects_disabled':True}))''')))

    def probe_connection(host: str, expected: bool) -> dict:
        program = f'''import socket,json
s=socket.socket();s.settimeout(5)
r=s.connect_ex(({probe!r},443));s.close()
print(json.dumps({{'connected':r==0}}))'''
        evidence = json.loads(guest(host, program))
        if evidence["connected"] != expected:
            raise GatewayLifecycleError("External IPv4 connection disagrees with permission state.")
        return evidence

    def captured(expected: bool) -> dict:
        state = observe(client_ip)
        _active_nat_link(state)
        if any(value != "0" for value in state["accept_redirects"].values()):
            raise GatewayLifecycleError("The client can accept ICMP redirects.")
        defaults = [route for route in state["routes"] if route.get("dst") == "default"]
        if not defaults or any(route.get("gateway") != router or route.get("dev") != interface for route in defaults):
            raise GatewayLifecycleError("The client has an alternate default path.")
        route = json.loads(guest(client_ip, "import subprocess,json;print(subprocess.check_output(['ip','-j','route','get'," + repr(probe) + "],text=True))"))[0]
        if route.get("gateway") != router or route.get("dev") != interface:
            raise GatewayLifecycleError("The client probe would bypass the router.")
        probe_connection(router, True)
        router_state = observe(router)
        _active_nat_link(router_state)
        if router_state["forwarding"] != "1" or "policy drop;" not in router_state["forward_chain"] or router_state["translations"]:
            raise GatewayLifecycleError("The router must forward with the default drop firewall and no masquerade.")
        router_path = json.loads(guest(router,
            "import subprocess;print(subprocess.check_output(['ip','-j','route','get'," + repr(probe) + ",'from'," + repr(client_ip) + ",'iif','eth0'],text=True))"))[0]
        if router_path.get("gateway") != upstream or router_path.get("dev") != interface or router_path.get("table") not in {200, "200", "atlaso_lab"}:
            raise GatewayLifecycleError("Forwarded client traffic must select the reviewed lab gateway.")
        neighbors = router_state["neighbors"]
        gateway_mac = next(row["lladdr"] for row in neighbors if row["dst"] == upstream and row["dev"] == interface)
        output = guest(router, guest_capture_program(client_ip, probe, interface, duration=9), timeout=25,
                       on_ready=lambda: probe_connection(client_ip, expected))
        records = [json.loads(line) for line in output.splitlines()]
        if records[-1].get("event") != "complete":
            raise GatewayLifecycleError("Packet capture did not complete.")
        frames = [{key: value for key, value in record.items() if key != "event"}
                  for record in records if record.get("event") == "frame"]
        proof = validate_forward_capture(frames, client_mac=macs[client_ip], router_mac=macs[router],
            gateway_mac=gateway_mac, client_ip=client_ip, probe_ip=probe, expected_forwarded=expected)
        return {"packet_proof": proof, "frames": frames, "client_route": route, "router_route": router_path,
                "client_state": state, "router_state": router_state}

    step("gateway-router-external-ip", lambda: probe_connection(router, True))
    step("gateway-client-blocked-before-permission", lambda: captured(False))

    permission = {"name": "Same-interface gateway acceptance", "source_interface": interface,
        "destination_interface": interface, "policy": "allow", "ip_family": "4", "priority": "100", "enabled": "on"}
    step("gateway-save-browser-permission", lambda: save(router, "/routes-wan", "/routes-wan/routing-rules", permission))
    step("gateway-apply-permission", lambda: apply(router, ["wan", "firewall"]))
    step("gateway-client-forwarded", lambda: captured(True))
    permission_id = next(row["id"] for row in rows(router, "/routes-wan", "data-rules") if row["name"] == permission["name"])
    permission_action = f"/routes-wan/routing-rules/{permission_id}/edit"
    step("gateway-disable-permission", lambda: save(router, "/routes-wan", permission_action, {**permission, "enabled": ""}))
    step("gateway-apply-negative-control", lambda: apply(router, ["wan", "firewall"]))
    step("gateway-router-retains-internet", lambda: probe_connection(router, True))
    step("gateway-client-negative-control", lambda: captured(False))
    step("gateway-restore-permission", lambda: save(router, "/routes-wan", permission_action, permission))
    step("gateway-apply-recovery", lambda: apply(router, ["wan", "firewall"]))
    step("gateway-client-recovered", lambda: captured(True))
    step("gateway-client-dns", lambda: json.loads(guest(client_ip,
        "import socket,json;print(json.dumps({'dns_addresses':sorted({r[4][0] for r in socket.getaddrinfo('example.com',443,family=socket.AF_INET)})}))")))

    for host, role in ((router, "router"), (client_ip, "client")):
        before = observe(host)["boot_id"]
        step("gateway-reboot-" + role, lambda host=host: save(host, "/dashboard", "/appliance/power/reboot", {}))
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            try:
                if observe(host)["boot_id"] != before:
                    lifecycle.ui_login(clients[host], args)
                    break
            except Exception:  # noqa: BLE001 - SSH and HTTPS intentionally disappear during the owned reboot.
                pass
            time.sleep(3)
        else:
            raise GatewayLifecycleError("The owned appliance did not return with a new boot identity.")
    step("gateway-client-forwarded-after-reboots", lambda: captured(True))
    step("gateway-final-router-state", lambda: observe(router))
    step("gateway-final-client-state", lambda: observe(client_ip))


def source_hashes(root: Path) -> dict[str, str]:
    """Return normalized source hashes to bind wheel/helper deployment evidence.

    Args:
        root: Exact clean source checkout admitted by the controller.
    """
    paths = ("atlaso/app/services/firewall.py", "atlaso/app/services/routing_permissions.py", "scripts/appliance/atlaso-helper")
    return {path: hashlib.sha256((root / path).read_text(encoding="utf-8").encode()).hexdigest() for path in paths}
