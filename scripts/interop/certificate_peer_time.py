"""Private NTP fixture backed by the peer's existing synchronized clock."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
from datetime import datetime, timezone
from typing import Any


class Refusal(Exception):
    """Fixed public reason preventing use of the peer as a clock authority."""


CONFIG = "/usr/local/etc/atlaso-certificate-peer-chrony.conf"
INSTALLER = "/usr/local/sbin/atlaso-certificate-peer-chrony"


def peer_time_files(address: str, clients: list[str]) -> dict[str, str]:
    """Render bounded server access without replacing any upstream clock sources.

    Args:
        address: Original private peer IPv4 address.
        clients: DHCP, static baseline and candidate appliance IPv4 addresses.
    """
    peer = ipaddress.IPv4Address(address)
    admitted = [ipaddress.IPv4Address(value) for value in clients]
    if (len(admitted) != 3 or len(set(admitted)) != 3 or peer in admitted
            or any(value.is_unspecified or value.is_multicast or value.is_loopback for value in [peer, *admitted])):
        raise ValueError("Three distinct appliance addresses and one distinct peer are required.")
    config = f"port 123\nbindaddress {peer}\nbindaddress ::1\n"
    config += "".join(f"allow {value}/32\n" for value in sorted([peer, *admitted]))
    installer = """#!/bin/sh
set -eu
base=/etc/chrony/chrony.conf
backup=/etc/chrony/chrony.conf.atlaso-certificate-before-serving
[ -f "$base" ] && [ ! -L "$base" ] && [ ! -e "$backup" ]
for service in ntpd openntpd; do
  if rc-service "$service" status >/dev/null 2>&1; then exit 1; fi
done
# This fixture never introduces a second controller or a synthetic local clock.
if apk info -e open-vm-tools-timesync >/dev/null 2>&1; then exit 1; fi
rc-service chronyd status >/dev/null
chronyc waitsync 10 0.1 0 1 >/dev/null
if chronyd -p | grep -Eq '^(allow|deny|bindaddress|binddevice|port|local|refclock)[[:space:]]'; then exit 1; fi
cp -p "$base" "$backup"
printf '\\ninclude /usr/local/etc/atlaso-certificate-peer-chrony.conf\\n' >> "$base"
chronyd -p >/dev/null
rc-service chronyd restart >/dev/null
chronyc waitsync 10 0.1 0 1 >/dev/null
"""
    return {CONFIG: config, INSTALLER: installer}


def verify_peer_time(peer: Any, address: str, clients: list[str]) -> dict[str, Any]:
    """Verify real synchronization, restricted serving and a genuine UDP reply.

    Args:
        peer: Original pinned SSH peer exposing bounded command execution.
        address: Original private peer IPv4 address.
        clients: Three admitted appliance addresses.
    """
    expected = peer_time_files(address, clients)[CONFIG].encode()
    singleton = peer.command(
        "for service in ntpd openntpd; do if rc-service \"$service\" status >/dev/null 2>&1; then exit 1; fi; done; "
        "if apk info -e open-vm-tools-timesync >/dev/null 2>&1; then exit 1; fi; "
        "rc-service chronyd status >/dev/null && echo chronyd_only"
    )
    if singleton.strip() != b"chronyd_only":
        raise Refusal("peer_time_competing_controller")
    if peer.command("cat " + CONFIG) != expected:
        raise Refusal("peer_time_configuration_changed")
    tracking = peer.command("sudo -n chronyc -n tracking").decode("ascii")
    fields = dict(line.split(":", 1) for line in tracking.splitlines() if ":" in line)
    fields = {key.strip(): value.strip() for key, value in fields.items()}
    sources = peer.command("sudo -n chronyc -n sources").decode("ascii").splitlines()
    selected = [line.split()[1] for line in sources if line.startswith("^* ")]
    try:
        stratum = int(fields.get("Stratum", "0"))
        upstream = ipaddress.IPv4Address(selected[0]) if len(selected) == 1 else None
    except (ValueError, IndexError):
        raise Refusal("peer_time_not_synchronized") from None
    if (fields.get("Leap status") != "Normal" or not 1 <= stratum <= 15 or upstream is None
            or upstream.is_loopback or str(upstream) == address):
        raise Refusal("peer_time_not_synchronized")
    try:
        reference = datetime.strptime(fields["Ref time (UTC)"], "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc).timestamp()
        interval = float(fields["Update interval"].split()[0])
        system_offset = float(fields["System time"].split()[0])
        peer_seconds = int(peer.command("date -u +%s").strip())
    except (KeyError, ValueError, OverflowError):
        raise Refusal("peer_time_freshness_unproven") from None
    # Chrony disciplines this peer from its real selected upstream. The Windows
    # controller is an observer, not an NTP authority: compare source freshness
    # with the peer's clock and require Chrony's measured system offset instead
    # of making an unrelated host-clock skew a fixture prerequisite.
    if (not math.isfinite(interval) or interval < 0 or not math.isfinite(system_offset)
            or abs(system_offset) > 0.1 or not 0 <= peer_seconds - reference <= max(120, interval * 2 + 60)):
        raise Refusal("peer_time_freshness_unproven")
    parsed = peer.command("sudo -n chronyd -p").decode("ascii").splitlines()
    if any(line.split() and line.split()[0] in {"local", "refclock"} for line in parsed):
        raise Refusal("peer_time_synthetic_source_refused")
    directives = [line.split() for line in parsed if line.split()]
    binds = [row[1:] for row in directives if row[0] == "bindaddress"]
    allowed = [row[1:] for row in directives if row[0] == "allow"]
    wanted = {str(ipaddress.IPv4Network(value + "/32")) for value in [address, *clients]}
    try:
        allowed_networks = {str(ipaddress.IPv4Network(row[0], strict=False)) for row in allowed if len(row) == 1}
    except ValueError:
        raise Refusal("peer_time_effective_scope_changed") from None
    if (len(binds) != 2 or {tuple(row) for row in binds} != {(address,), ("::1",)}
            or len(allowed) != 4 or any(len(row) != 1 for row in allowed) or allowed_networks != wanted
            or [row[1:] for row in directives if row[0] == "port"] != [["123"]]
            or any(row[0] in {"binddevice", "deny"} for row in directives)):
        raise Refusal("peer_time_effective_scope_changed")
    # The request nonce is its real transmit timestamp. No clock is adjusted by
    # this unprivileged query; every returned value comes from chronyd's reply.
    program = f"""import json,socket,struct,time
address={str(ipaddress.IPv4Address(address))!r}
stamp=time.time()+2208988800
nonce=struct.pack('!II',int(stamp),int((stamp%1)*2**32))
request=b'\\x23'+b'\\0'*39+nonce
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
 client.settimeout(5);client.bind((address,0));client.sendto(request,(address,123))
 reply,remote=client.recvfrom(4096)
assert remote==(address,123) and len(reply)>=48 and reply[0]&7==4 and reply[0]>>6!=3
assert reply[24:32]==nonce and 1<=reply[1]<=15
seconds,fraction=struct.unpack('!II',reply[40:48])
assert abs(seconds+fraction/2**32-2208988800-time.time())<2
print(json.dumps({{'stratum':reply[1],'real_udp_reply':True}}))
"""
    result = json.loads(peer.command("python3 -I -B -", stdin=program.encode()))
    if result != {"stratum": stratum, "real_udp_reply": True}:
        raise Refusal("peer_time_reply_invalid")
    return {"kind": "certificate-peer-time", "address": address, "stratum": stratum,
            "upstream": str(upstream), "synchronized": True, "real_udp_reply": True,
            "system_offset_seconds": system_offset,
            "configuration_sha256": hashlib.sha256(expected).hexdigest()}
