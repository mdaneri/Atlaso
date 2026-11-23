---
title: Network Diagnostics
description: Run Ping, Traceroute, and DNS lookup from the Atlaso appliance.
audience:
  - operator
status: current
---

# Network Diagnostics

Open **Operations → Network Diagnostics** as an Administrator or Network Administrator. You can also follow the link
beside **Route lookup** in [**Monitor → Network**](monitor.md). Route lookup reports the kernel's choice without sending
packets. [Maintenance diagnostics](diagnostics.md) handles support bundles.

## Run a check

1. Select **Ping**, **Traceroute**, or **DNS lookup**.
2. Enter a unicast IPv4 address, IPv6 address, or hostname. DNS lookup accepts hostnames. IPv6 link-local destinations
   that require an interface zone are currently unsupported.
3. Leave **Address family** set to **Automatic** or select **IPv4** or **IPv6** to test a specific family. For Ping and
   Traceroute, optionally choose an address assigned to an active local interface. The source and destination must use
   the same family. A hostname probe uses the first supported address returned in the requested or source address
   family. With an automatic source and family, it uses the resolver's address order.
4. Select **Run check**. Each submission runs once. Ping sends three ICMP Echo Requests. Traceroute sends one UDP probe
   per hop for up to 12 hops. Both display the local address bound for the probe.

Ping shows replies, loss, and round-trip times. Traceroute shows responding hops and individual timeouts. A hop can
forward traffic without answering a traceroute probe. DNS lookup shows the addresses returned by the appliance
resolver, including local host mappings. It uses the appliance's resolver configuration and does not bind to a selected
probe source.

The result distinguishes invalid targets and sources, name resolution failure, missing routes, no replies, and an
unavailable diagnostic. Results stay in the response. The audit record includes the operator, check type, and outcome.
Running the checks does not save settings or require Appliance Apply.
