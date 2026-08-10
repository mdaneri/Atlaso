---
title: Local console technical reference
description: Implementation contracts for the Atlaso tty1 recovery console, service state, and boot presentation.
audience:
  - maintainer
  - operator
status: current
---

# Local console technical reference

This page records implementation and maintenance contracts for the Photon appliance console. Operators looking for
recovery steps should start with the [local appliance console guide](../operate/appliance-console.md).

## Terminal ownership

- `atlaso-console.service` owns `/dev/tty1`, conflicts with `getty@tty1.service`, and restarts automatically.
- Image provisioning masks only `getty@tty1.service`; later virtual terminals retain normal Photon login prompts.
- The appliance masks `ctrl-alt-del.target` and sets `CtrlAltDelBurstAction=none`.
- systemd uses `ShowStatus=no` so unit progress does not overwrite the full-screen console.
- The minimum supported terminal is 72 columns by 22 rows. Smaller terminals show only the resize requirement.

## Refresh and redraw

The console refreshes every five seconds and after resize or completed actions. Set
`ATLASO_CONSOLE_REFRESH_SECONDS` in `/etc/atlaso/atlaso.env` to an integer from 1 through 300 and restart
`atlaso-console.service` to change the interval. Invalid values fall back to five seconds.

Completed actions and returns from interactive processes force a physical redraw. Additional bounded redraws at 1, 3,
and 8 seconds repair late terminal writes without continuous flicker.

During the first 30 seconds after tty1 starts, a not-yet-created management-interface inventory is represented by
**Initializing appliance networking...**. Unrelated failures remain immediately visible. After the grace period, a
still-missing management interface becomes the normal actionable error.

## Header and management presentation

The header shows the Atlaso version, Photon version, normalized architecture, kernel, CPU, memory, and 1/5/15-minute
load averages. `x86_64` and `AMD64` normalize to `amd64`; `aarch64` and `arm64` normalize to `arm64`.

Load remains in the normal header color below 75% of the logical CPU count, becomes amber when any average reaches 75%,
and becomes red when any average reaches 100%.

The management block uses stable columns for interface, IPv4 address/gateway/mode, IPv6 address/gateway/mode, and DNS.

## Desired and runtime service state

The **Appliance services** projection covers Authentication, Certificate Authority, DHCP, DNS, ESX Storage NFS, ESXi
PXE, Firewall, KMS/KMIP, Managed LDAP, NTP/NTS, Routing, VCF Backup SFTP, VCF Offline Depot, and VCF Private Registry.

Desired enablement and backing systemd state are evaluated independently:

- `▶ on` or `▶ off`: runtime running;
- `■ on` or `■ off`: runtime stopped;
- `! crashed`: backing unit failed; and
- `? on`: desired enabled but runtime unavailable.

An absent optional unit is stopped while the service is intentionally disabled. It is unavailable only when desired
state requires a runtime that the appliance cannot provide. Firewall desired state remains independent from readiness
of `atlaso-firewall.service`.

The normal 80×30 tty renders the complete service list in two columns. Shorter supported terminals show aggregate
counts and exceptions.

## Authentication boundaries

`F2`, `F3`, `F4`, and `F12` each require the Photon root password on every entry. Authorization is discarded when the
selected action closes and is never reused across menus.

`F4` shell sessions record open and close audit events with actor `console:root`. The password is not retained or
logged.

## Management editor contract

The `F2` management editor supports:

- IPv4 DHCP or static address/prefix with an optional on-link gateway;
- IPv6 Disabled, Automatic RA/SLAAC, or static address/prefix with an optional gateway;
- external DNS servers;
- persistent Firewall enablement; and
- reversible appliance-service isolation.

Static fields remain disabled unless their address family uses Static mode. A static IPv6 gateway must be within the
configured prefix or link-local (`fe80::/10`) and cannot equal the interface address. Disabled or Automatic IPv6 clears
stored static IPv6 address and gateway state.

Network, DNS, and Firewall edits update desired state and create two synchronous global appliance-apply tasks with actor
`console:root`. The first selects Network and Firewall together for every management correction. This guarantees that
the persisted nftables rules are regenerated from the corrected management CIDR instead of retaining an OVF-derived
source restriction. Other pending units remain unselected.

After the first task, the constrained console helper retries `atlaso-bootstrap-https.service` when
`/var/lib/atlaso/first-boot-https.applied` is absent. The bootstrap marker is created only after CA apply produces the
managed certificate/key and `nginx -t` succeeds. The helper validates nginx before reload, enables nginx and Atlaso,
starts an inactive control plane, and requires five consecutive local readiness samples: HTTP 200 from uvicorn
`/openapi.json` plus the applied nginx contract. HTTPS mode requires HTTP 308 and HTTPS `/openapi.json` 200; HTTP-only
mode requires HTTP `/openapi.json` 200. Appliance Settings is then applied as the second task and the same idempotent
readiness check runs again so its delayed Atlaso restart cannot produce a false success.

The console rejects changes while another appliance-apply task is active. The selected helper path runs as a real local
recovery action even when ordinary adapters use dry-run. Validation, bootstrap, nginx, service, and readiness failures
identify their stage and leave pending desired state for web review; the console never invokes unvalidated fallback
commands.

## Maintenance isolation

Maintenance isolation stores the service enablement and activity snapshot at
`/var/lib/atlaso/console/services.json`. It preserves:

- `atlaso-console.service`;
- `systemd-networkd.service`;
- `systemd-resolved.service`; and
- `atlaso-firewall.service`.

ESX Storage isolation includes `nfs-server.service` and `rpcbind.service` but never unmounts or deletes datastore data.
Restore enables or starts only units recorded as enabled or active.

## Power workflow

Restart and shutdown require an independent `F12` authentication and confirmation. They use the delayed, audited,
constrained appliance-power helper. Power actions do not appear in the `F2` customization menu.

## Boot presentation

GRUB uses a fixed 640×480 Atlaso theme with the Atlaso identity at the top and official Photon OS attribution at the
bottom. The boot entry has a blank display title so the splash remains visible during the five-second automatic boot.

`/opt/atlaso/bin/atlaso-install-boot-branding` installs the root-owned theme under
`/boot/grub2/themes/atlaso`, preserves the original GRUB configuration once as `grub.cfg.atlaso-backup`, and changes
only the theme reference and Photon menu-entry label. It does not add Plymouth or alter boot timing or kernel arguments.
