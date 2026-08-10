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
- The console starts after local filesystems and virtual-console setup, does not wait for management networking, and
  starts before VMware OVF customization and data-disk initialization.
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

The bounded VMware first-boot network-review form is the exception: it is available before the OVF root password is
applied and accepts only non-secret management-network values. It cannot open the process monitor, root shell, power
menu, or ordinary desired-state editor.

## VMware first-boot network review

`atlaso-vmware-ovf-customize.service` and the console use `atlaso.app.management_network` for the same IPv4, IPv6, and
DNS validation rules. Static gateways must be on-link for their configured prefix and cannot equal the interface
address; an IPv6 gateway may instead be link-local. The customizer validates all OVF management fields before the
first host mutation.

When validation fails, the customizer atomically writes a bounded, non-secret review document under
`/var/lib/atlaso` and waits without starting networkd, data-disk initialization, bootstrap HTTPS, or Atlaso. The console
prepopulates its existing management form from that document and atomically submits only allowlisted network fields in
a mode-`0600` correction document. OVF passwords remain only in customizer memory and never enter either document or
the console.

The customizer consumes a correction, revalidates the complete merged OVF configuration, applies it, and writes the
redacted applied marker only after every mutation succeeds. A validation or apply failure leaves the marker absent,
updates the review state without exception-derived command output, and permits another correction. Success removes
both handshake documents and releases the remaining first-boot units.

## Management editor contract

The `F2` management editor supports:

- IPv4 DHCP or static address/prefix with an optional on-link gateway that differs from the interface address;
- IPv6 Disabled, Automatic RA/SLAAC, or static address/prefix with an optional gateway;
- external DNS servers;
- persistent Firewall enablement; and
- reversible appliance-service isolation.

Static fields remain disabled unless their address family uses Static mode. A static IPv6 gateway must be within the
configured prefix or link-local (`fe80::/10`) and cannot equal the interface address. Disabled or Automatic IPv6 clears
stored static IPv6 address and gateway state.

Network, DNS, and Firewall edits update desired state and create one synchronous global appliance-apply task with actor
`console:root`. The management editor selects Network and Appliance Settings together, adding Firewall only when the
address change affects its rendered validity. Other pending units remain unselected.

The console rejects changes while another appliance-apply task is active. The selected helper path runs as a real local
recovery action even when ordinary adapters use dry-run. Validation and apply failures remain pending for web review;
the console never invokes unvalidated fallback commands.

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
