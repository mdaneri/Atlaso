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
menu, or ordinary desired-state editor. A root-owned initialization lock is present in the reusable VMware image, so
those privileged actions are unavailable from the moment tty1 starts until customization applies the deployment root
password and completes. A confirmed no-envelope boot removes that lock without opening network review and therefore
restores the same ordinary authenticated console actions.

## VMware first-boot network review

`atlaso-vmware-ovf-customize.service` and the console use `atlaso.app.management_network` for the same IPv4, IPv6, and
DNS validation rules. Static gateways must be on-link for their configured prefix and cannot equal the interface
address. IPv4 network and broadcast addresses are rejected for both the interface and gateway when the prefix is
shorter than `/31`, while both `/31` point-to-point peers remain usable; an IPv6 gateway may instead be link-local. The
customizer validates all OVF management fields before the first host mutation. It first validates the FQDN, required
properties, credentials, and root-SSH boolean because the network-only console handshake cannot correct those fields.

The VMware Tools read contract preserves both the answer signal and returned content. Thirty consecutive answered-empty
reads confirm that no OVF envelope was supplied without racing a delayed injection. Atlaso atomically records
`/var/lib/atlaso/vmware-no-ovf-initialization.applied`, clears the review/correction files and initialization lock, and
logs **No OVF deployment properties supplied; using image defaults.** The normal console and remaining first-boot units
then continue. An unanswered Tools channel resets empty confirmation and remains fail-closed. Malformed XML, a present
envelope with no complete property set, invalid non-network properties, and invalid management relationships also remain
blocked. On reboot, the durable non-OVF marker avoids the confirmation loop. A later nonempty envelope invalidates that
marker durably before entering the ordinary validation and customization path.

When validation fails, the customizer atomically writes a bounded, non-secret review document under
`/var/lib/atlaso` and waits without starting networkd, data-disk initialization, bootstrap HTTPS, or Atlaso. The console
prepopulates its existing management form from that document and atomically submits only allowlisted network fields in
a mode-`0600` correction document. OVF passwords remain only in customizer memory and never enter either document or
the console.

The customizer consumes a correction, revalidates the complete merged OVF configuration, applies it, and writes the
redacted applied marker only after every mutation succeeds. A validation or apply failure leaves the marker absent,
updates the review state without exception-derived command output, and permits another correction. Before that retry
starts host mutation, it durably invalidates any pending-success record from the preceding attempt so restart recovery
cannot promote stale state. After every host mutation succeeds, the customizer synchronizes host filesystem state before
durably writing pending success, so restart recovery cannot promote a marker ahead of its configuration. Because tty1
starts while that lock is present, customization restarts `atlaso-console.service` after rotating the appliance secret
keys and before the durability barrier; the replacement process loads the applied keys before privileged actions unlock.
Success removes both handshake documents plus the initialization lock and releases the remaining first-boot units. If
interruption occurs after marker creation but before cleanup, the next customizer start
recovers the pending marker only when the OVF environment is already empty or its non-secret raw-clone deployment
identifier matches. Any nonempty ID-less environment, including a release OVA redeployment, is reapplied rather than
promoting possibly stale source state. Empty guestinfo must remain conclusively empty for 30 one-second reads before it
proves scrub completion; properties that appear during that window are applied as a replacement deployment. An
interrupted original OVA apply is safe to reapply idempotently. The applied marker removes the stale handshake and lock
before exiting.

VMware deployment-property cleanup sets `guestinfo.ovfEnv` to the explicit empty string through either
`vmware-rpctool` or `vmtoolsd`. A credential-scrub or applied-marker failure after pending success is durable enters the
finalization retry loop directly and clears the network-review handshake. It must never ask the operator to resubmit
DHCP or static values after the management network has already validated and applied. VMware Tools may return that
cleared value as the exact quoted-empty sentinel `""`; the reader normalizes only that sentinel to answered-empty before
running the stable-empty confirmation.

DHCP OVF customization may leave the legacy management-source CIDR empty because the generated Firewall service rules
bind management access to the effective interface instead. When those generated rules replace the legacy rule, config
rendering does not parse or emit the unused CIDR. Static deployments continue to validate and use their explicit source
network.

OVF XML password attributes are consumed exactly as parsed rather than trimmed. This preserves valid leading or trailing
spaces supplied through a release deployment instead of applying a different credential or leaving initialization
locked on a shortened value.

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
readiness check runs again. Ordinary Appliance Settings proves the existing loopback upstream before nginx publication,
does not restart the active Atlaso worker, and rolls back the candidate front-door files when post-activation readiness
does not stabilize.

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
