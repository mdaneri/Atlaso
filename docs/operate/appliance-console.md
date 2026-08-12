---
title: Local appliance console
description: Use the local Photon appliance console for status, recovery, and administrative access.
audience:
  - operator
status: current
---

# Local appliance console

Use the local console when the management UI is unavailable or when you need direct status and recovery controls.
Atlaso owns only the first virtual terminal (`tty1`); `Alt+F2`, `Alt+F3`, and later terminals keep the normal Photon
login prompt.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso Photon appliance console showing management networking and service status.](../assets/screenshots/appliance-console-applied.webp)

*Figure: VMware console after a successful appliance apply.*

<!-- END GENERATED INTERFACE OVERVIEW -->

## Before you begin

- Open the VM console in VMware Workstation or Hyper-V.
- Use the Photon `root` password for authenticated recovery actions.
- Treat console networking and service changes as real appliance mutations.
- Prefer the web UI for routine desired-state editing when it is reachable.

## Read the main screen

The main screen refreshes every five seconds and shows:

- the Atlaso and Photon versions, architecture, kernel, CPU, memory, and load;
- management interfaces, addresses, gateways, address modes, DNS servers, and management URLs;
- desired and runtime state for Atlaso-managed services; and
- the available function-key actions.

During the first 30 seconds after startup, a missing interface inventory is shown as
**Initializing appliance networking...**. If the interface remains missing after that period, the console reports the
normal actionable error.

A raw VMware VM with no OVF envelope confirms that state through 30 consecutive successful empty VMware Tools reads.
Atlaso then records non-OVF first-boot completion, logs **No OVF deployment properties supplied; using image
defaults.**, clears the initialization lock and any stale network-review handshake, and opens the ordinary console.
The warning does not require input. A reboot uses the durable marker and does not repeat the confirmation wait. If the
same disk is later deployed with a real OVF envelope, Atlaso discards the non-OVF classification and validates the
supplied deployment properties normally.

## Correct invalid VMware OVF networking on first boot

An OVF/OVA deployment with inconsistent management networking pauses before the network or data disks are initialized.
The console displays **First-time initialization — Network configuration requires review** and the non-secret OVF
address, gateway, DNS, and appliance-name values. This screen does not depend on management-network readiness.
From the first tty1 screen until the deployment root password applies, only Help and the bounded network-review action
are available; Customize, process monitor, root shell, and power actions remain locked.

1. Press `F2` or `Enter`.
2. Correct the prepopulated IPv4 and IPv6 modes, addresses, gateways, and DNS servers.
3. Select **Apply**, review the values, and choose **Continue initialization**.
4. Wait for the normal appliance console to replace the review state.
5. Verify `https://<management-address>/openapi.json` from another machine.

Static IPv4 and IPv6 gateways must be reachable through their configured prefix and cannot equal the interface address.
For IPv4 prefixes shorter than `/31`, both the interface and gateway must also be usable host addresses rather than the
network or broadcast address; `/31` point-to-point peers remain valid. An IPv6 link-local gateway is also valid. The OVF
customizer validates the complete correction before making any host change. The first-boot flow does not request,
display, or persist deployment passwords: it retains the original OVF credentials in the waiting customizer and accepts
only non-secret network corrections from the console.

Atlaso validates the FQDN, required properties, credentials, and root-SSH boolean before offering network-only
correction. If initialization stays on the starting screen and no network review appears, correct those non-network OVF
properties in the hypervisor and restart the deployment, or redeploy with corrected values. When VMware Tools has not
yet supplied a complete valid set of Atlaso OVF properties, the customizer keeps tty1 privileged actions locked and
retries unanswered, unreadable, malformed, incomplete, or invalid non-network responses instead of using the
image-build credentials; redeploy if valid properties never become available. Only a successful empty response can
contribute to the bounded non-OVF confirmation. A present envelope without complete valid properties remains blocked.
A reboot after successful customization removes any stale review document by trusting the redacted applied marker.
If a later customization step fails after either the original or corrected network validates, the review screen remains
backed by the waiting customizer. Resolve the safe condition named in
`/var/log/atlaso/vmware-ovf-customize.log`, then resubmit the network review to retry; the applied marker remains absent
until the retry succeeds. Before a retry changes the host, Atlaso durably removes any pending-success record left by the
earlier attempt, so an interruption cannot promote stale state on the next boot.

Credential scrub and applied-marker finalization occur after host customization has already succeeded. Those layers
retry from the durable pending-success marker without returning to network review, because changing DHCP or static
values cannot resolve deployment-property cleanup. A successful scrub clears `guestinfo.ovfEnv` through VMware Tools,
promotes the applied marker, removes the initialization/review handshake, and opens the ordinary console.

Service state uses compact labels:

| Label       | Meaning                                            |
| ----------- | -------------------------------------------------- |
| `▶ on/off`  | The runtime is running.                            |
| `■ on/off`  | The runtime is stopped.                            |
| `! crashed` | A backing unit failed.                             |
| `? on`      | The service is enabled but runtime is unavailable. |

## Choose an action

| Key   | Action                 | Authentication | Use it for                                                   |
| ----- | ---------------------- | -------------- | ------------------------------------------------------------ |
| `F1`  | Help                   | None           | Screen regions, state legend, navigation, and safety notes.  |
| `F2`  | Customize              | Root password  | Management networking, DNS, Firewall, and service isolation. |
| `F3`  | Process monitor        | Root password  | A temporary interactive `top` session.                       |
| `F4`  | Root shell             | Root password  | Advanced diagnosis when bounded recovery is insufficient.    |
| `F12` | Restart or shut down   | Root password  | Audited appliance power actions with confirmation.           |

Authentication is required again every time an authenticated action opens. Atlaso does not reuse a password or an
authorization result between menus.

## Recover management networking

1. Press `F2` and authenticate as Photon `root`.
2. Open the management network editor.
3. Choose the IPv4 and IPv6 modes.
4. Enter static addresses and gateways only when the corresponding mode is **Static**.
5. Enter external DNS servers.
6. Review the values and submit the change.
7. Wait while Atlaso applies corrected Network and Firewall state, retries unfinished first-boot HTTPS, applies
   Appliance Settings, and verifies local application plus nginx readiness.
8. Confirm that the console reports both appliance-apply task IDs and shows the expected management address and URL.
9. Verify that `http://<management-address>/` redirects to HTTPS from another machine.
10. Verify that `https://<management-address>/openapi.json` returns HTTP 200 from another machine.

The editor supports IPv4 DHCP or static configuration. IPv6 can be disabled, automatic through RA/SLAAC, or static.
Static IPv4 and IPv6 gateways must be on-link and cannot equal their interface address; an IPv6 gateway may instead be
link-local.

The recovery action updates Atlaso desired state and submits two synchronous, scoped global appliance-apply tasks. The
first always applies Network and Firewall so stale management-source restrictions cannot survive an address correction.
Atlaso then retries first-boot HTTPS only when its completion marker is absent, validates nginx before any reload, and
ensures nginx and Atlaso are enabled and running. After the second task applies Appliance Settings, the console requires
five stable local checks: application `/openapi.json` on port 8000 plus the applied nginx management mode. HTTPS mode
requires the HTTP redirect and HTTPS `/openapi.json`; HTTP-only mode requires HTTP `/openapi.json`.

It never falls back to unvalidated host commands. A validation, bootstrap, firewall, nginx, service, or readiness
failure names the failing layer on the console and leaves unapplied desired state pending for review in the web UI.

## Isolate or restore appliance services

Use **Disable all appliance services** when troubleshooting requires maintenance isolation. Atlaso records the current
enabled and active state, stops the application services, and preserves the console, management networking, resolver,
and firewall persistence services.

While isolation is active, the action changes to **Restore appliance services**. Restore uses the saved state and does
not enable units that were previously disabled.

## Open a process monitor or root shell

- Press `F3`, authenticate, and use `top`. Press `q` to return to the Atlaso screen.
- Press `F4`, authenticate, and use the root Bash session only for necessary diagnosis. Run `exit` or press `Ctrl+D` to
  return.

Root-shell open and close events are audited as `console:root`. The screen is cleared before the status interface is
redrawn.

## Restart or shut down

Press `F12`, authenticate, choose the power action, and confirm it. Restart and shutdown use the delayed, audited,
constrained power helper. `Ctrl+Alt+Del` is disabled so it cannot bypass this workflow.

## Verify recovery

After any console change:

1. Check the displayed management addressing and service exceptions.
2. Open the management URL from another machine.
3. Verify `/openapi.json`.
4. Review the resulting task and audit event in the web UI.
5. Resolve or roll back any desired state left pending by a failed action.

For systemd ownership, redraw behavior, GRUB branding, service-isolation boundaries, and configuration paths, see the
[local console technical reference](../reference/appliance-console-technical.md).
