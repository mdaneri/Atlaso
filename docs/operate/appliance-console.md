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

Static IPv4 and IPv6 gateways must be reachable through their configured prefix and cannot equal the interface address;
an IPv6 link-local gateway is also valid. The OVF customizer validates the complete correction before making any host
change. The first-boot flow does not request, display, or persist deployment passwords: it retains the original OVF
credentials in the waiting customizer and accepts only non-secret network corrections from the console.

Atlaso validates the FQDN, required properties, credentials, and root-SSH boolean before offering network-only
correction. If initialization stays on the starting screen and no network review appears, correct those non-network OVF
properties in the hypervisor and restart the deployment, or redeploy with corrected values. A reboot after successful
customization removes any stale review document by trusting the redacted applied marker.

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
7. Wait for the global appliance-apply task to complete.
8. Confirm that the console shows the expected management address and URL.
9. Verify `https://<management-address>/openapi.json` from another machine.

The editor supports IPv4 DHCP or static configuration. IPv6 can be disabled, automatic through RA/SLAAC, or static.
Static IPv4 and IPv6 gateways must be on-link and cannot equal their interface address; an IPv6 gateway may instead be
link-local.

The recovery action updates Atlaso desired state and submits one synchronous global appliance-apply task. It never
falls back to unvalidated host commands. A validation or apply failure leaves the new desired state pending for review
in the web UI.

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
