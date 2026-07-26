---
title: Web Terminal
description: Open and audit constrained browser terminal sessions on the Atlaso appliance.
audience:
  - operator
status: current
---

# Web Terminal

Atlaso provides a permission-controlled browser terminal for the appliance shell. It is disabled globally by default and
appears under **Operations > Web terminal** on management after it is enabled in **Settings** and the related appliance
changes are applied. Selected additional listeners expose it through the Public Services portal instead of the admin
shell.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso Web terminal page in the clean-appliance desktop viewport.](../assets/screenshots/terminal-clean-desktop.webp)

*Figure: Web terminal in the verified clean-appliance desktop state.*

<!-- END GENERATED INTERFACE OVERVIEW -->

## Configure access

1. Enable **Management UI HTTPS**.
2. Enable **Web terminal access**.
3. Select any additional addressed interfaces in **Web terminal interfaces**. The management interface is always
   selected and cannot be removed.
4. Review and submit the changed **Appliance Settings**, **Public Services**, and **Firewall** units from the global
   appliance-apply workflow.
5. On **Users**, enable **Web SSH** for each local user who may open a terminal. The user must also be enabled, use an
   interactive shell such as `/bin/bash` or `/usr/bin/pwsh`, and have a Photon password applied through Local Users.

Only enabled, addressed access/route physical interfaces and enabled VLANs are valid additional bindings. Missing,
disabled, unused, trunk-only, or addressless interfaces fail validation. Atlaso has no WAN interface role and
web-terminal exposure does not infer internet or WAN connectivity.

On a selected non-management address, nginx exposes only the login/logout, terminal, WebSocket, and required
static-asset routes. Management dashboard and API routes remain unavailable. The Public Services directory for that
address includes a **Web Terminal** tile linked to `https://<selected-address>/terminal`; unselected interfaces do not
show the tile. The terminal and its login page use the Public Services header, sign-out action, and footer rather than
the admin application shell.

## Session behavior

- The terminal connects automatically; there is no separate Connect button.
- One bounded server-side shell is retained per authorized user across page reloads and short WebSocket interruptions.
- Opening the terminal in another browser prompts for confirmation. Confirming moves the existing shell, current working
  directory, buffered output, and input ownership to the new browser. The original browser shows an overlay with an
  in-terminal reconnect action.
- `Ctrl-D` and the `exit` command intentionally end the current shell. The disconnected transcript remains visible until
  a new session is started.
- Copy and download icons in the terminal's top-right corner export the visible session transcript. Their success
  notifications disappear automatically and remain above the application footer.
- A disconnected terminal uses a lighter background so stale output is visually distinct from an attached live shell.

## Authentication and security boundaries

The web login session and the user's explicit Web SSH permission authorize access. On a Public Services listener,
non-bootstrap local users authenticate against their applied Photon password. The local SSH connection then uses a
one-use browser ticket, an ephemeral Ed25519 key, and a short-lived OpenSSH user certificate issued by the
appliance-owned user CA. The certificate is restricted to loopback source and disables forwarding, agent forwarding,
X11, and user RC processing. Host keys are pinned locally.

This removes the SSH password prompt only. `sudo` continues to require the Photon OS account password according to the
normal OS policy. Root certificates and passwordless sudo are not permitted.

The service enforces bounded idle time, total lifetime, input, output, and retained transcript size. CA private keys
never reach the browser or the Atlaso service account.

## Apply and troubleshooting

Changing terminal interfaces should make these apply units pending:

- `appliance_settings` for HTTPS and SSH user-CA configuration;
- `public_services` for selected non-management nginx listeners and directory entries;
- `firewall` for interface-bound TCP/443 access.

The Public Services renderer merges terminal routes into an existing HTTPS listener when CA or depot routes already use
the same address. It must emit only one `/static/` location per nginx server block.

If apply fails, inspect the Public Services child task and validate
`/var/lib/atlaso/apply/public-services/atlaso-public-services.conf`. On the appliance, validate nginx with `nginx -t`,
confirm `atlaso.service` is active, and verify the selected address separately:

- `https://<address>/terminal` should redirect to login or open the terminal;
- `https://<address>/dashboard` and `/openapi.json` must remain unavailable on an additional listener;
- the management `/openapi.json` endpoint must remain reachable.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### Web terminal

![Atlaso Web terminal page in the clean-appliance responsive viewport.](../assets/screenshots/terminal-clean-responsive.webp)

*Figure: Web terminal in the verified clean-appliance responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
