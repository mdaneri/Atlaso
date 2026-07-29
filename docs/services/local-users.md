---
title: Local users
description: Manage Atlaso local operator accounts, roles, and enabled state.
audience:
  - operator
  - maintainer
status: current
---

# Local users

Open **Users** to manage local Atlaso identities and role assignments. Local users authenticate to the operator UI and
can also serve as explicitly selected identity sources where a service supports them.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso Users page in the clean-appliance desktop viewport.](../assets/screenshots/users-clean-desktop.webp)

*Figure: Users in the verified clean-appliance desktop state.*

<!-- END GENERATED INTERFACE OVERVIEW -->

## Manage an account

1. Select **Add user here**, create a unique username, record the account purpose in the multiline description row,
   and choose the least-privileged suitable roles.
2. Choose Photon shell and Web SSH access as separate decisions.
3. Set a policy-compliant Photon password in the guided workflow, or leave both password fields blank to postpone and
   keep the new account disabled.
4. Choose account enablement explicitly. Existing accounts can also be enabled or disabled directly from the grid;
   enabling still requires a staged or previously applied Photon password.
5. Use the shared confirmation dialog before permanent deletion.

Passwords are never displayed again or stored in audit details. Do not reuse the Photon build password or publish test
credentials in screenshots.

## Apply and status staging

A real Local Users apply writes its secret-bearing helper input with mode `0600` only for the validate-and-apply
execution window. Atlaso and `atlaso-helper` both remove that file after success, validation failure, or apply failure;
application startup also removes a stale input left by an interrupted process. Previews, baselines, task results, logs,
audits, and test output never receive the raw password.

Read-only Photon account status uses a different uniquely named, short-lived file containing no password values. It
cannot replace an active apply payload and is removed as soon as the status request finishes.

## Verify

Test the account in a separate private browser session and confirm that its permissions match the assigned role.
Maintain at least one verified administrator before disabling or deleting another administrative account.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### Users

![Atlaso Users page in the clean-appliance responsive viewport.](../assets/screenshots/users-clean-responsive.webp)

*Figure: Users in the verified clean-appliance responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
