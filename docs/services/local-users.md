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

1. Create a unique username and assign the least-privileged suitable role.
2. Set or rotate the password through the protected form.
3. Disable an account when access should be suspended without deleting its history.
4. Use the shared confirmation dialog before permanent deletion.

Passwords are never displayed again or stored in audit details. Do not reuse the Photon build password or publish test
credentials in screenshots.

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
