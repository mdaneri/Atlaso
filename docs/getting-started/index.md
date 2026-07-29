---
title: Getting started
description: Choose an Atlaso appliance path, reach the UI, and complete the first configuration.
audience:
  - operator
status: current
---

# Getting started

Atlaso is delivered as a Photon OS 5.0 appliance. VMware Workstation is the default live-test and documentation target;
Hyper-V provides the authoritative lifecycle environment for exact access and trunk VLAN behavior.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso sign-in page in the desktop viewport.](../assets/screenshots/login-desktop.webp)

*Figure: Appliance sign-in in the verified desktop viewport.*

<!-- END GENERATED INTERFACE OVERVIEW -->

## First-use sequence

1. Build or obtain the appliance by following the [full technical reference](../reference/full-technical-reference.md).
2. Start the VM and wait for the local console to report the management address.
3. Open the HTTPS management UI and sign in with the bootstrap administrator.
4. Confirm management networking and Appliance Settings validity on the Dashboard.
5. Configure required services as desired state.
6. Review and submit the first global [appliance change](../operate/appliance-apply.md).
7. Confirm that the task succeeds and the Dashboard leaves setup-readiness mode.

Do not treat an assigned IP address, a running VM, or a green service alone as application readiness. Verify the
host-facing `/openapi.json` endpoint before beginning configuration.

## Installed web app behavior

Atlaso can be installed as a standalone web app. Successful sign-in continues in the current browser context, and
supporting browsers reuse the most recently active Atlaso app window for later launches instead of creating duplicate
windows. Browsers that do not support launch handling continue to use their platform default.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### Services

![Atlaso Services page in the clean-appliance desktop viewport.](../assets/screenshots/services-clean-desktop.webp)

*Figure: Services in the verified clean-appliance desktop state.*

![Atlaso Services page in the clean-appliance responsive viewport.](../assets/screenshots/services-clean-responsive.webp)

*Figure: Services in the verified clean-appliance responsive state.*

### Sign in

![Atlaso sign-in page in the responsive viewport.](../assets/screenshots/login-responsive.webp)

*Figure: Appliance sign-in in the verified responsive viewport.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
