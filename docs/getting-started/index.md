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
