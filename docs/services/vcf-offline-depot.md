---
title: VCF Offline Depot
description: Configure, synchronize, and verify the local Atlaso VCF Offline Depot.
audience:
  - operator
status: current
---

# VCF Offline Depot

Open **VCF Offline Depot** to configure the local content repository used by supported VCF workflows.

<!-- BEGIN GENERATED INTERFACE OVERVIEW -->
## Interface overview

This verified appliance view provides visual orientation before you begin.

![Atlaso VCF Offline Depot page in the clean-appliance desktop viewport.](../assets/screenshots/vcf-offline-depot-clean-desktop.webp)

*Figure: VCF Offline Depot in the verified clean-appliance desktop state.*

<!-- END GENERATED INTERFACE OVERVIEW -->

## Configure the depot

1. Confirm the fixed depot mount is present and has sufficient working space.
2. Configure the service listener and the HTTP user used by approved VCF targets.
3. Review certificate readiness and the generated software depot identity. Atlaso reads the persisted identity back
   from VCFDT after generation and displays only that canonical value.
4. Validate the desired state and submit the VCF Offline Depot unit through
   [Appliance Apply](../operate/appliance-apply.md).
5. When the apply task succeeds, the page refreshes automatically so the applied VCF Download Tool version and
   generated Software Depot ID replace the previously staged values.
6. Run downloads as tasks and follow their terminal result in the page's **Profile download tasks** grid. This is the
   shared [Tasks](../operate/tasks.md) grid scoped to VCF Download Tool profile downloads, with the same filters,
   pagination, detail view, live state refresh, and access to the active or archived VCFDT task log. Use **Open full
   task history** when you need the appliance-wide view.

Download-profile creation uses a reviewed wizard. Notes stay with profile identity, task execution owns lifecycle
status, and profile enablement has its own step so availability is an explicit decision before review.

Metadata and binaries profiles use the download token or activation code staged most recently. Staging one credential
does not remove the other because ESX profiles always require the activation code. Review the generated command preview
after changing credentials to confirm that it references the intended runtime credential file.

Do not place depot credentials or authenticated URLs in task notes, manifests, logs, or screenshots.

Register the displayed software depot ID in the VCF Business Services console, then stage the activation code returned
for that exact registration. Atlaso preserves this ID when settings or download profiles are changed and applied.
**Refresh software depot ID** intentionally replaces it; its earlier activation code no longer matches the active
VCFDT identity, so register the current displayed ID and replace the staged activation code before retrying a download.

## Verify

Confirm the service is healthy, an approved target trusts the Atlaso CA, and required metadata or content is reachable
with the configured account. Use [VCF Helper](vcf-helper.md) for the separate remote workflow that points a supported
VCF appliance at the applied local depot.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### VCF Offline Depot

![Atlaso VCF Offline Depot page in the clean-appliance responsive viewport.](../assets/screenshots/vcf-offline-depot-clean-responsive.webp)

*Figure: VCF Offline Depot in the verified clean-appliance responsive state.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
