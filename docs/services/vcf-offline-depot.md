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

![Atlaso VCF Offline Depot desktop page showing Metadata before Binaries and ESX profiles and the combined VCFDT configuration action.](../assets/screenshots/vcf-offline-depot-clean-desktop.webp)

*Figure: VCF Offline Depot with metadata first and the compact VCFDT configuration summary in the desktop settings rail.*

<!-- END GENERATED INTERFACE OVERVIEW -->

## Configure the depot

1. Confirm the fixed depot mount is present and has sufficient working space.
2. Configure the service listener and the HTTP user used by approved VCF targets.
3. Upload the VCF Download Tool package, then select **Configure** under **VCFDT configuration**. Atlaso displays the
   version encoded in the validated staged archive name immediately; Appliance Apply later replaces it with VCFDT's
   authoritative `--version` result. The five-step wizard starts with the current Software Depot ID and refresh intent,
   then offers an exclusive choice to preserve both Broadcom inputs or replace either the download token or activation
   code. A selected credential gets its own upload-or-paste step before `application-prodv2.properties` and Review.
   Credential values are never loaded into the browser; an uploaded text file takes precedence over pasted text.
4. Save the wizard. Credentials and application properties are committed together, but the save does not mutate the
   appliance or replace an existing Software Depot ID.
5. Review certificate readiness and the generated software depot identity. Atlaso reads the persisted identity back
   from VCFDT after generation and displays only that canonical value.
6. Validate the desired state and submit the VCF Offline Depot unit through
   [Appliance Apply](../operate/appliance-apply.md).
7. When the apply task succeeds, the page refreshes automatically so the authoritative applied VCF Download Tool
   version and generated Software Depot ID replace the previously staged values.
8. Run downloads as tasks and follow their terminal result in the page's **Profile download tasks** grid. This is the
   shared [Tasks](../operate/tasks.md) grid scoped to VCF Download Tool profile downloads, with the same filters,
   pagination, detail view, live state refresh, and access to the active or archived VCFDT task log. Use **Open full
   task history** when you need the appliance-wide view.

Download-profile creation uses a reviewed wizard. Notes stay with profile identity, task execution owns lifecycle
status, and profile enablement has its own step so availability is an explicit decision before review.
Metadata profiles appear first initially, followed by binaries and ESX profiles. Column sorting can temporarily reorder
the profiles, while the add row remains last.

![Atlaso VCFDT configuration wizard starting with the Software Depot ID generation or refresh choice.](../assets/screenshots/vcf-offline-depot-configuration-wizard.webp)

*Figure: VCFDT configuration starts with the safe Software Depot ID apply choice and contains no credential contents.*

Metadata and binaries profiles use the download token or activation code staged most recently. Staging one credential
does not remove the other because ESX profiles always require the activation code. Review the generated command preview
after changing credentials to confirm that it references the intended runtime credential file.

Do not place depot credentials or authenticated URLs in task notes, manifests, logs, or screenshots.

Register the displayed software depot ID in the VCF Business Services console, then stage the activation code returned
for that exact registration. Atlaso preserves this ID when settings or download profiles are changed and applied.
Selecting **Refresh the Software Depot ID** (or **Generate the Software Depot ID** when none exists) skips directly to
Review without resaving unchanged credentials or properties. Atlaso then opens a second confirmation. Only
**Submit appliance changes** in that confirmation sends the
VCF Offline Depot unit and explicit refresh intent to Appliance Apply. The earlier activation code no longer matches
the active VCFDT identity, so register the new displayed ID and replace the staged activation code before retrying a download.
If VCFDT generates a replacement but Atlaso cannot read it back unambiguously, Atlaso clears the displayed ID instead
of presenting the previous registration as current. Retry the refresh before registering or downloading.

## Verify

Confirm the service is healthy, an approved target trusts the Atlaso CA, and required metadata or content is reachable
with the configured account. Use [VCF Helper](vcf-helper.md) for the separate remote workflow that points a supported
VCF appliance at the applied local depot.

<!-- BEGIN GENERATED ADDITIONAL SCREENSHOTS -->
## Additional verified states

These captures show responsive layouts and useful operational states referenced by this page.

### VCF Offline Depot

![Atlaso VCF Offline Depot responsive page showing Metadata first with the add-profile row pinned last.](../assets/screenshots/vcf-offline-depot-clean-responsive.webp)

*Figure: VCF Offline Depot profile ordering and staging state in the responsive viewport.*

![Atlaso VCFDT configuration wizard Software Depot ID step without credential contents.](../assets/screenshots/vcf-offline-depot-configuration-wizard.webp)

*Figure: VCFDT configuration starts with the Software Depot ID generation or refresh handoff.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
