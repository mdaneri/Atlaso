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
3. Select **Add** or **Update** for the VCF Download Tool package. The two-step package wizard reviews the archive name,
   size, and desired-state boundary before upload. During upload, Review remains visible and reports transferred bytes
   and upload percentage. Then select **Configure** under **VCFDT configuration**. Atlaso
   displays the
   version encoded in the validated staged archive name immediately; Appliance Apply later replaces it with VCFDT's
   authoritative `--version` result. The five-step wizard starts with the current Software Depot ID and refresh intent,
   then offers a standard **Credential action** selector. **Keep staged credentials unchanged** appears only when an
   input is already staged;
   absent inputs are labeled **Use** and existing inputs are labeled **Replace**. When no credential exists, selecting
   either the download token or activation code is required. The selected input gets its own upload-or-paste step before
   `application-prodv2.properties` and Review. Choosing **Keep staged credentials unchanged** removes the credential-input
   step because no secret input is needed.
Credential values are never loaded into the browser; an uploaded text file takes precedence over pasted text.
The application-properties Monaco editor is directly editable and synchronizes every change to the submitted textarea;
its visible editor is not nested in the source textarea's label.
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
When no Software Depot ID exists, **Generate the Software Depot ID** is selected and disabled because the first ID is
required before credentials can be registered. Selecting generation, or **Refresh the Software Depot ID** for an
existing ID, immediately hides
the credential, credential-input, and properties steps, leaving a two-step Software Depot ID and Review flow. It does
not resave unchanged credentials or properties. **Queue Software Depot ID task** on Review creates and immediately
dispatches a dedicated VCFDT identity task. Atlaso opens the ordinary Tasks view for that job while it stages the
required VCFDT runtime inputs, applies the properties and CEIP prerequisites, and generates and reads back the identity
without invoking nginx or global Appliance Apply. The task exposes those four safe child operations and sanitized logs.
Atlaso serializes this identity task with profile downloads and any Appliance Apply task that includes VCF Offline
Depot. A queued identity task can be cancelled before it starts; once VCFDT execution begins, cancellation is disabled
because the identity may already have changed.
It succeeds only after Atlaso persists a non-empty Software Depot ID (and a different ID for refresh). Once
VCFDT changes the identity, Atlaso removes both the staged and runtime download token and activation code. A generation
failure that leaves the identity unchanged preserves both credentials. Register the new displayed ID, then stage a
matching credential before retrying a download. Use the copy control on the **Depot ID Ready** status tile to copy the
current ID; Atlaso confirms the clipboard action without exposing any credential value.
VCFDT tool staging and Software Depot ID generation remain available while the HTTPS depot service is disabled; the
service toggle controls publishing, not VCFDT identity preparation.
**Reset** uses one destructive confirmation and clears the staged package, both Broadcom credentials, saved application
properties, generated identity/version metadata, and all profile enablement together. Runtime removal still waits for
global Appliance Apply.
If VCFDT generates a replacement but Atlaso cannot read it back unambiguously, Atlaso clears the displayed ID instead
of presenting the previous registration as current. Retry the refresh before registering or downloading.
After an Atlaso restart interrupts a running identity task, startup performs the same canonical VCFDT readback before
failing the interrupted task. Atlaso saves a changed runtime ID and removes obsolete credentials; if readback cannot
verify the runtime identity, it invalidates the stored ID and credentials instead of retaining stale registration data.

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

![Atlaso two-step VCFDT Software Depot ID wizard Review with a Queue Software Depot ID task action and no additional confirmation dialog.](../assets/screenshots/vcf-offline-depot-configuration-wizard.webp)

*Figure: VCFDT Software Depot ID generation ends at Review, which immediately dispatches a dedicated identity task.*

<!-- END GENERATED ADDITIONAL SCREENSHOTS -->
