---
title: Atlaso local appliance console design QA
description: Historical visual design record for the local appliance console.
audience:
  - contributor
  - maintainer
status: historical
---

# Atlaso local appliance console design QA

Source visual truth:

- `C:\Users\m_dan\AppData\Local\Temp\codex-clipboard-4ced0d62-dba3-4e12-a9a4-c9403fe13e4e.png` for the appliance screen
  iteration.
- `C:\Users\m_dan\AppData\Local\Temp\codex-clipboard-febfd43f-cf36-4f55-bf87-5dd27404c4bc.png` for the compact framed
  editor direction.

Implementation screenshots:

- `C:\Users\m_dan\AppData\Local\Temp\atlaso-console-final8.png`
- `C:\Users\m_dan\AppData\Local\Temp\atlaso-console-management-form-final2.png`

Viewport: VMware Workstation virtual console, 640 x 480 pixels, 80 x 30 terminal cells.

State: healthy dual-stack-capable management console with DHCP IPv4, Automatic RA/SLAAC IPv6, and enabled Firewall;
management editor focused on the IPv4 mode field.

Full-view comparison evidence: `C:\Users\m_dan\AppData\Local\Temp\atlaso-console-comparison-final.png`. The final screen
deliberately incorporates the requested changes instead of literally retaining the earlier screenshot: pale-blue header,
product version beside the title, separate system rows, no ONLINE label, repaired Photon release line, spacing before
management URLs, normalized network rows, separated Firewall status, and F3/F4 footer actions.

Focused comparison evidence: `C:\Users\m_dan\AppData\Local\Temp\atlaso-console-form-comparison-final.png`. The crop
compares the supplied nmtui direction with the final management form at readable scale. The implementation preserves the
framed terminal hierarchy, blue section labels, highlighted editable controls, paired Apply/Cancel actions, and keyboard
guidance while removing unrelated profile, device, route, search-domain, and checkbox controls.

## Findings

No actionable P0, P1, or P2 visual differences remain.

- Fonts and typography: the Photon virtual-console bitmap font is consistent across the screen and editor. Title,
  section, label, value, and action hierarchy is legible without wrapping at 80 columns.
- Spacing and layout rhythm: the header and body have explicit separation; Interface, address families, DNS, and
  Firewall occupy stable rows. The editor has balanced section spacing and remains inside the 72 x 22 minimum.
- Colors and visual tokens: pale blue, slate/gray, Atlaso blue, green, amber, and red map consistently to the Linux
  console's eight-color capability. The focused control is dark blue, other editable controls are pale blue, and
  disabled fields remain neutral.
- Image quality and asset fidelity: no raster imagery, logos, icons, or decorative assets belong to this terminal UI.
  The captured terminal text and borders are sharp at native resolution.
- Copy and content: labels match the approved appliance scope. IPv6 remains Disabled, Automatic RA/SLAAC, or Static;
  DHCPv6 is intentionally not implied.

## Comparison history

1. Earlier P1: embedded metadata from `/etc/photon-release` created a black strip and `PHOTKernel` text. Fix: normalize
   the release value to its first display line. Post-fix evidence: `atlaso-console-final8.png` shows a clean Photon and
   Kernel separation.
2. Earlier P1: systemd progress output and late service activity could overwrite tty1 until the normal refresh. Fix:
   keep systemd status in the journal, force full restoration after external processes, and use bounded non-blanking
   redraws at 1, 3, and 8 seconds. Post-fix evidence: the immediate post-deploy `atlaso-console-final8.png` capture is
   clean.
3. Earlier P2: the first framed form made the active mode less visually obvious than an inactive mode, and DHCP could
   retain observed lease values in its submit tuple. Fix: dark-blue active control, pale-blue inactive editable
   controls, neutral disabled fields, and mode-aware clearing on submit. Post-fix evidence:
   `atlaso-console-management-form-final2.png`.

## Primary interactions tested

- Left/Right, Home/End, insertion, Backspace, and Delete within text values.
- Tab, Shift+Tab, Up/Down navigation and mode-dependent field skipping.
- DHCP/Automatic submit normalization.
- F3 `top` terminal handoff and curses restoration path.
- Authenticated/audited F4 Bash handoff and restoration path.
- Five-second default refresh plus bounded 1-through-300-second environment configuration.
- No browser console applies to this curses surface; Python compilation, focused tests, VMware service readiness, and
  native tty captures were checked instead.

## Implementation checklist

- [x] Main-screen hierarchy and palette match the approved direction.
- [x] Management form matches the compact framed editor direction.
- [x] Keyboard editing and navigation are covered by tests.
- [x] Service-output corruption and post-process restoration are covered.
- [x] VMware tty1 renders cleanly; tty2 ownership remains unchanged by the implementation.

## Follow-up polish

No P3 polish item is required for handoff.

final result: passed

## Managed LDAP web follow-up

Reference and implementation evidence:

- `test-results/design-qa/vcf-helper-generator-live.png` shows the generator modal before overflow correction.
- `test-results/design-qa/vcf-helper-generator-no-scroll.png` shows the same appliance and modal state after correction.
- `test-results/design-qa/ldap-directory-live.png` shows organization actions, directory tabs, and the settings rail.
- `test-results/design-qa/task-errors-live.png` shows the deployed redacted task failure summary.

Findings:

- The test-directory workflow has its own VCF Helper tile and opens independently from Managed LDAP VCF configuration.
- The generator modal has no horizontal scrollbar and preserves the existing compact Atlaso modal pattern.
- Organization actions align to the right of the organization header, with additional space between the VCF bind DN row
  and Users/Groups tabs.
- The one-time bind credential dialog contains copy, download, and close actions. Its bind DN wraps, its password
  control stays within the dialog, and help text is anchored to the field-label bounds.
- Failed task details show the redacted component reason immediately and an expanded log-style error section above the
  complete redacted result payload.
- VCF Helper actions are grouped by subject: platform deployment, naming, trust, and depot workflows under
  `SDDC Manager / VCF Installer`, with directory configuration and synthetic identities under `LDAP`.
- Generated LDAP credentials use one CSV representation for the Prism-highlighted preview, clipboard copy, and `.csv`
  download; the compact copy/download icons remain overlaid inside the preview.
- Disabled SDDC Manager and Offline Depot tiles expose their availability reason on tile hover/focus; persistent warning
  rows no longer interrupt the subject layout.
- Managed LDAP preserves organization, Users/Groups mode, and per-organization grid offsets across reloads using
  browser-local page state.

Managed LDAP web follow-up final result: passed

## Managed script revision comparison follow-up

Reference and implementation evidence:

- Source reference: `C:\Users\m_dan\AppData\Local\Temp\codex-clipboard-743a6bab-f5ec-4abe-84ff-997b9b1a779a.png`.
- Live implementation: `test-results/design-qa/automation-revision-diff-light-final.png`.
- Combined comparison input: `test-results/design-qa/automation-revision-diff-comparison.png`.
- Browser viewport: 2446 x 1562 pixels. Reference: 2048 x 436 pixels. The comparison normalizes both surfaces to 2446
  pixels wide and crops the implementation to the active modal.
- State: Automation > Managed Scripts, `fdd` revision comparison open with r1 as the base and r2 as the comparison.

Findings:

- No actionable P0, P1, or P2 visual differences remain.
- Typography: the viewer uses the Atlaso sans hierarchy for controls and metadata, with a compact monospace source
  surface and interpreter-specific Prism highlighting.
- Spacing and layout: the modal uses nearly the full workspace width, keeps paired source rows and line numbers aligned,
  and stays content-sized for short revisions while allowing bounded scrolling for long revisions.
- Colors and tokens: the shell uses the standard light Atlaso surface, border, blue header, and muted metadata tokens.
  Removed and added rows use soft red and green fills with stronger edge markers.
- Copy and content: operators can choose any base and comparison revision. Each option and heading includes the
  immutable revision number, creation date, interpreter, and enabled state.
- Image and asset quality: this workflow contains no decorative raster assets. Native browser text, borders, controls,
  and Prism tokens remain sharp at the captured viewport.

Comparison history:

1. P1: the first implementation used a narrow generic modal with large unused vertical space. Fix: rebuild it as one
   shared, near-full-width aligned diff surface with compact content height.
2. P1: the reference-derived dark shell conflicted with the established Atlaso application style. Fix: retain the diff
   structure but move the modal shell, toolbar, revision headers, and unchanged rows to the product's light surface
   system.
3. P2: the original comparison was fixed to the latest two revisions and omitted creation dates. Fix: add dated
   base/comparison selectors populated from all immutable revisions and refresh the Prism diff in place.
4. P2: switching to the initial hash-selected tab could request a Tabulator redraw before table initialization. Fix:
   gate tab redraws on the `tableBuilt` event; the final reload and modal-open interaction produced no browser warnings
   or errors.

Primary interactions tested:

- Revision cell opens the comparison viewer.
- Base and comparison selectors expose every revision with date and state and update the selected comparison without
  mutating history.
- Close control remains keyboard- and pointer-accessible.
- Diff rows preserve aligned line numbers, additions, removals, empty counterparts, and collapsed unchanged runs.
- Live reload and modal open completed without browser console warnings or errors.

Managed script revision comparison final result: passed

final result: passed

## ESX Storage wizard design QA

### Result

Passed on the VMware test appliance at `https://192.168.167.219/esx-storage` using the annotated 1968 x 1562 browser
captures as the source reference.

### Visual comparison

- Preserved the ESX Storage page shell, compact Tabulator grids, resource tabs, right-side Service Settings and
  Validation rail, typography, spacing, and status treatments from the reference.
- Replaced each expanded inline add form with the established Atlaso grid add-row affordance and modal wizard pattern.
- Verified the volume wizard at the storage-selection step and the NFS datastore wizard at identity and review steps at
  the same desktop viewport.
- The modal layout, step rail, field density, help controls, action placement, overlay, borders, and radii match the
  existing Atlaso wizard system without clipping or overlap.

## Interaction verification

- `+ Add storage volume here` opens the three-step volume wizard.
- Required volume identity and eligible-storage selection prevent invalid advancement.
- `+ Add NFS datastore here` opens the four-step datastore wizard.
- A dual-stack interface defaults both IPv4 and IPv6 on with equal treatment.
- The client step independently requires IPv4 and IPv6 VMkernel clients when both families are enabled.
- The review step shows the datastore, backing path, NFS version, interface, both address families, and both allowlists
  before any desired-state submission.
- Cancel closes either wizard without creating a volume or datastore.
- No browser console warnings or errors were recorded during the verified flow.
