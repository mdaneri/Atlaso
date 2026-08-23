---
title: Atlaso Brand Assets
description: Use and regenerate the approved Atlaso brand asset set.
audience:
  - contributor
  - maintainer
status: current
---

# Atlaso Brand Assets

Atlaso is the complete product and technical identity of the appliance.

## Message hierarchy

- Headline: **Everything your virtualization lab needs.**
- Capability line: **Infrastructure • Storage • Identity • Networking • Lifecycle**
- Supporting pillars: **Infrastructure • Connectivity • Automation**
- Product promise: Atlaso supports POC, lab, and test environments by simplifying deployment, maintenance, and
  validation.

## Canonical assets

The complete source kit is documented in the [Atlaso Brand Kit](../assets/brand/BRAND_GUIDE.md). It defines the mark,
colors,
clear space, and approved variants. Use the supplied masters without stretching, rotating, recoloring individual
elements, or adding shadows.

The primary palette is:

- Atlaso Navy: `#071A3A`
- Atlaso Blue: `#1769E0`
- Atlaso Teal: `#16C7BC`
- Atlaso Cyan: `#17A8C8`
- White: `#FFFFFF`

## Runtime assets

The appliance package includes only the assets required at runtime under `atlaso/app/static/brand/`:

- `atlaso-icon.svg` for compact product marks;
- light and dark horizontal SVG logos;
- the transparent 1200×300 horizontal logo for the authenticated sidebar and management login masthead;
- 180, 192, and 512 pixel application icons;
- `favicon.ico`.

The PWA manifest uses the dark 192 and 512 pixel application icons as maskable icons. Its start URL and service-worker
scope are restricted to `/ui/management/`; public UI caching is disabled. Browser templates also expose the SVG mark
and the 180 pixel Apple touch icon. The cached management offline fallback uses the horizontal light SVG within the
same bounded, aspect-preserving logo presentation as the sign-in card so the recovery copy remains readable at narrow
viewports and browser zoom.

## Appliance boot

`image/common/boot/grub/atlaso.png` is a deterministic 640×480 composition derived from the Atlaso dark application
icon. It carries the headline and retains the required **Powered by Photon OS** attribution. GRUB timing, boot entries,
and kernel arguments remain unchanged.
