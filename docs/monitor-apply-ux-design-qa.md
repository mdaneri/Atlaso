# Monitor hierarchy and interaction design QA

## Reference and capture setup

- Source: historical browser annotation captured from `https://192.168.167.219/monitor` before the hierarchy changes and before the Disk Usage panel was removed.
- Desktop viewport: 1968 × 1562 CSS pixels at the browser's native device density.
- Narrow viewport: 900 × 1200 CSS pixels.
- Historical validation target: VMware appliance `192.168.167.219`, deployed with the repository VMware wheel helper. The images below document the preceding layout and interaction work; they are not screenshots of the current panel set.
- Current shared cache revision: `monitor-no-disk-usage-20260723-3` / `atlaso-pwa-v156`.

## Comparison

![Atlaso Monitor](images/monitor-apply-ux/monitor-after.png)

The captured desktop comparison records the earlier hierarchy where Disk Activity owned unique-device I/O and Disk Usage owned capacity. It is retained as historical evidence, not as a representation of the current page. The current Monitor removes the top-level Disks capacity metric, Disk Usage chart, and mount table while retaining Network Throughput and Disk Activity at matching row heights.

## Interaction evidence

![Full-screen Network chart at 800 percent zoom](images/monitor-apply-ux/monitor-fullscreen-zoom.png)

- Full-screen-only zoom uses the in-chart lens controls and editable percentage.
- A tall spike was selected along its line segment, pinned after pointer movement, and cleared from empty chart space.
- Legend selection was exercised live: `Total` selected, a second click cleared it, and `cpu0` then became selected.
- 12h and 24h controls were exercised live; both became active and returned a successful Monitor refresh.

## Responsive check

![Narrow Monitor capture](images/monitor-apply-ux/monitor-narrow.png)

At 900 × 1200 the dashboard returns to natural stacked sizing; full-width controls remain reachable and the desktop two-column card coupling does not force a fixed narrow height.

## Review history

1. Added total/detail hierarchy and unique-device disk series.
2. Split Disk Activity from Disk Usage and restored the per-device I/O table.
3. Added full-screen charts, in-chart percentage zoom, and drag-to-select zoom.
4. Expanded hit testing from sampled points to complete line segments.
5. Equalized Network Throughput and Disk Activity desktop card heights.
6. Added clickable legend selection plus 12h and 24h history ranges.
7. Removed the top-level Disks capacity metric, Disk Usage chart, and per-mount table after live operator review found capacity presentation not useful on this page.

## Final result

The current implementation preserves the useful chart interactions and responsive layout without the removed Disk Usage panel.
Filesystem-usage fields remain available to backend samples and API consumers for compatibility; their presence does not imply a Monitor page panel.
