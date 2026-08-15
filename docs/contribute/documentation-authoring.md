---
title: Documentation authoring guide
description: Create current, accessible, branded, testable Atlaso documentation and media.
audience:
  - contributor
  - maintainer
status: current
---

# Documentation authoring guide

Markdown under `docs/` is the canonical source for the public documentation site. The generated site is a presentation
artifact; never edit generated HTML directly.

## Choose one canonical page

- Put operator tasks under **Getting started**, **Operate**, or **Services**.
- Put detailed technical contracts and test procedures under **Reference**.
- Put contribution policies and design standards under **Contribute**.
- Put brand guidance, roadmaps, and historical records under **Project**.
- Link to canonical instructions instead of copying them into the README, policy indexes, or component READMEs.
- Leave a redirect stub when a tracked Markdown page moves. Keep `redirect_to` as its only destination reference; do
  not duplicate the target as a Markdown link in the body. `scripts/check_docs.py` validates the source and target,
  while `scripts/build_docs.py` owns the deterministic strict build and published redirect link generation.

## Required metadata

Every published page starts with YAML front matter containing `title`, `description`, `audience`, and `status`.
`audience` is a list containing `operator`, `contributor`, or `maintainer`. `status` is `current`, `roadmap`,
`historical`, or `redirect`. Redirects also require `redirect_to`.

The page must contain exactly one level-one heading and it must match `title`.

## Write an operator task

1. State the outcome and prerequisites.
2. Identify the scope and safety boundary.
3. Give ordered actions using the exact current UI labels.
4. Explain validation messages and expected results.
5. Include a verification step based on real appliance state.
6. Include rollback or recovery guidance when the action changes runtime state.

Never claim successful apply, service health, or external interoperability from an unverified or fabricated state. Use
RFC 1918 addresses, reserved example domains, and non-secret sample identities.

## Screenshots

- Capture the current UI from the dedicated documentation VM.
- Prefer one orientation image followed by focused images for tabs, dialogs, previews, validation, and results.
- Store optimized WebP images under `docs/assets/screenshots/`.
- Provide descriptive alt text and a caption that adds context instead of repeating the alt text.
- Record every image in `docs/assets/screenshots/manifest.json`.
- Assign every image to the canonical page that explains it and run
  `python scripts/generate_embedded_screenshot_sections.py`. The generated **Interface overview** section stays near
  the page introduction; responsive and state-transition captures remain in **Additional verified states**.
- Capture browser content at 1600×1000 and responsive examples at 900×1200.
- Strip metadata and check every frame for credentials, personal data, misleading state, and stale branding.

## Video

Store storyboards, narration, captions, transcripts, manifests, export settings, thumbnails, and poster images under
`docs/media/`. Do not commit rendered MP4 files. Record the appliance version and source commit. Update or supersede
media when a material UI change makes it inaccurate.

## Branding checklist

[`docs/assets/brand/BRAND_GUIDE.md`](../assets/brand/BRAND_GUIDE.md) is canonical.

- Use the approved light or dark logo for its documented background.
- Preserve logo proportions, colors, and clear space.
- Do not stretch, rotate, recolor individual elements, or add drop shadows.
- Use the approved palette and product language.
- Verify that promotional claims describe implemented and demonstrated behavior.

## Accessibility

- Use descriptive headings in a logical hierarchy.
- Provide useful alt text, captions, transcripts, and synchronized video captions.
- Do not communicate status through color alone.
- Keep controls, code, and UI text readable at the published viewport.
- Avoid autoplay, rapid flashing, and third-party tracking embeds.

## Publication

Every push to `main` runs the Documentation workflow, even when the commit does not change a documentation path. The
workflow validates the checked-in Markdown and media, builds the site in strict mode, and replaces only the `/docs`
subtree on the shared `gh-pages` branch. The release-repository landing page and signed content under `/updates` remain
unchanged. When the generated documentation matches the published site, the workflow succeeds without creating a new
`gh-pages` commit or entering the shared Pages publication queue. Only a detected `/docs` change enters the serialized
`atlaso-github-pages` writer, so routine verification runs cannot delay publication. Every Pages mutation job uses
`queue: max` with `cancel-in-progress: false`; overlapping documentation, appliance release, Inventory Linux release,
and promotion writers wait and execute sequentially instead of replacing an earlier pending writer.

To request a rebuild manually, open **Actions > Documentation** in GitHub, choose **Run workflow**, select `main`, and
run the workflow. Maintainers can request the same rebuild from an authenticated GitHub CLI session with
`gh workflow run docs.yml --ref main` and monitor it with `gh run watch`.

## Required checks

Run these commands before opening a pull request:

```powershell
npm ci
npm run lint:markdown
.\.venv-docs\Scripts\python.exe -m pip install --require-hashes -r requirements-docs.lock
.\.venv-docs\Scripts\python.exe scripts/build_docs.py
python scripts/check_docs.py
python scripts/check_repo.py
git diff --check
```

The build wrapper removes only a recognized repository-local Zensical `.cache` before invoking `build --clean
--strict`, then generates the legacy redirect pages. Do not replace it with a direct Zensical invocation: stale cache
entries can otherwise make unchanged redirect targets fail nondeterministically. The wrapper does not disable link or
anchor validation, so genuine missing targets still fail the strict build.

Documentation linting applies to every tracked Markdown source. Do not suppress existing files, create a warning-only
baseline, or couple tests to exact explanatory prose when a stable marker or canonical path can express the contract.
