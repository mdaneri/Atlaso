# Browser regression fixtures

## Certificate IP SAN validation

Start the isolated loopback fixture described under **Network Boot host reference**, then run
`node tests/browser/ca-ip-sans.cjs` with `ATLASO_BROWSER_FIXTURE_URL`, `ATLASO_BROWSER_OUTPUT`, `TEMP`, and `TMP`
pointing at that fixture and originally receipted task-owned output. Playwright and Microsoft Edge are required.
This exercises the actual CA templates, shared wizard, and local create/edit transports at desktop, narrow, and
200% zoom-equivalent CSS viewports. It checks malformed mixed SANs, submit-time revalidation, adjacent accessible
feedback, focus, correction, clearing, and CSR Names validation. It stages disabled requests only; no Apply or external
certificate mutation is performed. Captures are local fixture evidence, not deployed-appliance or native zoom evidence.
The existing CA grid resize exception tracked in [#1040](https://github.com/mdaneri/Atlaso/issues/1040) is reported
separately; every other browser exception fails the fixture.

## vSphere grid refresh

`vsphere-grid-refresh.cjs` runs the production vSphere initializer, resource save/delete callbacks and vendored
Tabulator with synthetic mutation responses. It verifies visible provider labels, collection badges, provider trust
counts, rejected deletion, and preservation of sort, filters, selection, scroll and the synthetic Add row at desktop
and narrow viewports. Wizard navigation, backend admission and native appliance acceptance are outside this fixture.
With Playwright and Microsoft Edge available, set `ATLASO_BROWSER_OUTPUT`, `TEMP` and `TMP` to an originally receipted
task-owned output directory, then run `node tests/browser/vsphere-grid-refresh.cjs`.

## Appliance Apply task scrolling

`appliance-apply-scroll.cjs` renders the production Apply dialog markup, CSS, shared Tabulator foundation, and task
rendering functions with synthetic task data. It does not submit an Apply or connect to an appliance. With Playwright
available to Node and Microsoft Edge installed, set `ATLASO_BROWSER_OUTPUT`, `TEMP`, and `TMP` to the same originally
receipted task-owned output directory beneath the configured worktree root, then run:

```powershell
node tests/browser/appliance-apply-scroll.cjs
```

The checks cover long and short lists, tree expansion, final-row reachability, horizontal overflow, footer accessibility,
focus, task updates, and running/completed/failed detail views. Desktop, short, narrow, and a 200% zoom-equivalent CSS
viewport are captured. The fixture forces space-consuming scrollbar styling to exercise hosts that normally use overlay
scrollbars. These captures are layout evidence, not deployed-appliance acceptance or native browser-zoom evidence.

## Network Boot host reference

Run from a task worktree with the repository Python test dependencies, Playwright
available to Node, and Microsoft Edge installed. Choose an unused fixture root
beneath the configured worktree root and an unused loopback port:

```powershell
python tests/browser/network_boot_fixture.py --root <absolute-task-owned-root> --port 18783
```

In a second terminal, set `ATLASO_BROWSER_FIXTURE_URL` to
`http://127.0.0.1:18783`, `ATLASO_BROWSER_OUTPUT` to an absolute task-owned output
directory, and `TEMP`/`TMP` to that same output directory. Set `NODE_PATH` to the
installed Playwright package directory if it is not otherwise resolvable. Run:

```powershell
node tests/browser/network-boot-host-reference.cjs
```

The fixture signs into an isolated SQLite-backed TestClient with synthetic test
credentials and the development adapter. It serves only loopback and never
connects to a deployed appliance. The browser test exercises actual templates,
shared grids/wizards, native validity, and supported Kickstart create/delete
routes. Discovery HTTP responses are controlled fixtures to reproduce first-row
arrival deterministically. No boot or Appliance Apply is submitted. The captures
are fixture evidence, not deployed-appliance acceptance evidence.

Stop the fixture with Ctrl+C after validation. Preserve required evidence and
release its exact task-owned database, logs, browser output, and temporary files
through the task's resource cleanup workflow.
