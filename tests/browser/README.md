# Network Boot browser regression fixture

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
