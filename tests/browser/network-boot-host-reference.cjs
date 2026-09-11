// Run against an explicitly isolated, authenticated Atlaso test fixture.
// NODE_PATH must expose Playwright; keep browser state and output under the task root.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require("playwright");

(async () => {
  const url = process.env.ATLASO_BROWSER_FIXTURE_URL;
  const output = process.env.ATLASO_BROWSER_OUTPUT;
  assert(url && output, "Explicit isolated fixture URL and task-owned output path are required");
  fs.mkdirSync(output, { recursive: true });
  const browser = await chromium.launch({ channel: "msedge", headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
    const failures = [];
    page.on("pageerror", (error) => failures.push(error.message));
    let hosts = [];
    await page.route("**/api/v1/network-boot/hosts", (route) => route.fulfill({ json: hosts }));
    await page.route(/\/api\/v1\/network-boot\/hosts\/\d+$/, (route) => {
      const host = hosts.find((item) => String(item.id) === route.request().url().split("/").pop());
      return route.fulfill({ json: { ...host, latest_report: { assigned_addresses: ["192.0.2.10/24"] } } });
    });
    await page.goto(`${url}/ui/management/network-boot`);
    await page.waitForFunction(() => document.getElementById("network-boot-discovered-table")?.atlasoTabulator);
    const wizard = page.locator("#network-boot-promote-dialog");
    const refresh = () => page.evaluate(() => networkBootDiscoveredHostRefresh.refresh());
    const close = () => page.evaluate(() => esxiHostReferenceWizard.close("cancel"));
    const promote = async (id) => {
      await page.evaluate(async (hostId) => {
        const table = document.getElementById("network-boot-discovered-table").atlasoTabulator;
        const row = table.getRow(hostId);
        await table.options.rowContextMenu.find((action) => String(action.label).includes("Promote to ESXi")).action(null, row);
      }, id);
      await wizard.waitFor({ state: "visible" });
      assert.equal(await wizard.locator('[name="host_id"]').inputValue(), String(id));
    };
    hosts = [{ id: 803, boot_mac: "00:0c:29:be:e2:b6", macs: ["00:0c:29:be:e2:b6"], product_name: "fixture-host", assigned_to_esxi: false }];
    await refresh();
    await promote(803);
    await close();
    hosts.push({ ...hosts[0], id: 804, boot_mac: "00:0c:29:be:e2:b7", macs: ["00:0c:29:be:e2:b7"] });
    await refresh();
    await promote(804);
    await close();
    await promote(803);
    await refresh();
    assert.equal(await wizard.locator('[name="host_id"]').inputValue(), "803");
    await close();

    // Existing records must start native-valid, without an input/blur workaround.
    await page.evaluate(() => openEsxiHostReferenceWizard({ mode: "edit", host: {
      id: 805, hostname: "fixture-edit", mac_address: "00:0c:29:be:e2:b6", enabled: false,
      variables_json: "{}", kickstart_id: null, installer_iso_path: "",
    } }));
    const mac = wizard.locator('[name="manual_mac_address"]');
    assert.deepEqual(await mac.evaluate((field) => [field.checkValidity(), field.validationMessage, field.getAttribute("aria-invalid")]), [true, "", "false"]);
    for (const value of ["", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01", "bad"]) {
      await mac.fill(value);
      assert.equal(await mac.evaluate((field) => field.checkValidity()), false);
      await wizard.locator("[data-atlaso-wizard-next]").click();
      assert.equal(await page.evaluate(() => esxiHostReferenceWizard.currentStepId), "identity");
    }
    await mac.fill("00:0c:29:be:e2:b6");
    await wizard.locator("[data-atlaso-wizard-next]").click();
    await page.waitForFunction(() => document.querySelector("[data-esxi-host-kickstart-status]").dataset.state === "ready");
    assert.equal(await page.evaluate(() => esxiHostReferenceWizard.currentStepId), "installer");

    // Create through the supported server flow after the browser page was loaded.
    const kickstart = await page.evaluate(async () => {
      const body = new FormData();
      body.set("csrf", document.querySelector('[name="csrf"]').value);
      body.set("name", `browser-refresh-fixture-${Date.now()}`);
      body.set("content", "vmaccepteula\nreboot\n");
      const response = await fetch(managementUiPath("/esxi-pxe/kickstarts"), {
        method: "POST", body, headers: { "X-Atlaso-Grid": "1", Accept: "application/json" },
      });
      if (!response.ok) throw new Error(`Create failed: ${response.status}`);
      return (await response.json()).kickstart;
    });
    await wizard.locator("[data-esxi-host-refresh-kickstarts]").click();
    await page.waitForFunction(() => document.querySelector("[data-esxi-host-kickstart-status]").dataset.state === "ready");
    await wizard.locator('[name="kickstart_id"]').selectOption(String(kickstart.id));
    await page.evaluate(async (item) => {
      const table = document.getElementById("esxi-pxe-hosts-table").atlasoTabulator;
      const row = await table.addRow({ id: -809, hostname: "grid-refresh-proof", kickstart_id: item.id });
      if (row.getCell("kickstart_id").getElement().textContent !== item.name) throw new Error("Stale grid label");
      const values = table.getColumn("kickstart_id").getDefinition().editorParams().values;
      if (values[item.id] !== item.name) throw new Error("Stale default-row choices");
      await row.delete();
    }, kickstart);
    await wizard.locator("[data-esxi-host-refresh-kickstarts]").click();
    await page.waitForFunction(() => document.querySelector("[data-esxi-host-kickstart-status]").dataset.state === "ready");
    assert.equal(await wizard.locator('[name="kickstart_id"]').inputValue(), String(kickstart.id));
    // Refresh failure and deletion cannot silently change a selected scripted install to None.
    const failRefresh = (route) => route.fulfill({ status: 503, body: "unavailable" });
    await page.route("**/ui/management/network-boot", failRefresh);
    await wizard.locator("[data-esxi-host-refresh-kickstarts]").click();
    await page.waitForFunction(() => document.querySelector("[data-esxi-host-kickstart-status]").dataset.state === "error");
    assert.equal(await wizard.locator('[name="kickstart_id"]').inputValue(), String(kickstart.id));
    await wizard.locator("[data-atlaso-wizard-next]").click();
    assert.equal(await page.evaluate(() => esxiHostReferenceWizard.currentStepId), "installer");
    await page.unroute("**/ui/management/network-boot", failRefresh);
    await page.evaluate(async (id) => {
      const body = new FormData();
      body.set("csrf", document.querySelector('[name="csrf"]').value);
      const response = await fetch(managementUiPath(`/esxi-pxe/kickstarts/${id}/delete`), {
        method: "POST", body, headers: { "X-Atlaso-Grid": "1", Accept: "application/json" },
      });
      if (!response.ok) throw new Error(`Delete failed: ${response.status}`);
    }, kickstart.id);
    await wizard.locator("[data-esxi-host-refresh-kickstarts]").click();
    await page.waitForFunction(() => document.querySelector('#network-boot-promote-dialog [name="kickstart_id"]').selectedOptions[0]?.dataset.unavailable === "true");
    assert.equal(await wizard.locator('[name="kickstart_id"]').inputValue(), String(kickstart.id));
    await wizard.locator("[data-atlaso-wizard-next]").click();
    assert.equal(await page.evaluate(() => esxiHostReferenceWizard.currentStepId), "installer");
    await wizard.locator('[name="kickstart_id"]').selectOption("");
    await wizard.locator("[data-atlaso-wizard-next]").click();
    assert.equal(await page.evaluate(() => esxiHostReferenceWizard.currentStepId), "enablement");
    await page.screenshot({ path: path.join(output, "enabled-desktop.png") });
    await page.setViewportSize({ width: 900, height: 1200 });
    await page.screenshot({ path: path.join(output, "enabled-narrow.png") });
    await close();
    const blocked = await page.evaluate(async () => {
      const host = { id: 807, enabled: true, kickstart_id: 1 };
      const reason = esxiHostAuthorizationDisabledReason(host);
      await requestEsxiHostBootAuthorization({ getData: () => host });
      return { reason, opened: document.getElementById("esxi-boot-authorization-dialog").open };
    });
    assert.match(blocked.reason, /disabled/);
    assert.equal(blocked.opened, false);
    assert.deepEqual(failures, []);
    console.log("Network Boot browser regressions passed; desktop and narrow captures saved.");
  } finally {
    await browser.close();
  }
})().catch((error) => { console.error(error); process.exitCode = 1; });
