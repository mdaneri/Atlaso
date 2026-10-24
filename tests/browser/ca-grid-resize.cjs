// Exercise the real CA page and vendored Tabulator with display-only synthetic rows.
const assert = require("node:assert/strict");
const path = require("node:path");
const { chromium } = require("playwright");

(async () => {
  const url = process.env.ATLASO_BROWSER_FIXTURE_URL;
  const output = process.env.ATLASO_BROWSER_OUTPUT;
  assert(url && output && path.isAbsolute(output), "Explicit isolated fixture URL and receipted output root required");
  assert.equal(new URL(url).hostname, "127.0.0.1", "Run only against the loopback test fixture");
  const browser = await chromium.launch({ channel: "msedge", headless: true });
  try {
    for (const [label, width, height] of [["desktop", 1600, 1000], ["narrow", 900, 1200], ["zoom-equivalent", 800, 500]]) {
      const page = await browser.newPage({ viewport: { width, height } });
      const errors = [];
      const mutations = [];
      page.on("pageerror", (error) => errors.push(error.stack));
      page.on("request", (request) => {
        const pathname = new URL(request.url()).pathname;
        // The normal session activity heartbeat is unrelated to desired-state mutation.
        if (request.method() !== "GET" && pathname !== "/ui/management/session/activity") {
          mutations.push(`${request.method()} ${pathname}`);
        }
      });
      await page.goto(`${url}/ui/management/certificate-authority`);
      await page.getByRole("button", { name: "+ Add certificate here", exact: true }).waitFor();
      const grid = page.locator("#ca-certificates-table");
      const settle = () => page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
      const inlineHeight = () => grid.evaluate((element) => element.style.height);
      await settle();
      assert.equal(Boolean(await inlineHeight()), width > 1100);

      // Reproduce the original transition, including the CSR wizard opening.
      await page.getByRole("tab", { name: "CSR Intake", exact: true }).click();
      await page.locator("[data-ca-csr-open]").click();
      await settle();
      assert.equal(await inlineHeight(), "");
      await page.locator("#ca-csr-dialog [data-atlaso-wizard-cancel]").click();
      const certificates = page.getByRole("tab", { name: "Certificates", exact: true });
      await certificates.focus();
      await page.keyboard.press("Enter");
      await settle();
      assert.equal(Boolean(await inlineHeight()), width > 1100);

      await page.evaluate(async () => {
        const table = document.getElementById("ca-certificates-table").atlasoTabulator;
        const addRow = table.getData().find((row) => row.is_new);
        await table.replaceData([
          ...Array.from({ length: 60 }, (_, index) => ({
            id: 90000 + index, common_name: `resize-${String(index).padStart(2, "0")}.example.test`,
            status: "pending", enabled: false, profile_name: "Synthetic profile", can_edit: true,
          })),
          addRow,
        ]);
        table.setFilter("common_name", "like", "resize-");
        table.setSort("common_name", "desc");
      });
      const before = await grid.evaluate((element) => ({
        filters: element.atlasoTabulator.getFilters(),
        sorters: element.atlasoTabulator.getSorters().map(({ field, dir }) => ({ field, dir })),
      }));
      for (let cycle = 0; cycle < 3; cycle += 1) {
        await page.getByRole("tab", { name: "Profiles", exact: true }).click();
        await page.setViewportSize({ width, height: height - 60 });
        await settle();
        assert.equal(await inlineHeight(), "");
        await certificates.click();
        await settle();
      }
      const after = await grid.evaluate((element) => ({
        filters: element.atlasoTabulator.getFilters(),
        sorters: element.atlasoTabulator.getSorters().map(({ field, dir }) => ({ field, dir })),
      }));
      assert.deepEqual(after, before);
      assert.equal(await grid.evaluate((element) => element.atlasoTabulator.getData().filter((row) => row.is_new).length), 1);
      assert.equal(Boolean(await inlineHeight()), width > 1100);
      if (width > 1100) {
        const tallHeight = await inlineHeight();
        await page.setViewportSize({ width, height: height - 160 });
        await settle();
        assert.notEqual(await inlineHeight(), tallHeight, "Visible desktop grid responds to window height changes");
        await page.setViewportSize({ width: 900, height });
        await settle();
        assert.equal(await inlineHeight(), "", "Visible narrow grid uses the CSS fallback");
        await page.setViewportSize({ width, height });
        await settle();
        assert.ok(await inlineHeight(), "Desktop dynamic sizing resumes");
      }
      await grid.screenshot({ path: path.join(output, `ca-grid-resize-${label}.png`) });
      assert.deepEqual(errors, [], "Every browser exception fails this regression");
      assert.deepEqual(mutations, [], "Grid sizing and navigation must not mutate desired state");
      console.log(`${label}: CSR wizard, repeated hidden/visible transitions, responsive height, filters, sorting, Add row and keyboard activation passed`);
      await page.close();
    }
  } finally {
    await browser.close();
  }
})().catch((error) => { console.error(error); process.exitCode = 1; });
