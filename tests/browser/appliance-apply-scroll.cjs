// Render production modal markup/assets with synthetic tasks; no appliance mutation.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require("playwright");

const root = path.resolve(__dirname, "../..");
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");
const source = read("atlaso/app/static/app.js");
function productionFunction(name) {
  const start = source.indexOf(`function ${name}(`);
  assert(start >= 0, `Missing production function ${name}`);
  const end = source.indexOf("\n}", start);
  assert(end > start, `Missing production function boundary for ${name}`);
  return source.slice(start, end + 2);
}
const names = ["escapeHtml", "taskStatusActive", "taskStatusPillHtml", "applianceApplyModalElements",
  "showApplianceApplyModal", "clearApplianceApplyAutoClose", "scheduleApplianceApplyAutoClose",
  "applianceApplyDuration", "renderApplianceApplyStepDetail", "renderApplianceApplyTask"];
const template = read("atlaso/app/templates/base.html");
const start = template.indexOf('<dialog id="appliance-apply-modal"');
const markup = template.slice(start, template.indexOf("</dialog>", start) + 9).replaceAll("{{ csrf_token }}", "fixture");
const output = process.env.ATLASO_BROWSER_OUTPUT;
assert(output && path.isAbsolute(output), "ATLASO_BROWSER_OUTPUT must name an owned absolute output root");
const task = (count, status = "running") => ({
  id: "fixture-apply", type_label: "Appliance Apply", status, state: status,
  status_pill: status === "failed" ? "bad" : "warn", can_cancel: status === "running",
  progress_percent: 12, created_at: new Date().toISOString(),
  _children: Array.from({ length: count }, (_, i) => ({ id: `step-${i}`, label: `Component ${i + 1}`,
    is_step: true, status: i === 0 ? "succeeded" : status === "failed" ? "skipped" : status,
    state: status, progress_percent: i === 0 ? 100 : 0, result_json: JSON.stringify({ result: "Synthetic result" }) })),
});

(async () => {
  fs.mkdirSync(output, { recursive: true });
  const browser = await chromium.launch({ channel: "msedge", headless: true });
  try {
    const page = await browser.newPage();
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    await page.setContent(`<html><head></head><body><button id="launcher">Inspect fixture</button>${markup}</body></html>`);
    await page.addStyleTag({ path: path.join(root, "atlaso/app/static/vendor/tabulator/tabulator.min.css") });
    await page.addStyleTag({ content: read("atlaso/app/static/app.css") });
    // Exercise space-consuming scrollbars even on hosts configured for overlay scrollbars.
    await page.addStyleTag({ content: "::-webkit-scrollbar { width: 15px; height: 15px; } ::-webkit-scrollbar-thumb { background: #888; }" });
    await page.addScriptTag({ path: path.join(root, "atlaso/app/static/vendor/tabulator/tabulator.min.js") });
    await page.addScriptTag({ path: path.join(root, "atlaso/app/static/ui-patterns.js") });
    await page.addScriptTag({ content: `let applianceApplyModalTable = null; let applianceApplyAutoCloseTimer = 0;
      const APPLIANCE_APPLY_SUCCESS_AUTO_CLOSE_MS = 15000;
      function highlightConfigPreviewElement() {}
      ${names.map(productionFunction).join("\n")}` });
    const render = async (count, status = "running") => {
      await page.evaluate((data) => {
        const ready = applianceApplyModalTable ? new Promise((resolve) => {
          const done = () => { applianceApplyModalTable.off("dataProcessed", done); resolve(); };
          applianceApplyModalTable.on("dataProcessed", done);
        }) : Promise.resolve();
        renderApplianceApplyTask(data);
        return ready;
      }, task(count, status));
      await page.waitForFunction(() => document.querySelectorAll(".tabulator-row").length > 0);
      await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    };
    const inspect = () => page.evaluate(() => {
      const modal = document.getElementById("appliance-apply-modal");
      const grid = document.getElementById("appliance-apply-live-grid");
      const holder = grid.querySelector(".tabulator-tableholder");
      const footer = modal.querySelector(".appliance-apply-live > .appliance-apply-modal-actions");
      const rect = (element) => { const r = element.getBoundingClientRect(); return { top: r.top, bottom: r.bottom, left: r.left, right: r.right }; };
      return {
        scrollers: [modal, ...modal.querySelectorAll("*")].filter((element) =>
          /auto|scroll/.test(getComputedStyle(element).overflowY) && element.scrollHeight > element.clientHeight + 1)
          .map((element) => element.className),
        modal: rect(modal), footer: rect(footer), holder: rect(holder),
        horizontal: holder.scrollWidth > holder.clientWidth, height: innerHeight, width: innerWidth,
      };
    });
    const results = [];
    for (const [label, width, height] of [["desktop", 1600, 1000], ["short", 1280, 600],
      ["narrow", 420, 740], ["zoom-200-equivalent", 800, 500]]) {
      await page.setViewportSize({ width, height });
      await render(17);
      const geometry = await inspect();
      results.push({ label, ...geometry });
      await page.screenshot({ path: path.join(output, `${label}.png`) });
      assert.equal(geometry.scrollers.length, 1, `${label}: ${JSON.stringify(geometry)}`);
      assert.match(geometry.scrollers[0], /tabulator-tableholder/);
      assert(geometry.modal.top >= 0 && geometry.modal.bottom <= height + 1, `${label}: modal fits`);
      assert(geometry.footer.bottom <= height && geometry.footer.top >= 0, `${label}: footer reachable`);
      if (width < 900) assert(geometry.horizontal, `${label}: necessary horizontal overflow retained`);
      await page.evaluate(() => {
        const holder = document.querySelector("#appliance-apply-live-grid .tabulator-tableholder");
        holder.scrollTop = holder.scrollHeight;
      });
      await page.waitForFunction(() => {
        const row = applianceApplyModalTable.getRows()[0].getTreeChildren().at(-1).getElement();
        const holder = document.querySelector("#appliance-apply-live-grid .tabulator-tableholder");
        const r = row.getBoundingClientRect(), h = holder.getBoundingClientRect();
        return r.height > 0 && r.top >= h.top && r.bottom <= h.bottom + 1;
      }, null, { timeout: 2000 });
      await page.evaluate(() => applianceApplyModalTable.getRows()[0].treeCollapse());
      assert.equal((await inspect()).scrollers.length, 0, `${label}: collapsed list needs no vertical scrolling`);
      await page.evaluate(() => applianceApplyModalTable.getRows()[0].treeExpand());
      assert.equal((await inspect()).scrollers.length, 1, `${label}: expanded scroll ownership`);
      await page.locator('[data-appliance-apply-cancel]').focus();
      assert(await page.locator('[data-appliance-apply-cancel]').evaluate((el) => el === document.activeElement));
      await page.keyboard.press("Shift+Tab");
      assert(await page.evaluate(() => document.getElementById("appliance-apply-modal").contains(document.activeElement)));
      for (const status of ["running", "succeeded", "failed"]) {
        await render(17, status);
        await page.evaluate(async () => {
          const child = applianceApplyModalTable.getRows()[0].getTreeChildren()[0];
          await applianceApplyModalTable.scrollToRow(child, "top", false);
          child.getElement().focus();
        });
        await page.keyboard.press("Enter");
        assert(await page.locator('[data-appliance-apply-step-detail]').isVisible(), `${label}: keyboard opens detail`);
        await page.evaluate((state) => renderApplianceApplyStepDetail({ id: "step-1", is_step: true,
          label: "Component detail", status: state, error: state === "failed" ? "Synthetic failure" : "",
          result_json: "Fixture line\n".repeat(100) }), status);
        const detailGeometry = await inspect();
        assert(detailGeometry.footer.bottom <= Math.min(height, detailGeometry.modal.bottom),
          `${label}/${status}: detail leaves footer accessible: ${JSON.stringify(detailGeometry)}`);
        assert(await page.locator(status === "running" ? '[data-appliance-apply-cancel]' : '[data-appliance-apply-result-close]').isVisible());
        await page.screenshot({ path: path.join(output, `${label}-${status}-detail.png`) });
      }
      await page.evaluate(() => document.querySelector('[data-appliance-apply-step-detail]').classList.add("hidden"));
    }
    await page.setViewportSize({ width: 1280, height: 600 });
    await render(2);
    assert.equal((await inspect()).scrollers.length, 0, "Short list has no vertical scrollbars");
    assert.deepEqual(errors, []);
    fs.writeFileSync(path.join(output, "results.json"), JSON.stringify(results, null, 2));
    console.log("Apply dialog browser checks passed: overflow, collapse/expand, short list, responsive layout, focus, live updates and result states.");
  } finally {
    await browser.close();
  }
})().catch((error) => { console.error(error); process.exitCode = 1; });
