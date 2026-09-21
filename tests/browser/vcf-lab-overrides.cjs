// Deterministic browser coverage of the real template and shared wizard adapter.
// NODE_PATH supplies Playwright; TEMP and TMP must point inside the owned task root.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const { execFileSync } = require("node:child_process");
const { chromium } = require("playwright");
const template = execFileSync("python", ["-B", "-c", "from jinja2 import Environment,FileSystemLoader; from types import SimpleNamespace; print(Environment(loader=FileSystemLoader('atlaso/app/templates')).get_template('partials/vcf_lab_overrides.html').render(identity=SimpleNamespace(has_role=lambda role: True),management_ui_root='/ui/management',csrf_token='fixture-csrf'))"], {encoding: "utf8"});
const vaults = [{name: "Fixture", entries: [
  {id: 1, key: "API", username: "admin", has_value: true, uris: ["https://vcf.example.test"]},
  {id: 2, key: "SSH", username: "vcf", has_value: true, uris: ["ssh://vcf.example.test"]},
  {id: 3, key: "Root", username: "root", has_value: true, uris: ["ssh://vcf.example.test"]},
]}];
const html = `<html><head><style>${fs.readFileSync("atlaso/app/static/app.css", "utf8")}</style></head><body><button data-vcf-lab-open>Lab overrides</button>${template}<script id="vcf-vault-credential-options" type="application/json">${JSON.stringify(vaults)}</script><script>${fs.readFileSync("atlaso/app/static/ui-patterns.js", "utf8")}</script><script>window.requestConfirmation=async()=>true;</script><script>${fs.readFileSync("atlaso/app/static/vcf-lab-overrides.js", "utf8")}</script></body></html>`;
(async () => {
  const browser = await chromium.launch({channel: "msedge", headless: true});
  try {
    for (const viewport of [{width: 1600, height: 1000}, {width: 900, height: 1200}, {width: 430, height: 800}]) {
      const page = await browser.newPage({viewport});
      const errors = [], calls = [];
      let rejectSubmit = true, tlsAvailable = true;
      page.on("pageerror", (error) => errors.push(error.message));
      await page.route("http://atlaso.test/**", async (route) => {
        const operation = route.request().url().split("/").pop();
        if (operation === "") return route.fulfill({contentType: "text/html", body: html});
        calls.push({operation, body: route.request().postDataJSON()});
        if (operation === "history") return route.fulfill({json: {jobs: [{id: "previous", target: "vcf.example.test", status: "succeeded", created_at: "fixture"}]}});
        if (operation === "probe") return route.fulfill({json: {target: "vcf.example.test", tls_fingerprint: tlsAvailable ? "tls-fixture" : "", ssh_fingerprint: "ssh-fixture"}});
        if (operation === "inspect") return route.fulfill({json: {target: "vcf.example.test", role: "VcfInstaller", version: "9.1.1", values: {esa: null, nic: "true"}, service_active: true}});
        if (operation === "review") return route.fulfill({json: {token: "review-fixture", target: "vcf.example.test", role: "VcfInstaller", version: "9.1.1", changes: [{key: "enable.speed.of.physical.nics.validation", previous: "true", value: "false"}], restart_required: true}});
        if (operation === "execute" && rejectSubmit) { rejectSubmit = false; return route.fulfill({status: 409, json: {detail: "Transient fixture failure; retry."}}); }
        if (operation === "execute") return route.fulfill({json: {job_id: "fixture-task"}});
        throw new Error(`Unexpected request: ${operation}`);
      });
      await page.goto("http://atlaso.test/");
      const modal = page.locator("#vcf-lab-modal");
      const next = page.locator("[data-atlaso-wizard-next]");
      await page.locator("[data-vcf-lab-open]").click();
      await modal.waitFor({state: "visible"});
      await page.waitForFunction(() => document.activeElement?.name === "api_credential");
      for (const [name, value] of [["api_credential", "1:1"], ["ssh_credential", "2:1"], ["root_credential", "3:1"]]) await page.locator(`[name="${name}"]`).selectOption(value);
      await next.click(); await next.click();
      await next.click();
      assert.match(await page.locator("[data-atlaso-wizard-error]").textContent(), /confirm/i);
      assert(!calls.some((call) => ["inspect", "execute"].includes(call.operation)));
      await page.locator('[data-lab-action="probe"]').click();
      await page.waitForFunction(() => document.querySelector('[data-lab-ssh]').textContent === 'ssh-fixture');
      await page.locator('[name="confirmed"]').check(); await next.click();
      await page.locator('[data-lab-action="inspect"]').click();
      await page.waitForFunction(() => document.querySelector('[data-lab-observed]').textContent.includes('VcfInstaller'));
      await next.click(); await page.locator('[name="nic"]').check(); await next.click();
      await page.locator('[data-atlaso-wizard-step="review"]').waitFor({state: "visible"});
      assert(!calls.some((call) => call.operation === "execute"));
      const review = calls.find((call) => call.operation === "review");
      assert.equal(review.body.root_entry_id, 3); assert.equal(review.body.ssh_entry_id, 2);
      await page.locator('[data-atlaso-wizard-back]').click();
      await page.locator('[name="nic"]').uncheck();
      await page.locator('[name="esa"]').check();
      await next.click();
      await page.locator('[data-atlaso-wizard-step="review"]').waitFor({state: "visible"});
      assert.deepEqual(calls.filter((call) => call.operation === "review").at(-1).body.selections, ["esa"]);
      assert.equal(await page.locator('[name="acknowledged"]').isChecked(), false);
      await page.locator('[name="acknowledged"]').check();
      await page.locator('[data-atlaso-wizard-submit]').click();
      await page.waitForFunction(() => document.querySelector('[data-atlaso-wizard-error]').textContent.includes('Transient'));
      assert(await modal.isVisible()); assert(await page.locator('[name="acknowledged"]').isChecked());
      await page.locator('[data-atlaso-wizard-submit]').click();
      await page.locator('[data-lab-task]').waitFor({state: "visible"});
      assert.match(await page.locator('[data-lab-task]').getAttribute('href'), /fixture-task/);
      assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
      assert.equal(await modal.evaluate((element) => element.scrollWidth <= element.clientWidth + 1), true);
      await page.locator('[data-atlaso-wizard-cancel]').click();
      await page.waitForFunction(() => document.activeElement?.hasAttribute('data-vcf-lab-open'));
      await page.locator('[data-vcf-lab-open]').click();
      assert.equal(await page.locator('[name="api_credential"]').inputValue(), "");
      assert.equal(await page.locator('[name="confirmed"]').isChecked(), false);
      tlsAvailable = false;
      for (const [name, value] of [["api_credential", "1:1"], ["ssh_credential", "2:1"], ["root_credential", "3:1"]]) await page.locator(`[name="${name}"]`).selectOption(value);
      await next.click(); await next.click();
      await page.locator('[data-lab-action="probe"]').click();
      await page.waitForFunction(() => document.querySelector('[data-lab-tls]').textContent.includes('Unavailable'));
      await page.locator('[name="confirmed"]').check(); await next.click(); await next.click();
      await page.locator('[name="source_job_id"]').selectOption('previous');
      await next.click();
      await page.locator('[data-atlaso-wizard-step="review"]').waitFor({state: "visible"});
      assert.equal(calls.filter((call) => call.operation === "review").at(-1).body.source_job_id, 'previous');
      assert.equal(calls.filter((call) => call.operation === "execute").length, 2);
      assert.deepEqual(errors, []);
      console.log(`PASS shared lab wizard ${viewport.width}x${viewport.height}`);
      await page.close();
    }
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exitCode = 1; });
