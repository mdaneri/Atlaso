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
      let rejectSubmit = true;
      const departures = [];
      await page.exposeFunction('recordDeparture', (data) => departures.push(data));
      await page.addInitScript(() => document.addEventListener('DOMContentLoaded', () => {
        document.querySelector('#vcf-lab-modal')?.addEventListener('close', () => window.recordDeparture({open: document.querySelector('#vcf-lab-modal').open, passwords: [...document.querySelectorAll('input[type="password"]')].map(el => el.value)}));
      }));
      page.on("pageerror", (error) => errors.push(error.message));
      await page.route("http://atlaso.test/**", async (route) => {
        if (route.request().url().includes('/tasks?job_id=')) {
          return route.fulfill({contentType: 'text/html', body: '<p>Task details fixture</p>'});
        }
        const operation = route.request().url().split("/").pop();
        if (operation === "") return route.fulfill({contentType: "text/html", body: html});
        calls.push({operation, body: route.request().postDataJSON()});
        if (operation === "probe") return route.fulfill({json: {target: "vcf.example.test", ssh_fingerprint: "ssh-fixture"}});
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
      await page.waitForFunction(() => document.activeElement?.name === "credential_mode");
      for (const [name, value] of [["ssh_credential", "2:1"], ["root_credential", "3:1"]]) await page.locator(`[name="${name}"]`).selectOption(value);
      await next.click(); await next.click();
      await page.waitForFunction(() => document.querySelector('[data-lab-ssh]').textContent === 'ssh-fixture');
      await next.click();
      assert.match(await page.locator("[data-atlaso-wizard-error]").textContent(), /confirm/i);
      assert(!calls.some((call) => ["inspect", "execute"].includes(call.operation)));
      await page.waitForFunction(() => document.querySelector('[data-lab-ssh]').textContent === 'ssh-fixture');
      assert.equal(await page.locator('[data-lab-action="probe"]').count(), 0);
      assert.equal(calls.filter((call) => call.operation === "probe").length, 1);
      const checkbox = await page.locator('[name="confirmed"]').boundingBox();
      const approval = await page.locator('[name="confirmed"] + span').boundingBox();
      assert(checkbox.x + checkbox.width <= approval.x + 2);
      assert(Math.abs(checkbox.y - approval.y) < approval.height);
      assert.equal(await page.locator('[data-atlaso-wizard-step="trust"]').evaluate((el) => el.scrollWidth <= el.clientWidth + 1), true);
      await page.locator('[name="confirmed"]').check(); await next.click();
      assert(await page.locator('[data-atlaso-wizard-step="options"]').isVisible());
      assert(await page.locator('[name="ssh_password"]').isDisabled());
      await page.locator('[data-lab-action="inspect"]').click();
      await page.waitForFunction(() => document.querySelector('[data-lab-observed]').textContent.includes('VcfInstaller'));
      assert.equal(await page.locator('[name="nic"]').inputValue(), 'true');
      assert.equal(await page.locator('[name="esa"]').inputValue(), 'absent');
      await page.locator('[name="nic"]').selectOption("false"); await next.click();
      await page.locator('[data-atlaso-wizard-step="review"]').waitFor({state: "visible"});
      assert(!calls.some((call) => call.operation === "execute"));
      const review = calls.find((call) => call.operation === "review");
      assert.equal(review.body.root_entry_id, 3); assert.equal(review.body.ssh_entry_id, 2);
      await page.locator('[data-atlaso-wizard-back]').click();
      await page.locator('[name="nic"]').selectOption("true");
      await page.locator('[name="esa"]').selectOption("true");
      await next.click();
      await page.locator('[data-atlaso-wizard-step="review"]').waitFor({state: "visible"});
      assert.deepEqual(calls.filter((call) => call.operation === "review").at(-1).body.desired, {esa: "true", nic: "true"});
      assert.equal(await page.locator('[name="acknowledged"]').isChecked(), false);
      await page.locator('[name="acknowledged"]').check();
      await page.locator('[data-atlaso-wizard-submit]').click();
      await page.waitForFunction(() => document.querySelector('[data-atlaso-wizard-error]').textContent.includes('Transient'));
      assert(await modal.isVisible()); assert(await page.locator('[name="acknowledged"]').isChecked());
      await page.locator('[data-atlaso-wizard-submit]').click();
      await page.waitForURL('**/tasks?job_id=fixture-task');
      assert.deepEqual(departures.at(-1), {open: false, passwords: ['', '']});
      await page.goto('http://atlaso.test/');
      await page.locator('[data-vcf-lab-open]').click();
      assert.equal(await page.locator('[name="ssh_credential"]').inputValue(), "");
      assert.equal(await page.locator('[name="confirmed"]').isChecked(), false);
      await page.locator('[name="credential_mode"]').selectOption('manual');
      await next.click();
      await page.locator('[name="host"]').fill('vcf.example.test');
      await next.click();
      await page.waitForFunction(() => document.querySelector('[data-lab-ssh]').textContent === 'ssh-fixture');
      assert.equal(calls.filter((call) => call.operation === 'probe').at(-1).body.credentials, undefined);
      await page.locator('[name="confirmed"]').check(); await next.click();
      assert(await page.locator('[data-atlaso-wizard-step="login"]').isVisible());
      assert(!(await page.locator('[name="ssh_password"]').isDisabled()));
      for (const kind of ['ssh', 'root']) await page.locator(`[name="${kind}_password"]`).fill(`synthetic-${kind}`);
      await next.click();
      await page.locator('[data-lab-action="inspect"]').click();
      await page.waitForFunction(() => document.querySelector('[data-lab-observed]').textContent.includes('VcfInstaller'));
      await page.locator('[name="esa"]').selectOption("true"); await next.click();
      await page.locator('[data-atlaso-wizard-step="review"]').waitFor({state:'visible'});
      assert.equal(calls.filter((call) => call.operation === 'review').at(-1).body.credential_mode, 'manual');
      await page.locator('[name="acknowledged"]').check();
      await page.locator('[data-atlaso-wizard-submit]').click();
      await page.waitForURL('**/tasks?job_id=fixture-task');
      assert.deepEqual(departures.at(-1), {open: false, passwords: ['', '']});
      assert.deepEqual(calls.filter((call) => call.operation === 'execute').at(-1).body.credentials, {ssh:'synthetic-ssh',root:'synthetic-root'});
      assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
      assert.deepEqual(errors, []);
      console.log(`PASS shared lab wizard ${viewport.width}x${viewport.height}`);
      await page.close();
    }
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exitCode = 1; });
