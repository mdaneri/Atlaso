// Production enrollment template, request adapter, and wizard with synthetic vCenter responses.
// This verifies browser recovery and layout; it does not establish native vCenter interoperability.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { chromium } = require("playwright");
const root = path.resolve(__dirname, "../..");
const output = process.env.ATLASO_BROWSER_OUTPUT;
assert(output && path.isAbsolute(output), "Use an originally receipted task output root");
const source = fs.readFileSync(path.join(root, "atlaso/app/static/app.js"), "utf8");
const functionSource = (name) => {
  const match = new RegExp(`(?:async )?function ${name}\\(`).exec(source);
  assert(match, `Missing ${name}`);
  return source.slice(match.index, source.indexOf("\n}", match.index) + 2);
};
const fixture = spawnSync("python", ["-B", "-"], { cwd: root, encoding: "utf8", input: `
import json
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
from atlaso.app.services.vsphere_enrollment import EnrollmentError, _check_cluster_endpoint
templates=Path('atlaso/app/templates')
source=(templates/'kms.html').read_text(encoding='utf-8')
start=source.index('{% set enrollment_steps')
end=source.index('{% endcall %}', start)+len('{% endcall %}')
env=Environment(loader=FileSystemLoader(templates), autoescape=select_autoescape(['html']))
html=env.from_string('{% from "partials/resource_wizard.html" import resource_wizard %}'+source[start:end]).render(
    management_ui_root='/ui/management', csrf_token='synthetic-csrf', vsphere_vault_credential_choices=[],
    vsphere_key_providers=[{'id':'provider-1','name':'Default','enabled':True}])
try:
    _check_cluster_endpoint([{'name':'kms.example.test','address':'192.168.1.254','port':5696}], 'kms.example.test', 5696)
except EnrollmentError as exc:
    detail=str(exc)
# Synthetic admission fixture; fresh production ownership is covered separately.
_check_cluster_endpoint([{'name':'kms.example.test','address':'192.168.1.254','port':5696}],
                        'kms.example.test', 5696, listener_addresses=frozenset({'192.168.1.254'}))
print(json.dumps({'html':html,'detail':detail}))
` });
assert.equal(fixture.status, 0, fixture.stderr);
const { html, detail } = JSON.parse(fixture.stdout);
assert(detail.includes("Expected configured Atlaso endpoint: kms.example.test, port 5696"));
assert(!detail.includes("member 2"));
assert(!detail.includes("address differs"));
assert(!detail.includes("192.168.1.254"), "Remote values must not reach the browser diagnostic");

(async () => {
  const browser = await chromium.launch({ channel: "msedge", headless: true });
  try {
    for (const [label, width, height] of [["desktop", 1600, 1000], ["narrow", 900, 1200]]) {
      const page = await browser.newPage({ viewport: { width, height } });
      let attempts = 0;
      const errors = [];
      page.on("pageerror", (error) => errors.push(error.message));
      await page.route("http://atlaso.test/**", async (route) => {
        const url = route.request().url();
        if (url.endsWith("/probe")) return route.fulfill({ json: { https_fingerprint: "AA:BB:CC" } });
        if (url.endsWith("/inventory")) {
          return route.fulfill({ json: { name: "Synthetic vCenter product", cluster_ids: ["Default"] } });
        }
        if (url.endsWith("/inspect")) {
          if (++attempts === 1) return route.fulfill({ status: 422, json: { detail } });
          return route.fulfill({ json: { client_fingerprint: "11:22", subject: "Synthetic vCenter", expires_at: "2030-01-01", cluster_id: "Default" } });
        }
        return route.fulfill({ contentType: "text/html", body: `<html><body>${html}</body></html>` });
      });
      await page.goto("http://atlaso.test/");
      await page.addStyleTag({ path: path.join(root, "atlaso/app/static/app.css") });
      await page.addScriptTag({ path: path.join(root, "atlaso/app/static/ui-patterns.js") });
      await page.addScriptTag({ content: `
        const managementUiPath = path => '/ui/management' + path;
        const renderAtlasoWizardReview = () => {};
        ${functionSource("atlasoGridWizardRequest")}
        ${functionSource("initializeVsphereEnrollmentWizard")}
        const form = document.querySelector('[data-vsphere-enrollment-form]');
        window.fixtureWizard = initializeVsphereEnrollmentWizard(form, document.querySelector('dialog'));
        fixtureWizard.open({ context: {} });
      ` });
      const next = page.locator("[data-atlaso-wizard-next]");
      await next.click(); // Method
      await next.click(); // Credential
      await page.locator('[name="hostname"]').fill("vcsa.example.test");
      await next.click(); // Server probe
      await page.locator("[data-vsphere-tls-confirm]").check();
      await next.click(); // TLS
      await page.locator('[name="username"]').fill("synthetic-user");
      await page.locator('[name="password"]').fill("synthetic-password");
      await next.click(); // Login
      await page.waitForFunction(() => document.querySelector('[name="name"]').value === 'Synthetic vCenter product');
      await page.locator('[name="name"]').fill("Synthetic lab");
      await page.locator('[name="cluster_id"]').fill("Default");
      await page.locator('[name="provider_id"]').selectOption("provider-1");
      await next.click(); // Target rejection
      await page.waitForFunction((expected) => document.querySelector('[data-atlaso-wizard-error]').textContent === expected, detail).catch(async (error) => {
        console.error({ attempts, errors, status: await page.locator('[data-atlaso-wizard-error]').textContent(), title: await page.locator('[data-atlaso-wizard-title]').textContent(), invalid: await page.locator('[data-atlaso-wizard-step="target"] input, [data-atlaso-wizard-step="target"] select').evaluateAll(controls => controls.filter(control => !control.checkValidity()).map(control => control.name)) });
        throw error;
      });
      assert.equal(await page.locator('[name="cluster_id"]').inputValue(), "Default");
      assert.equal(await page.locator('[name="password"]').inputValue(), "synthetic-password");
      assert.equal(await page.locator('[name="provider_id"]').inputValue(), "provider-1");
      assert.equal(await page.locator('[name="expected_client_fingerprint"]').inputValue(), "");
      assert(await page.locator('[data-atlaso-wizard-step="target"]').isVisible());
      const bounds = await page.locator('[data-atlaso-wizard-error]').boundingBox();
      assert(bounds && bounds.x >= 0 && bounds.x + bounds.width <= width, "Diagnostic must fit the viewport");
      await page.screenshot({ path: path.join(output, `endpoint-${label}.png`) });
      await next.click(); // Fresh read after independent listener admission, simulated by second response
      await page.waitForFunction(() => document.querySelector('[name="expected_client_fingerprint"]').value === '11:22');
      assert(await page.locator('[data-atlaso-wizard-step="review"]').isVisible());
      assert.equal(attempts, 2);
      assert.deepEqual(errors, []);
      await page.close();
      console.log(`${label}: actionable rejection retained inputs; retry reached Review`);
    }
  } finally {
    await browser.close();
  }
})().catch((error) => { console.error(error); process.exitCode = 1; });
