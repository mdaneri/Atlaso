// Exercise real CA templates, controllers, and local desired-state saves only.
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
      const knownGridErrors = [];
      const submissions = [];
      page.on("pageerror", (error) => {
        // #1040 is reproduced on unchanged main. Fail on every other error.
        if (error.message === "Cannot read properties of null (reading 'getBoundingClientRect')"
          && error.stack.includes("adjustTableSize") && error.stack.includes("at resize (")) knownGridErrors.push(error.message);
        else errors.push(error.stack);
      });
      page.on("request", (request) => {
        if (request.method() === "POST" && /\/certificate-authority\/certificates(?:\/\d+\/edit)?$/.test(request.url())) submissions.push(request);
      });
      await page.goto(`${url}/ui/management/certificate-authority`);
      await page.waitForFunction(() => document.getElementById("ca-certificates-table")?.atlasoWizard);
      const dialog = page.locator("#ca-certificate-dialog");
      const field = dialog.locator('[name="ip_addresses"]');
      const feedback = dialog.locator("[data-ca-ip-san-error]");
      const step = (id) => dialog.locator(`[data-atlaso-wizard-step="${id}"]`).waitFor({ state: "visible" });
      const next = () => dialog.locator("[data-atlaso-wizard-next]").click();
      const open = (context) => page.evaluate((record) => document.getElementById("ca-certificates-table").atlasoWizard.open({ context: record }), context);
      const close = () => page.evaluate(() => document.getElementById("ca-certificates-table").atlasoWizard.close("cancel"));
      const assertRejected = async (value) => {
        await field.fill(value);
        await next();
        await feedback.filter({ hasText: "Enter a valid" }).waitFor();
        await step("names");
        assert.equal(await field.inputValue(), value);
        assert.equal(await field.getAttribute("aria-invalid"), "true");
        assert.equal(await field.evaluate((control) => document.activeElement === control), true);
        assert.equal(await field.getAttribute("aria-describedby"), await feedback.getAttribute("id"));
        assert.equal(await feedback.getAttribute("aria-live"), "polite");
      };

      // Use the keyboard to launch the production grid's create wizard.
      const launcher = page.getByRole("button", { name: "+ Add certificate here", exact: true });
      if (label === "desktop") {
        await launcher.focus();
        await page.keyboard.press("Enter");
      } else {
        await launcher.click();
      }
      await step("identity");
      await dialog.locator('[name="common_name"]').fill(`ip-sans-${label}.example.test`);
      await next();
      await step("names");
      for (const value of ["192.0.2.999", "2001:db8:::1", "192.0.2.1\n2001:db8:::1", "192.0.2.01", "::1]/path"]) await assertRejected(value);
      assert.equal(submissions.length, 0);
      await dialog.screenshot({ path: path.join(output, `ca-ip-sans-${label}.png`) });
      // Closing and reopening clears previous feedback without erasing a new context.
      await close();
      await open();
      assert.equal(await feedback.textContent(), "");
      await dialog.locator('[name="common_name"]').fill(`ip-sans-${label}.example.test`);
      await next();
      await step("names");
      const valid = "0.0.0.0, 255.255.255.255\n::\nffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\n::ffff:192.0.2.10";
      await field.fill(valid);
      assert.equal(await feedback.textContent(), "");
      assert.notEqual(await field.getAttribute("aria-invalid"), "true");
      await next();
      await step("enablement");
      await next();
      await step("review");
      // A changed hidden field still must be revalidated at submission.
      await field.evaluate((control) => { control.value = "2001:db8:::1"; });
      await dialog.locator("[data-atlaso-wizard-submit]").click();
      await step("names");
      assert.equal(await field.evaluate((control) => document.activeElement === control), true);
      assert.equal(submissions.length, 0);
      await field.fill(valid);
      await next();
      await step("enablement");
      await next();
      await step("review");
      const savedResponse = page.waitForResponse((response) => response.request().method() === "POST" && response.url().endsWith("/certificate-authority/certificates"));
      await dialog.locator("[data-atlaso-wizard-submit]").click();
      const response = await savedResponse;
      assert.equal(response.status(), 200);
      const saved = (await response.json()).certificate;
      await dialog.waitFor({ state: "hidden" });
      assert.equal(submissions.length, 1);

      // Edit retains all values after rejection and supports clearing optional IP SANs.
      await open(saved);
      await next();
      await step("names");
      await assertRejected("192.0.2.10,2001:db8:::1");
      await field.fill("");
      assert.equal(await feedback.textContent(), "");
      await dialog.locator('[name="subject_alt_names"]').fill(saved.common_name);
      await next();
      await step("enablement");
      await next();
      await step("review");
      await field.evaluate((control) => { control.value = "192.0.2.999"; });
      await dialog.locator("[data-atlaso-wizard-submit]").click();
      await step("names");
      assert.equal(submissions.length, 1);
      await field.fill("");
      await next();
      await step("enablement");
      await next();
      await step("review");
      const editedResponse = page.waitForResponse((result) => result.request().method() === "POST" && result.url().endsWith(`/certificates/${saved.id}/edit`));
      await dialog.locator("[data-atlaso-wizard-submit]").click();
      const edited = await editedResponse;
      assert.equal(edited.status(), 200);
      assert.equal((await edited.json()).certificate.ip_addresses, "");
      await dialog.waitFor({ state: "hidden" });

      assert.deepEqual(errors, []);
      // CSR intake uses the same Names validation before any CSR can be staged.
      await page.getByRole("tab", { name: "CSR Intake", exact: true }).click();
      await page.locator("[data-ca-csr-open]").click();
      const csr = page.locator("#ca-csr-dialog");
      await csr.locator('[name="common_name"]').fill("csr-ip-sans.example.test");
      await csr.locator("[data-atlaso-wizard-next]").click();
      await csr.locator('[data-atlaso-wizard-step="names"]').waitFor({ state: "visible" });
      await csr.locator('[name="ip_addresses"]').fill("2001:db8:::1");
      await csr.locator("[data-atlaso-wizard-next]").click();
      await csr.locator("[data-ca-ip-san-error]").filter({ hasText: "2001:db8:::1" }).waitFor();
      assert.equal(await csr.locator('[name="ip_addresses"]').evaluate((control) => document.activeElement === control), true);
      await csr.locator('[name="ip_addresses"]').fill("2001:db8::1");
      await csr.locator("[data-atlaso-wizard-next]").click();
      await csr.locator('[data-atlaso-wizard-step="csr"]').waitFor({ state: "visible" });
      assert.deepEqual(errors, []);
      console.log(`${label}: create/edit, final-submit recheck, feedback recovery, ${label === "desktop" ? "keyboard" : "pointer"} launch, CSR Names passed`);
      if (knownGridErrors.length) console.log(`${label}: observed ${knownGridErrors.length} existing CA grid resize exception(s), tracked in #1040`);
      await page.close();
    }
  } finally {
    await browser.close();
  }
})().catch((error) => { console.error(error); process.exitCode = 1; });
