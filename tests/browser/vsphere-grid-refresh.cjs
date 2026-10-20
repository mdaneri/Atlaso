// Production resource save/delete callbacks and vendored grids with synthetic responses.
// Wizard navigation and backend admission are outside this display regression fixture.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require("playwright");
const root = path.resolve(__dirname, "../..");
const source = fs.readFileSync(path.join(root, "atlaso/app/static/app.js"), "utf8");
const productionFunction = (name) => {
  const match = new RegExp(`(?:async )?function ${name}\\(`).exec(source);
  assert(match, `Missing ${name}`);
  return source.slice(match.index, source.indexOf("\n}", match.index) + 2);
};
const output = process.env.ATLASO_BROWSER_OUTPUT;
assert(output && path.isAbsolute(output), "Use an originally receipted task output root");
const functions = ["escapeHtml", "atlasoBooleanFormatter", "newRecordRequiredValue", "markNewRecordRow",
  "initializeAtlasoResourceWizard", "syncVsphereProviderSelect", "updateVsphereGridCounts",
  "updateVsphereProviderTrustCount", "reformatVsphereProviderCells", "syncVsphereEnrollmentResult",
  "initializeVsphereKeyProviderTables"];

(async () => {
  const browser = await chromium.launch({ channel: "msedge", headless: true });
  try {
    const errors = [];
    const results = [];
    for (const [label, width, height] of [["desktop", 1600, 1000], ["narrow", 900, 1200]]) {
      const page = await browser.newPage();
      page.on("pageerror", (error) => { errors.push(error.message); console.error(error.message); });
      console.log(`Checking ${label}`);
      await page.setViewportSize({ width, height });
      await page.setContent(`<html><body>
        <h2>Providers <span data-vsphere-count="providers">1 providers</span></h2>
        <div id="vsphere-providers-table"></div>
        <h2>Trusted vCenters <span data-vsphere-count="vcenters">24 vCenters</span></h2>
        <div id="vsphere-vcenters-table"></div>
        <dialog id="vsphere-provider-dialog"><form data-vsphere-provider-form>
          <input name="record_id"><input name="name"><input name="description">
        </form></dialog>
        <dialog id="vsphere-vcenter-dialog"><form data-vsphere-vcenter-form>
          <input name="record_id"><input name="name"><select name="provider_id"></select>
        </form></dialog>
        <form data-vsphere-certificate-form><select name="target"><option value="p1|v1">Old provider / Center 01</option></select></form>
        </body></html>`);
      await page.addStyleTag({ path: path.join(root, "atlaso/app/static/vendor/tabulator/tabulator.min.css") });
      await page.addStyleTag({ path: path.join(root, "atlaso/app/static/app.css") });
      await page.addScriptTag({ path: path.join(root, "atlaso/app/static/vendor/tabulator/tabulator.min.js") });
      await page.addScriptTag({ path: path.join(root, "atlaso/app/static/ui-patterns.js") });
      await page.addScriptTag({ content: `
        window.fixture = { grids: {}, wizards: {}, response: null, requests: [] };
        let vsphereEnrollmentWizard = null;
        const createGrid = AtlasoUiPatterns.createGrid;
        window.AtlasoUiPatterns = { ...AtlasoUiPatterns };
        AtlasoUiPatterns.createGrid = (config) => {
          const id = config.element.id;
          const grid = createGrid(config);
          fixture.grids[id] = { ...grid, actions: config.rowActions };
          return grid;
        };
        AtlasoUiPatterns.createWizard = (config) => {
          fixture.wizards[config.form.hasAttribute('data-vsphere-provider-form') ? 'provider' : 'vcenter'] = config;
          return { open() {} };
        };
        const managementUiPath = (url) => url;
        const requestConfirmation = async () => true;
        const atlasoGridWizardRequest = async (url) => {
          fixture.requests.push(url);
          if (fixture.fail) throw new Error('Synthetic rejected mutation');
          return fixture.response;
        };
        const showTransientGridStatus = () => {};
        ${functions.map(productionFunction).join("\n")}
        const provider = { id: 'p1', name: 'Old provider', trusted_vcenter_count: 24, enabled: false };
        document.getElementById('vsphere-providers-table').dataset.providers = JSON.stringify([provider]);
        document.getElementById('vsphere-vcenters-table').dataset.vcenters = JSON.stringify(
          Array.from({length:24}, (_, i) => ({ id: 'v' + (i+1), provider_id:'p1',
            provider_name:'Old provider', name:'Center ' + String(i+1).padStart(2,'0'), enabled:false })));
        initializeVsphereKeyProviderTables();
      ` });
      await page.waitForFunction(() => document.querySelectorAll("#vsphere-vcenters-table .tabulator-row").length > 1);
      console.log("Grids rendered");
      const result = await page.evaluate(async () => {
        const providers = fixture.grids['vsphere-providers-table'].table;
        const vcenters = fixture.grids['vsphere-vcenters-table'].table;
        const badge = (name) => document.querySelector('[data-vsphere-count="' + name + '"]').textContent;
        const tick = () => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
        vcenters.setSort('name', 'desc');
        vcenters.setFilter('name', 'like', 'Center');
        vcenters.selectRow('v1');
        const holder = document.querySelector('#vsphere-vcenters-table .tabulator-tableholder');
        holder.scrollTop = 100;
        holder.scrollLeft = 50;
        await tick();
        const before = { scrollTop: holder.scrollTop, scrollLeft: holder.scrollLeft,
          sorts: vcenters.getSorters().map(({field,dir})=>({field,dir})), filters: vcenters.getFilters(),
          selected: vcenters.getSelectedData().map(row=>row.id) };
        const providerForm = document.querySelector('[data-vsphere-provider-form]');
        providerForm.elements.record_id.value = 'p1';
        fixture.response = { provider: {...providers.getRow('p1').getData(), name:'Renamed provider'} };
        await fixture.wizards.provider.onSubmit();
        await tick();
        const visibleNames = [...document.querySelectorAll('#vsphere-vcenters-table .tabulator-cell[tabulator-field="provider_id"]')]
          .filter(cell => cell.closest('.tabulator-row').getAttribute('data-is-new') !== 'true')
          .map(cell=>cell.textContent).filter(Boolean);
        const after = { scrollTop: holder.scrollTop, scrollLeft: holder.scrollLeft,
          sorts: vcenters.getSorters().map(({field,dir})=>({field,dir})), filters: vcenters.getFilters(),
          selected: vcenters.getSelectedData().map(row=>row.id) };
        const option = document.querySelector('[data-vsphere-certificate-form] option').textContent;
        const selector = document.querySelector('[data-vsphere-vcenter-form] option').textContent;
        const initialBadges = [badge('providers'), badge('vcenters')];
        providerForm.elements.record_id.value = '';
        fixture.response = {provider: {id:'p2', name:'Disposable provider', enabled:false}};
        await fixture.wizards.provider.onSubmit();
        const createdProvider = badge('providers');
        await fixture.grids['vsphere-providers-table'].actions.find(a=>a.label==='Delete provider').action(null, providers.getRow('p2'));
        const deletedProvider = badge('providers');
        const vcenterForm = document.querySelector('[data-vsphere-vcenter-form]');
        fixture.response = {trusted_vcenter:{id:'v25', provider_id:'p1', provider_name:'Renamed provider', name:'Center 25'}};
        await fixture.wizards.vcenter.onSubmit();
        const createdVcenter = [badge('vcenters'), providers.getRow('p1').getData().trusted_vcenter_count];
        fixture.fail = true;
        await fixture.grids['vsphere-vcenters-table'].actions.find(a=>a.label==='Delete trusted vCenter').action(null, vcenters.getRow('v25'));
        const rejectedDelete = [badge('vcenters'), Boolean(vcenters.getRow('v25'))];
        fixture.fail = false;
        await fixture.grids['vsphere-vcenters-table'].actions.find(a=>a.label==='Delete trusted vCenter').action(null, vcenters.getRow('v25'));
        const deletedVcenter = [badge('vcenters'), providers.getRow('p1').getData().trusted_vcenter_count];
        return {before, after, visibleNames, option, selector, initialBadges, createdProvider, deletedProvider,
          createdVcenter, rejectedDelete, deletedVcenter, addRows:vcenters.getData().filter(row=>row.is_new).length};
      });
      assert.deepEqual(result.after, result.before, "Rename must preserve grid context");
      assert(result.visibleNames.length > 0);
      assert(result.visibleNames.every(name => name === "Renamed provider"));
      assert.equal(result.option, "Renamed provider / Center 01");
      assert.equal(result.selector, "Renamed provider");
      assert.deepEqual(result.initialBadges, ["1 providers", "24 vCenters"]);
      assert.equal(result.createdProvider, "2 providers");
      assert.equal(result.deletedProvider, "1 providers");
      assert.deepEqual(result.createdVcenter, ["25 vCenters", 25]);
      assert.deepEqual(result.rejectedDelete, ["25 vCenters", true]);
      assert.deepEqual(result.deletedVcenter, ["24 vCenters", 24]);
      assert.equal(result.addRows, 1);
      results.push({label, ...result});
      await page.screenshot({path:path.join(output, `vsphere-refresh-${label}.png`)});
      await page.close();
    }
    assert.deepEqual(errors, []);
    fs.writeFileSync(path.join(output, "vsphere-refresh-results.json"), JSON.stringify(results, null, 2));
    console.log("vSphere rendered save/delete regression passed at desktop and narrow viewports");
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
