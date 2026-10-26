const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "../../atlaso/app/static/vcf-certificate-renewal.js"), "utf8");

test("wizard step order matches credential, server, TLS and target, health, policy flows", () => {
  const connection = source.slice(source.indexOf("const connectionWizard"), source.indexOf("function invalidateFingerprint"));
  const connectionSteps = [...connection.matchAll(/\{ id: "([^"]+)"/g)].map((match) => match[1]);
  assert.deepEqual(connectionSteps, ["credential", "server", "fingerprint"]);
  const policy = source.slice(source.indexOf("const policyWizard"), source.indexOf("function openPolicy"));
  const policySteps = [...policy.matchAll(/\{ id: "([^"]+)"/g)].map((match) => match[1]);
  assert.deepEqual(policySteps, ["target", "target-health", "policy"]);
  const fingerprintInvalidation = source.slice(source.indexOf("function invalidateFingerprint"), source.indexOf("connectProbe?.addEventListener"));
  assert.match(fingerprintInvalidation, /credential_vault_id/);
  assert.match(fingerprintInvalidation, /credential_entry_id/);
});

function element() {
  const classes = new Set();
  return {
    dataset: {},
    classList: {
      add: (name) => classes.add(name),
      remove: (name) => classes.delete(name),
      toggle: (name, force) => force === undefined ? (classes.has(name) ? classes.delete(name) : classes.add(name)) : (force ? classes.add(name) : classes.delete(name)),
      contains: (name) => classes.has(name),
    },
    attributes: {},
    setAttribute(name, value) { this.attributes[name] = value; },
    removeAttribute(name) { delete this.attributes[name]; },
    events: {},
    addEventListener(name, handler) { this.events[name] = handler; },
    append(item) { (this.children ||= []).push(item); },
    replaceChildren() { this.children = []; },
  };
}

function createHarness({ admin = true, connection = false, fetchImpl = async () => ({ ok: true, json: async () => ({}) }) } = {}) {
  const root = element();
  root.dataset = { admin: String(admin), endpoint: "/ui/management/vcf-helper/certificate-renewals", csrf: "csrf-test", tasksRoot: "/ui/management/tasks" };
  const status = element();
  const link = element();
  const panel = element();
  panel.hidden = true;
  const gridElement = element();
  const reconfirmSelect = element();
  const reconfirmOpen = element();
  const fields = Object.fromEntries(["connection_id", "name", "address", "port", "credential_vault_id", "credential_entry_id", "confirm_fingerprint"].map((name) => [name, { ...element(), value: "", checked: false }]));
  const form = { ...element(), elements: { namedItem: (name) => fields[name] }, querySelector: () => null };
  const fingerprint = element();
  const probe = element();
  const explanation = element();
  const dialog = { ...element(), querySelector: (selector) => selector.includes("connection-form") ? form : selector.includes("fingerprint") ? fingerprint : selector.includes("probe") ? probe : selector.includes("reconfirm-context") ? explanation : null };
  let wizardConfig;
  let wizard;
  let gridConfig;
  const grid = { table: { setData(rows) { this.rows = rows; } }, setError(message) { this.error = message; }, setState() { status.classList.add("hidden"); } };
  const document = {
    visibilityState: "visible",
    querySelector: () => root,
    getElementById(id) {
      if (id === "vcf-helper-certificates") return panel;
      if (id === "vcf-renewal-grid") return gridElement;
      if (id === "vcf-renewal-connection-dialog" && connection) return dialog;
      return null;
    },
    createElement: () => element(),
    addEventListener() {},
  };
  const window = {
    AtlasoUiPatterns: { createGrid(config) { gridConfig = config; return grid; }, createWizard(config) {
      wizardConfig = config;
      wizard = { open: async (options = {}) => { config.onOpen?.(options); }, reset() {}, setError() {} };
      return wizard;
    } },
    setTimeout: () => 1,
    clearTimeout() {},
  };
  root.querySelector = (selector) => selector.includes("message") ? status : selector.includes("task") ? link : connection && selector.includes("reconfirm-select") ? reconfirmSelect : connection && selector.includes("reconfirm-open") ? reconfirmOpen : null;
  const context = vm.createContext({ document, window, fetch: fetchImpl, encodeURIComponent, JSON, String, Boolean, Number, Map, Array, Error });
  vm.runInContext(source, context);
  return { context, gridConfig, status, link, grid, wizardConfig, wizard, fields, probe, reconfirmSelect, reconfirmOpen, explanation };
}

test("non-admin browser state never initializes the renewal grid", () => {
  const harness = createHarness({ admin: false });
  assert.equal(harness.gridConfig, undefined);
});

test("renewal inventory formatters put remote strings in text nodes", () => {
  const { gridConfig } = createHarness();
  const target = gridConfig.options.columns.find((column) => column.field === "host");
  const hostile = "<img src=x onerror=alert(1)>";
  const rendered = target.formatter({ getValue: () => hostile });
  assert.equal(rendered.textContent, hostile);
});

test("read-only row actions enforce policy state and send only the saved policy reference", async () => {
  const calls = [];
  const { gridConfig, status, link } = createHarness({ fetchImpl: async (url, options = {}) => {
    calls.push({ url, options });
    return { ok: true, json: async () => url.endsWith("/state") ? { connections: [], profiles: [], inventory: [], policies: [] } : { job_id: "task-42", message: "Check queued." } };
  } });
  const check = gridConfig.rowActions.find((action) => action.label === "Check now");
  const prepare = gridConfig.rowActions.find((action) => action.label === "Prepare renewal");
  assert.equal(check.disabled({ getData: () => ({ policy_id: "" }) }), true);
  assert.equal(prepare.disabled({ getData: () => ({ policy_id: "p1", enabled: false, eligible: true }) }), true);
  await check.action(null, { getData: () => ({ policy_id: "policy-7" }) });
  assert.equal(calls[0].url, "/ui/management/vcf-helper/certificate-renewals/check");
  assert.equal(calls[0].options.headers["X-CSRF-Token"], "csrf-test");
  assert.deepEqual(JSON.parse(calls[0].options.body), { policy_id: "policy-7" });
  assert.equal(link.href, "/ui/management/tasks?job_id=task-42");
  assert.equal(status.textContent, "Connect a VCF Operations endpoint to load certificate inventory.");
  assert.equal(status.classList.contains("hidden"), false);
});

test("renewal action failures remain visible and do not issue a follow-up mutation", async () => {
  const calls = [];
  const { gridConfig, status } = createHarness({ fetchImpl: async (url) => {
    calls.push(url);
    return { ok: false, status: 422, json: async () => ({ detail: "Renewal prerequisites are unavailable." }) };
  } });
  status.classList.add("hidden");
  await gridConfig.rowActions.find((action) => action.label === "Check now").action(null, {getData: () => ({policy_id:"p1",enabled:true})});
  assert.equal(calls.length, 1);
  assert.equal(status.textContent, "Renewal prerequisites are unavailable.");
  assert.equal(status.attributes.role, "alert");
  assert.equal(status.classList.contains("hidden"), false);
});

test("disabling enrollment needs only its saved policy and remains guarded during native work", async () => {
  const calls = [];
  const { gridConfig } = createHarness({fetchImpl: async (url, options = {}) => {
    calls.push({url, options});
    return {ok:true, json:async () => url.endsWith("/state") ? {connections:[],profiles:[],inventory:[],policies:[]} : {policy_id:"policy-7"}};
  }});
  const disable = gridConfig.rowActions.find((action) => action.label === "Disable enrollment");
  assert.equal(disable.disabled({getData:() => ({policy_id:"p",enabled:true,proposal_state:"proposal"})}), false);
  assert.equal(disable.disabled({getData:() => ({policy_id:"p",enabled:true,proposal_state:"prepared"})}), true);
  assert.equal(disable.disabled({getData:() => ({policy_id:"p",enabled:false,proposal_state:"not_due"})}), true);
  await disable.action(null, {getData:() => ({policy_id:"policy-7",enabled:true,proposal_state:"not_due"})});
  assert.equal(calls[0].url, "/ui/management/vcf-helper/certificate-renewals/save_policy");
  assert.deepEqual(JSON.parse(calls[0].options.body), {policy_id:"policy-7",enabled:false});
  assert.equal(calls[0].options.headers["X-CSRF-Token"], "csrf-test");
  assert.equal(calls.length, 2);
  assert.ok(calls[1].url.endsWith("/state"));
});

test("reconfirming a saved connection requires a fresh fingerprint and retains its identity", async () => {
  const calls = [];
  const harness = createHarness({connection:true, fetchImpl:async (url, options = {}) => {
    calls.push({url,options});
    return {ok:true,json:async () => url.endsWith("/state") ? {connections:[{id:"connection-1",name:"Saved Operations",address:"operations.example.test",port:443}],inventory:[],policies:[],profiles:[]} : url.endsWith("/probe") ? {fingerprint:"a".repeat(64)} : {connection_id:"connection-1"}};
  }});
  await harness.gridConfig.rowActions.find((a) => a.label === "Check now").action(null,{getData:() => ({policy_id:"p"})});
  assert.equal(harness.reconfirmSelect.value,"connection-1");
  assert.equal(harness.reconfirmOpen.disabled,false);
  harness.reconfirmOpen.events.click({currentTarget:harness.reconfirmOpen});
  assert.equal(harness.fields.connection_id.value,"connection-1");
  assert.match(harness.explanation.textContent,/operations.example.test:443/);
  assert.equal(harness.wizardConfig.validateStep({step:{id:"fingerprint"}}).valid,false);
  harness.fields.address.value="operations.example.test";
  harness.fields.port.value="443";
  harness.fields.credential_vault_id.value="v1";
  harness.fields.credential_entry_id.value="e1";
  await harness.probe.events.click();
  assert.equal(harness.wizardConfig.validateStep({step:{id:"fingerprint"}}).valid,false);
  harness.fields.confirm_fingerprint.checked=true;
  assert.equal(harness.wizardConfig.validateStep({step:{id:"fingerprint"}}),true);
  await harness.wizardConfig.onSubmit();
  const saved=calls.find((c) => c.url.endsWith("/save_connection"));
  const body=JSON.parse(saved.options.body);
  assert.equal(body.connection_id,"connection-1");
  assert.equal(body.confirm_connection_update,true);
  assert.equal(body.confirmed_tls_fingerprint,"a".repeat(64));
  assert.equal(saved.options.headers["X-CSRF-Token"],"csrf-test");
  assert.equal(calls.some((c) => c.url.endsWith("/inventory")),false);
  await harness.wizard.open({});
  assert.equal(harness.fields.connection_id.value,"");
  assert.equal(harness.fields.confirm_fingerprint.checked,false);
});
