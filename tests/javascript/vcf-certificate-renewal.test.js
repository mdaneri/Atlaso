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

function createHarness({ admin = true, connection = false, health = false, fetchImpl = async () => ({ ok: true, json: async () => ({}) }) } = {}) {
  const root = element();
  root.dataset = { admin: String(admin), endpoint: "/ui/management/vcf-helper/certificate-renewals", csrf: "csrf-test", tasksRoot: "/ui/management/tasks" };
  const status = element();
  const link = element();
  const panel = element();
  panel.hidden = true;
  const gridElement = element();
  const reconfirmSelect = element();
  const reconfirmOpen = element();
  const fields = Object.fromEntries(["connection_id", "name", "address", "port", "credential_vault_id", "credential_entry_id", "confirm_fingerprint", "policy_id", "health_credential_vault_id", "health_credential_entry_id", "confirm_health_fingerprint", "approve_replacement"].map((name) => [name, { ...element(), value: "", checked: false }]));
  const form = { ...element(), elements: { namedItem: (name) => fields[name] }, querySelector: () => null };
  const reviewSummary = element();
  const reviewError = element();
  reviewError.classList.add("hidden");
  const reviewForm = { ...element(), elements: { namedItem: (name) => fields[name] }, querySelector: (selector) => selector.includes("dialog-error") ? reviewError : selector.includes("approve_replacement") ? fields.approve_replacement : selector === "[type='submit']" ? reviewApprove : null, reset() { fields.approve_replacement.checked = false; } };
  const reviewApprove = { ...element(), disabled: true };
  const reviewDialog = { ...element(), open: false, querySelectorAll: () => [], querySelector: (selector) => selector.includes("review-form") ? reviewForm : selector.includes("review-summary") ? reviewSummary : null, showModal() { this.open = true; }, close() { this.open = false; this.events.close?.(); } };
  const fingerprint = element();
  const probe = element();
  const explanation = element();
  const dialog = { ...element(), querySelector: (selector) => selector.includes("connection-form") || selector.includes("health-form") ? form : selector.includes("health-host") ? explanation : selector.includes("fingerprint") ? fingerprint : selector.includes("probe") ? probe : selector.includes("reconfirm-context") ? explanation : null };
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
      if (id === "vcf-renewal-health-dialog" && health) return dialog;
      if (id === "vcf-renewal-review-dialog") return reviewDialog;
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
  return { context, gridConfig, status, link, grid, wizardConfig, wizard, fields, probe, reconfirmSelect, reconfirmOpen, explanation, reviewDialog, reviewForm, reviewApprove, reviewSummary, reviewError };
}

const tick = () => new Promise((resolve) => setImmediate(resolve));

test("review approval readiness follows the current checkbox and exact review token in either order", async () => {
  let resolveReview;
  const harness = createHarness({ fetchImpl: (url) => url.endsWith("/review") ? new Promise((resolve) => { resolveReview = resolve; }) : Promise.resolve({ ok: true, json: async () => ({}) }) });
  const open = harness.gridConfig.rowActions.find((action) => action.label === "Review replacement").action;
  open(null, { getData: () => ({ operation_id: "operation-1", proposal_state: "prepared" }) });
  assert.equal(harness.reviewApprove.disabled, true);
  harness.fields.approve_replacement.checked = true;
  harness.fields.approve_replacement.events.change({ target: harness.fields.approve_replacement });
  assert.equal(harness.reviewApprove.disabled, true);
  resolveReview({ ok: true, json: async () => ({ review_token: "review-token-1", summary: { target: "vc.example.test" } }) });
  await tick();
  assert.equal(harness.reviewApprove.disabled, false);
  assert.match(harness.reviewSummary.textContent, /vc\.example\.test/);

  harness.reviewDialog.close();
  open(null, { getData: () => ({ operation_id: "operation-2", proposal_state: "prepared" }) });
  resolveReview({ ok: true, json: async () => ({ review_token: "review-token-2", summary: "Second exact review" }) });
  await tick();
  assert.equal(harness.reviewApprove.disabled, true);
  harness.fields.approve_replacement.checked = true;
  harness.fields.approve_replacement.events.change({ target: harness.fields.approve_replacement });
  assert.equal(harness.reviewApprove.disabled, false);
});

test("an invalid review response stays closed to approval and reports failure", async () => {
  const harness = createHarness({ fetchImpl: async (url) => url.endsWith("/review") ? ({ ok: true, json: async () => ({ summary: "Exact details, but no token" }) }) : ({ ok: true, json: async () => ({}) }) });
  harness.gridConfig.rowActions.find((action) => action.label === "Review replacement").action(null, { getData: () => ({ operation_id: "operation-1" }) });
  harness.fields.approve_replacement.checked = true;
  harness.fields.approve_replacement.events.change();
  await tick();
  assert.equal(harness.reviewApprove.disabled, true);
  assert.equal(harness.reviewSummary.textContent, "Review details could not be loaded.");
  assert.match(harness.reviewError.textContent, /approval token/);
});

test("review request failures and malformed tokens stay disabled and clear when a fresh review opens", async () => {
  for (const response of [
    { ok: false, status: 503, json: async () => ({ detail: "Review service unavailable." }) },
    { ok: true, json: async () => ({ review_token: { value: "not-a-token" }, summary: "Malformed token" }) },
    { ok: true, json: async () => ({ review_token: "   ", summary: "Blank token" }) },
  ]) {
    const harness = createHarness({ fetchImpl: async (url) => url.endsWith("/review") ? response : ({ ok: true, json: async () => ({}) }) });
    const open = harness.gridConfig.rowActions.find((action) => action.label === "Review replacement").action;
    open(null, { getData: () => ({ operation_id: "operation-1" }) });
    harness.fields.approve_replacement.checked = true;
    harness.fields.approve_replacement.events.change();
    await tick();
    assert.equal(harness.reviewApprove.disabled, true);
    assert.equal(harness.reviewError.classList.contains("hidden"), false);
    open(null, { getData: () => ({ operation_id: "operation-2" }) });
    assert.equal(harness.reviewError.textContent, "");
    assert.equal(harness.reviewError.classList.contains("hidden"), true);
    assert.equal(harness.fields.approve_replacement.checked, false);
    assert.equal(harness.reviewApprove.disabled, true);
  }
});

test("an execute failure consumes the token and checkbox toggles cannot retry it", async () => {
  const calls = [];
  const harness = createHarness({ fetchImpl: async (url, options = {}) => {
    if (url.endsWith("/review")) return { ok: true, json: async () => ({ review_token: "one-use-token", summary: "Exact review" }) };
    if (url.endsWith("/execute")) {
      calls.push(JSON.parse(options.body));
      return { ok: false, status: 409, json: async () => ({ detail: "Approval expired." }) };
    }
    return { ok: true, json: async () => ({}) };
  } });
  const open = harness.gridConfig.rowActions.find((action) => action.label === "Review replacement").action;
  open(null, { getData: () => ({ operation_id: "operation-1" }) });
  await tick();
  harness.fields.approve_replacement.checked = true;
  harness.fields.approve_replacement.events.change();
  await harness.reviewForm.events.submit({ preventDefault() {} });
  assert.equal(calls.length, 1);
  assert.equal(harness.reviewApprove.disabled, true);
  assert.match(harness.reviewError.textContent, /Approval expired/);
  harness.fields.approve_replacement.checked = false;
  harness.fields.approve_replacement.events.change();
  harness.fields.approve_replacement.checked = true;
  harness.fields.approve_replacement.events.change();
  await harness.reviewForm.events.submit({ preventDefault() {} });
  assert.equal(calls.length, 1);
  assert.equal(harness.reviewApprove.disabled, true);

  harness.reviewDialog.close();
  assert.equal(harness.reviewApprove.disabled, true);
  open(null, { getData: () => ({ operation_id: "operation-2" }) });
  assert.equal(harness.reviewApprove.disabled, true);
  assert.equal(harness.fields.approve_replacement.checked, false);
});

test("closing and reopening invalidates a delayed review response", async () => {
  let resolveOld;
  let resolveCurrent;
  const harness = createHarness({ fetchImpl: (url, options) => url.endsWith("/review") ? new Promise((resolve) => {
    if (JSON.parse(options.body).operation_id === "old") resolveOld = resolve;
    else resolveCurrent = resolve;
  }) : Promise.resolve({ ok: true, json: async () => ({}) }) });
  const open = harness.gridConfig.rowActions.find((action) => action.label === "Review replacement").action;
  open(null, { getData: () => ({ operation_id: "old" }) });
  harness.reviewDialog.close();
  open(null, { getData: () => ({ operation_id: "current" }) });
  resolveOld({ ok: true, json: async () => ({ review_token: "stale", summary: "Stale summary" }) });
  await tick();
  assert.equal(harness.reviewApprove.disabled, true);
  assert.equal(harness.reviewSummary.textContent, "Loading exact replacement details…");
  harness.fields.approve_replacement.checked = true;
  harness.fields.approve_replacement.events.change();
  resolveCurrent({ ok: true, json: async () => ({ review_token: "current-token", summary: "Current summary" }) });
  await tick();
  assert.equal(harness.reviewApprove.disabled, false);
  assert.equal(harness.reviewSummary.textContent, "Current summary");
});

test("a rejected stale review cannot replace the current review state", async () => {
  let rejectOld;
  let resolveCurrent;
  const harness = createHarness({ fetchImpl: (url, options) => url.endsWith("/review") ? new Promise((resolve, reject) => {
    if (JSON.parse(options.body).operation_id === "old") rejectOld = reject;
    else resolveCurrent = resolve;
  }) : Promise.resolve({ ok: true, json: async () => ({}) }) });
  const open = harness.gridConfig.rowActions.find((action) => action.label === "Review replacement").action;
  open(null, { getData: () => ({ operation_id: "old" }) });
  open(null, { getData: () => ({ operation_id: "current" }) });
  resolveCurrent({ ok: true, json: async () => ({ review_token: "current-token", summary: "Current summary" }) });
  await tick();
  rejectOld(new Error("stale failure"));
  await tick();
  harness.fields.approve_replacement.checked = true;
  harness.fields.approve_replacement.events.change();
  assert.equal(harness.reviewApprove.disabled, false);
  assert.equal(harness.reviewSummary.textContent, "Current summary");
  assert.equal(harness.reviewError.classList.contains("hidden"), true);
});

test("execution requires the explicit checkbox, submits the current exact token once and clears it on completion", async () => {
  const calls = [];
  let resolveExecute;
  const harness = createHarness({ fetchImpl: (url, options = {}) => {
    if (url.endsWith("/review")) return Promise.resolve({ ok: true, json: async () => ({ review_token: "current-token", summary: "Current summary" }) });
    if (url.endsWith("/execute")) {
      calls.push(JSON.parse(options.body));
      return new Promise((resolve) => { resolveExecute = resolve; });
    }
    return Promise.resolve({ ok: true, json: async () => ({}) });
  } });
  harness.gridConfig.rowActions.find((action) => action.label === "Review replacement").action(null, { getData: () => ({ operation_id: "operation-1" }) });
  await tick();
  const submit = () => harness.reviewForm.events.submit({ preventDefault() {} });
  await submit();
  assert.equal(calls.length, 0);
  harness.fields.approve_replacement.checked = true;
  harness.fields.approve_replacement.events.change();
  const pending = submit();
  assert.deepEqual(calls, [{ operation_id: "operation-1", review_token: "current-token" }]);
  assert.equal(harness.reviewApprove.disabled, true);
  await submit();
  assert.equal(calls.length, 1);
  resolveExecute({ ok: true, json: async () => ({ job_id: "job-1" }) });
  await pending;
  assert.equal(harness.reviewDialog.open, false);
  assert.equal(harness.reviewApprove.disabled, true);
  assert.equal(harness.link.href, "/ui/management/tasks?job_id=job-1");
});

test("stale execution success or failure cannot alter a reopened review", async () => {
  for (const outcome of ["success", "failure"]) {
    let reviewCount = 0;
    let finishExecute;
    const harness = createHarness({ fetchImpl: (url) => {
      if (url.endsWith("/review")) {
        reviewCount += 1;
        const number = reviewCount;
        return Promise.resolve({ ok: true, json: async () => ({ review_token: `token-${number}`, summary: `summary-${number}` }) });
      }
      if (url.endsWith("/execute")) return new Promise((resolve, reject) => { finishExecute = outcome === "success" ? resolve : reject; });
      return Promise.resolve({ ok: true, json: async () => ({}) });
    } });
    const open = harness.gridConfig.rowActions.find((action) => action.label === "Review replacement").action;
    open(null, { getData: () => ({ operation_id: "operation-1" }) });
    await tick();
    harness.fields.approve_replacement.checked = true;
    harness.fields.approve_replacement.events.change();
    const submit = harness.reviewForm.events.submit({ preventDefault() {} });
    harness.reviewDialog.close();
    open(null, { getData: () => ({ operation_id: "operation-2" }) });
    await tick();
    harness.fields.approve_replacement.checked = true;
    harness.fields.approve_replacement.events.change();
    if (outcome === "success") finishExecute({ ok: true, json: async () => ({ job_id: "stale-job" }) });
    else finishExecute(new Error("stale execution failure"));
    await submit;
    assert.equal(harness.reviewDialog.open, true);
    assert.equal(harness.reviewSummary.textContent, "summary-2");
    assert.equal(harness.reviewApprove.disabled, false);
    assert.equal(harness.link.href, undefined);
  }
});

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


test("health reconfirmation binds saved target and requires fresh fingerprint acknowledgement", async () => {
  const calls=[];
  const harness=createHarness({health:true,fetchImpl:async (url,options={}) => {
    calls.push({url,options});
    return {ok:true,json:async () => url.endsWith("/state") ? {connections:[],inventory:[],policies:[],profiles:[]} : url.endsWith("/probe") ? {fingerprint:"b".repeat(64)} : {policy_id:"p1"}};
  }});
  const action=harness.gridConfig.rowActions.find((a) => a.label === "Reconfirm health access");
  assert.equal(action.disabled({getData:() => ({policy_id:"p1",proposal_state:"needs_recovery"})}),false);
  assert.equal(action.disabled({getData:() => ({policy_id:"p1",proposal_state:"installing"})}),true);
  const launcher={};
  let opened;
  const onOpen=harness.wizardConfig.onOpen;
  harness.wizardConfig.onOpen=(options) => {opened=options;onOpen(options);};
  await action.action(null,{getData:() => ({policy_id:"p1",host:"vcenter.example.test",proposal_state:"needs_recovery"}),getElement:() => launcher});
  assert.equal(opened.launcher,launcher);
  assert.equal(harness.fields.policy_id.value,"p1");
  assert.equal(harness.explanation.textContent,"vcenter.example.test");
  assert.equal(harness.wizardConfig.validateStep({step:{id:"credential"}}).valid,false);
  harness.fields.health_credential_vault_id.value="v1";
  harness.fields.health_credential_entry_id.value="e1";
  await harness.probe.events.click();
  assert.deepEqual(JSON.parse(calls[0].options.body),{policy_id:"p1"});
  assert.equal(harness.wizardConfig.validateStep({step:{id:"fingerprint"}}).valid,false);
  harness.fields.confirm_health_fingerprint.checked=true;
  assert.equal(harness.wizardConfig.validateStep({step:{id:"fingerprint"}}),true);
  await harness.wizardConfig.onSubmit();
  const saved=calls.find((c) => c.url.endsWith("/save_policy"));
  assert.deepEqual(JSON.parse(saved.options.body),{policy_id:"p1",confirm_health_update:true,health_credential_vault_id:"v1",health_credential_entry_id:"e1",confirmed_target_tls_fingerprint:"b".repeat(64)});
  assert.equal(saved.options.headers["X-CSRF-Token"],"csrf-test");
  harness.fields.health_credential_entry_id.events.change();
  assert.equal(harness.fields.confirm_health_fingerprint.checked,false);
  assert.equal(harness.wizardConfig.validateStep({step:{id:"fingerprint"}}).valid,false);
  assert.equal(calls.some((c) => c.url.endsWith("/inventory")),false);
});

test("a delayed health probe cannot confirm a changed credential", async () => {
  let resolveProbe;
  const harness=createHarness({health:true,fetchImpl:() => new Promise((resolve) => {resolveProbe=resolve;})});
  await harness.wizard.open({context:{item:{policy_id:"p1",host:"vcenter.example.test"}}});
  const probing=harness.probe.events.click();
  harness.fields.health_credential_entry_id.events.change();
  resolveProbe({ok:true,json:async () => ({fingerprint:"b".repeat(64)})});
  await probing;
  harness.fields.confirm_health_fingerprint.checked=true;
  assert.equal(harness.wizardConfig.validateStep({step:{id:"fingerprint"}}).valid,false);
});
