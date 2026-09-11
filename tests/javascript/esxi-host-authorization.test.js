const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");
const source = fs.readFileSync("atlaso/app/static/app.js", "utf8");

function harness() {
  const element = { dataset: { canWrite: "true", authorizationReasons: '{"1":""}' } };
  const setting = { checked: true, dataset: {} };
  let requests = 0;
  let opened = 0;
  const context = vm.createContext({
    document: { getElementById: () => element, querySelector: () => setting },
    JSON, Error, Boolean,
    clearEsxiHostError() {}, showEsxiHostError() {},
    refreshEsxiHostReferenceState: async () => { requests++; return {}; },
    esxiBootAuthorizationWizard: { open: async () => { opened++; } },
  });
  vm.runInContext(source.split("function esxiHostAuthorizationDisabledReason", 2)[1]
    .split("function esxiHostMacKey", 1).map((part) => `function esxiHostAuthorizationDisabledReason${part}`).join(""), context);
  vm.runInContext(`async function requestEsxiHostBootAuthorization${source.split("async function requestEsxiHostBootAuthorization", 2)[1].split("function initializeEsxiBootAuthorizationWizard", 1)[0]}`, context);
  const data = { id: 1, enabled: true, kickstart_id: 2 };
  return { element, setting, data, context, counts: () => [requests, opened] };
}

test("console-off, pending save, failed refresh, permission and row gates block direct activation", async () => {
  for (const block of [
    (h) => { h.setting.checked = false; },
    (h) => { h.setting.dataset.pending = "true"; },
    (h) => { h.element.dataset.authorizationRefreshError = "Connection failed"; },
    (h) => { h.element.dataset.canWrite = "false"; },
    (h) => { h.data.enabled = false; },
    (h) => { h.data.kickstart_id = null; },
    (h) => { h.data.is_new = true; },
    (h) => { h.data.is_default = true; },
    (h) => { h.element.dataset.authorizationReasons = '{"1":"Apply required"}'; },
  ]) {
    const h = harness();
    block(h);
    await h.context.requestEsxiHostBootAuthorization({ getData: () => h.data, getElement: () => null });
    assert.deepEqual(h.counts(), [0, 0]);
  }
});

test("effective console authorization refreshes readiness before opening", async () => {
  const h = harness();
  await h.context.requestEsxiHostBootAuthorization({ getData: () => h.data, getElement: () => null });
  assert.deepEqual(h.counts(), [1, 1]);
});

test("a stale enabled menu cannot open after readiness changes during refresh", async () => {
  const h = harness();
  h.context.refreshEsxiHostReferenceState = async () => { h.setting.checked = false; };
  await h.context.requestEsxiHostBootAuthorization({ getData: () => h.data, getElement: () => null });
  assert.deepEqual(h.counts(), [0, 0]);
});

test("a superseded readiness projection cannot open the authorization wizard", async () => {
  const h = harness();
  h.context.refreshEsxiHostReferenceState = async () => null;
  await h.context.requestEsxiHostBootAuthorization({ getData: () => h.data, getElement: () => null });
  assert.deepEqual(h.counts(), [0, 0]);
});

test("a superseded readiness projection cannot submit a boot authorization", async () => {
  const h = harness();
  let configuration;
  let submissions = 0;
  class Form { elements = { host_id: {}, boot_code: {} }; }
  const form = new Form();
  class Dialog { querySelector() { return form; } }
  const dialog = new Dialog();
  Object.assign(h.context, {
    HTMLDialogElement: Dialog, HTMLFormElement: Form,
    window: { AtlasoUiPatterns: { createWizard: (config) => { configuration = config; } } },
    refreshEsxiHostReferenceState: async () => null,
    networkBootRequest: async () => { submissions++; },
    showEsxiHostSuccess() {},
  });
  h.context.document.getElementById = (id) => id === "esxi-boot-authorization-dialog" ? dialog : h.element;
  vm.runInContext(`function initializeEsxiBootAuthorizationWizard${source.split("function initializeEsxiBootAuthorizationWizard", 2)[1].split("function esxiHostHasValidWakeMac", 1)[0]}`, h.context);
  h.context.initializeEsxiBootAuthorizationWizard();
  configuration.onOpen({ context: { host: h.data } });
  const result = await configuration.onSubmit();
  assert.equal(result.valid, false);
  assert.match(result.message, /Retry authorization/);
  assert.equal(submissions, 0);
});
