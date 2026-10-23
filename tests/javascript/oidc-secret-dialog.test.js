const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync("atlaso/app/static/app.js", "utf8");
const start = source.indexOf("function setOidcSecretResult(");
const end = source.indexOf("function validateOidcRedirectUriField(", start);
assert.ok(start >= 0 && end > start);

function harness({ initial = "", autoOpen = false } = {}) {
  class Control {
    constructor() { this.events = {}; this.attributes = {}; this.value = ""; this.textContent = ""; }
    addEventListener(name, callback) { this.events[name] = callback; }
    setAttribute(name, value) { this.attributes[name] = value; }
    removeAttribute(name) { delete this.attributes[name]; }
    hasAttribute(name) { return name in this.attributes; }
    focus() { document.activeElement = this; }
    closest() { return null; }
  }
  const input = new Control();
  input.value = initial;
  input.setAttribute("value", initial);
  const fields = Object.fromEntries(["value", "client-id", "reveal", "copy", "close", "status", "slash"].map((name) => [name, name === "value" ? input : new Control()]));
  fields.slash.classList = { toggle: (_name, hidden) => { fields.slash.hidden = hidden; } };
  const frames = [];
  const timers = new Map();
  const windowEvents = {};
  class Dialog extends Control {
    querySelector(selector) { return fields[selector.slice("[data-oidc-secret-".length, -1)]; }
    showModal() { this.open = true; }
    close() { this.open = false; this.events.close(); }
  }
  const dialog = new Dialog();
  dialog.dataset = { csrf: "synthetic-csrf" };
  if (autoOpen) dialog.setAttribute("data-oidc-secret-auto-open", "");
  const launcher = new Control();
  launcher.isConnected = true;
  const confirmation = new Control();
  confirmation.classList = { remove() {} };
  const document = { activeElement: launcher, getElementById: (id) => id === "oidc-client-secret-modal" ? dialog : confirmation, querySelector: () => launcher };
  const copied = [];
  const audits = [];
  let failCopy = false;
  let nextTimer = 0;
  const context = vm.createContext({
    document, HTMLDialogElement: Dialog, HTMLInputElement: Control,
    FormData: class { constructor() { this.fields = {}; } set(key, value) { this.fields[key] = value; } },
    managementUiPath: (path) => path,
    oidcFormRequest: async (path, body) => { audits.push({ path, fields: body.fields }); return { audited: true }; },
    copyTextToClipboard: async (value) => { if (failCopy) throw new Error("denied"); copied.push(value); },
    window: {
      requestAnimationFrame: (callback) => frames.push(callback),
      setTimeout: (callback, milliseconds) => { const id = ++nextTimer; timers.set(id, { callback, milliseconds }); return id; },
      clearTimeout: (id) => timers.delete(id),
      addEventListener: (name, callback) => { windowEvents[name] = callback; },
    },
  });
  vm.runInContext(source.slice(start, end), context);
  const flush = () => { while (frames.length) frames.shift()(); };
  return { context, dialog, input, fields, document, launcher, confirmation, copied, audits, timers, windowEvents, flush, failCopy: () => { failCopy = true; } };
}

test("registration handoff opens masked after wizard focus restoration; copy does not reveal", async () => {
  const h = harness();
  h.context.setOidcSecretResult("synthetic-client", "synthetic-secret");
  assert.equal(h.dialog.open, undefined);
  h.flush();
  assert.equal(h.dialog.open, true);
  assert.equal(h.input.type, "password");
  assert.equal(h.document.activeElement, h.fields.close);
  assert.equal(h.fields["client-id"].textContent, "synthetic-client");
  await h.fields.copy.events.click();
  assert.deepEqual(h.copied, ["synthetic-secret"]);
  assert.equal(h.input.type, "password");
  assert.ok(!h.confirmation.textContent.includes("synthetic-secret"));
});

test("reveal is audited, deliberate, accessible, and automatically remasked after 15 seconds", async () => {
  const h = harness();
  h.context.setOidcSecretResult("id", "synthetic-secret");
  h.flush();
  const reveal = h.fields.reveal.events.click();
  assert.equal(h.input.type, "password");
  await reveal;
  assert.equal(h.input.type, "text");
  assert.deepEqual(h.audits[0].fields, { csrf: "synthetic-csrf", client_id: "id" });
  assert.ok(!JSON.stringify(h.audits).includes("synthetic-secret"));
  assert.equal(h.fields.reveal.attributes["aria-label"], "Hide client secret");
  assert.equal(h.fields.reveal.attributes["aria-pressed"], "true");
  const timer = [...h.timers.values()][0];
  assert.equal(timer.milliseconds, 15000);
  timer.callback();
  assert.equal(h.input.type, "password");
  assert.equal(h.fields.reveal.attributes["aria-label"], "Reveal client secret");
  assert.equal(h.fields.slash.hidden, true);
});

test("Done, native Escape close, and page exit discard live and initial HTML values", async () => {
  for (const dismiss of [(h) => h.fields.close.events.click(), (h) => h.dialog.close(), (h) => h.windowEvents.pagehide()]) {
    const h = harness({ initial: "synthetic-server-secret", autoOpen: true });
    h.context.initializeOidcSecretModal();
    h.flush();
    assert.equal(h.dialog.open, true);
    await h.fields.reveal.events.click();
    dismiss(h);
    assert.equal(h.dialog.open, false);
    assert.equal(h.input.value, "");
    assert.equal(h.input.hasAttribute("value"), false);
    assert.equal(h.input.type, "password");
    assert.equal(h.timers.size, 0);
    assert.equal(h.dialog.hasAttribute("data-oidc-secret-auto-open"), false);
    assert.equal(h.document.activeElement, h.launcher);
    h.context.initializeOidcSecretModal();
    h.flush();
    assert.equal(h.dialog.open, false);
  }
});

test("rotation reuses the dialog with a fresh masked value and recoverable copy failure", async () => {
  const h = harness();
  h.context.setOidcSecretResult("id", "synthetic-old");
  h.flush();
  h.fields.close.events.click();
  h.context.setOidcSecretResult("id", "synthetic-replacement");
  h.flush();
  h.failCopy();
  await h.fields.copy.events.click();
  assert.equal(h.input.value, "synthetic-replacement");
  assert.equal(h.input.type, "password");
  assert.match(h.fields.status.textContent, /Copy failed/);
  assert.ok(!h.fields.status.textContent.includes(h.input.value));
});

test("leaving before the deferred open cannot resurrect a credential", () => {
  const h = harness();
  h.context.setOidcSecretResult("id", "synthetic-secret");
  h.windowEvents.pagehide();
  h.flush();
  assert.ok(!h.dialog.open);
  assert.equal(h.input.value, "");
});

test("late clipboard completion cannot acknowledge a replacement credential", async () => {
  const h = harness();
  let completeCopy;
  h.context.copyTextToClipboard = () => new Promise((resolve) => { completeCopy = resolve; });
  h.context.setOidcSecretResult("id", "synthetic-old");
  h.flush();
  const pending = h.fields.copy.events.click();
  h.fields.close.events.click();
  h.context.setOidcSecretResult("id", "synthetic-new");
  h.flush();
  completeCopy();
  await pending;
  assert.equal(h.fields.status.textContent, "");
});

test("failed audit stays masked and late audit cannot reveal a replacement", async () => {
  const h = harness();
  h.context.setOidcSecretResult("id", "synthetic-old");
  h.flush();
  h.context.oidcFormRequest = async () => { throw new Error("denied"); };
  await h.fields.reveal.events.click();
  assert.equal(h.input.type, "password");
  assert.equal(h.fields.reveal.disabled, false);
  assert.match(h.fields.status.textContent, /remains masked/);
  let completeAudit;
  h.context.oidcFormRequest = () => new Promise((resolve) => { completeAudit = resolve; });
  const pending = h.fields.reveal.events.click();
  assert.equal(h.fields.reveal.disabled, true);
  h.fields.close.events.click();
  h.context.setOidcSecretResult("id", "synthetic-new");
  h.flush();
  completeAudit({ audited: true });
  await pending;
  assert.equal(h.input.type, "password");
  assert.equal(h.fields.reveal.disabled, false);
  assert.equal(h.fields.status.textContent, "");
});

test("registration closes the shared wizard before the credential handoff; edits do not reissue it", async () => {
  const gridStart = source.indexOf("function initializeOidcClientsTable(");
  const gridEnd = source.indexOf("function initializeOidcKeysTable(", gridStart);
  class Element {
    constructor() { this.dataset = { clients: "[]", csrf: "synthetic-csrf" }; }
    addEventListener() {}
  }
  class Form extends Element {}
  class Dialog extends Element {}
  const grid = new Element();
  const form = new Form();
  const dialog = new Dialog();
  let wizardConfig;
  let recordId = "";
  const order = [];
  const payload = { client: { id: 1, client_id: "synthetic-id" }, client_secret: "synthetic-secret" };
  const context = vm.createContext({
    HTMLElement: Element, HTMLFormElement: Form, HTMLDialogElement: Dialog,
    document: { getElementById: (id) => id === "oidc-clients-table" ? grid : dialog, querySelector: () => form },
    FormData: class { get() { return recordId; } },
    managementUiPath: (value) => value,
    markNewRecordRow() {},
    oidcFormRequest: async () => payload,
    setOidcSecretResult: (...args) => order.push(["secret", ...args]),
    window: { AtlasoUiPatterns: {
      createGrid: () => ({ table: { addRow: async () => order.push(["row-added"]), getRow: () => ({ update: async () => order.push(["row-updated"]) }) } }),
      createWizard: (config) => { wizardConfig = config; return { close: (value) => order.push(["closed", value]) }; },
    } },
  });
  vm.runInContext(source.slice(gridStart, gridEnd), context);
  context.initializeOidcClientsTable();
  const created = await wizardConfig.onSubmit();
  assert.equal(created.close, false);
  assert.deepEqual(order, [["row-added"], ["closed", "submit"], ["secret", "synthetic-id", "synthetic-secret"]]);
  order.length = 0;
  recordId = "1";
  delete payload.client_secret;
  const edited = await wizardConfig.onSubmit();
  assert.equal(edited.valid, true);
  assert.deepEqual(order, [["row-updated"]]);
});
