const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const appSource = fs.readFileSync("atlaso/app/static/app.js", "utf8");
const vaultTemplate = fs.readFileSync("atlaso/app/templates/vaults.html", "utf8");

function functionSource(name) {
  const start = appSource.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must exist in app.js`);
  const bodyStart = appSource.indexOf("{", appSource.indexOf(")", start));
  let depth = 0;
  for (let index = bodyStart; index < appSource.length; index += 1) {
    if (appSource[index] === "{") depth += 1;
    if (appSource[index] === "}") depth -= 1;
    if (depth === 0) return appSource.slice(start, index + 1);
  }
  throw new Error(`Unable to extract ${name}`);
}

class FakeElement {
  constructor() {
    this.isConnected = true;
    this.dataset = {};
    this.children = [];
    this.listeners = new Map();
    this.classList = { toggle() {}, add() {}, remove() {} };
    this.textContent = "";
    this.value = "";
  }

  addEventListener(name, callback) { this.listeners.set(name, callback); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = [...children]; }
  querySelector() { return null; }
  querySelectorAll() { return []; }
  setAttribute() {}
}

class FakeDialog extends FakeElement {}
class FakeButton extends FakeElement {}
class FakeMutationObserver {
  constructor(callback) { this.callback = callback; }
  observe() {}
  trigger() { this.callback(); }
}
class FakeInput extends FakeElement {
  constructor(value = "") {
    super();
    this.value = value;
    this.required = false;
    this.type = "";
    this.placeholder = "";
  }
}
class FakeSelect extends FakeElement {
  constructor(options) {
    super();
    this.options = options;
    this.value = "unknown";
  }

  get selectedOptions() {
    return [{ textContent: this.options.find(([value]) => value === this.value)?.[1] || "Unknown" }];
  }
}

class FakeForm extends FakeElement {
  constructor() {
    super();
    this.uriList = new FakeElement();
    this.uriAdd = new FakeButton();
    this.password = new FakeInput();
    this.passwordEye = new FakeButton();
    this.submit = new FakeButton();
    this.title = new FakeElement();
    this.passwordHelp = new FakeElement();
    this.review = {
      key: new FakeElement(), service: new FakeElement(), username: new FakeElement(),
      password: new FakeElement(), uris: new FakeElement(),
    };
    this.elements = {
      csrf: new FakeInput("fixture-csrf"), uris_json: new FakeInput("[]"), copy_entry_id: new FakeInput(""),
      key: new FakeInput(), service_type: new FakeSelect([["unknown", "Unknown"], ["operations", "Operations"], ["vcenter", "vCenter"]]),
      description: new FakeInput(), username: new FakeInput(), value: this.password,
    };
  }

  reset() { this.listeners.get("reset")?.(); }

  querySelector(selector) {
    const elements = {
      "[data-vault-uri-list]": this.uriList,
      "[data-vault-uri-add]": this.uriAdd,
      "[data-vault-entry-password]": this.password,
      "[data-vault-entry-password-eye]": this.passwordEye,
      "[data-atlaso-wizard-submit]": this.submit,
      "[data-vault-entry-title]": this.title,
      "[data-vault-entry-password-help]": this.passwordHelp,
      "[data-vault-entry-review-key]": this.review.key,
      "[data-vault-entry-review-service]": this.review.service,
      "[data-vault-entry-review-username]": this.review.username,
      "[data-vault-entry-review-password]": this.review.password,
      "[data-vault-entry-review-uris]": this.review.uris,
    };
    return elements[selector] || null;
  }
}

function makeRuntime() {
  const workspace = new FakeElement();
  workspace.querySelector = () => new FakeElement();
  const dialog = new FakeDialog();
  const form = new FakeForm();
  const table = new FakeElement();
  table.dataset.vaultId = "4";
  const source = new FakeElement();
  source.textContent = JSON.stringify([
    { id: 9, key: "vcf.operations.admin", display_name: "Operations · vc01 · admin", service_type: "operations", service_type_label: "Operations", username: "admin", description: "Historical entry", uris: [], has_value: true },
  ]);
  const gridConfigs = [];
  const copiedText = [];
  const statuses = [];
  const newRecordFields = [];
  const timers = new Map();
  const clearedTimers = new Set();
  const observers = [];
  let nextTimerId = 0;
  let fetchHandler = async () => ({ ok: true, json: async () => ({ value: "fixture-value" }) });
  let wizardOpenOptions;
  let wizardOptions;
  const wizard = { open(options) { wizardOpenOptions = options; } };
  const context = vm.createContext({
    document: {
      querySelector: (selector) => selector === "[data-vaults-workspace]" ? workspace : selector === "[data-vault-entry-form]" ? form : null,
      querySelectorAll: (selector) => selector === "[data-vault-entries-table]" ? [table] : [],
      getElementById: (id) => id === "vault-entry-modal" ? dialog : id === "vault-entries-data-4" ? source : null,
      createElement: () => new FakeElement(),
    },
    window: {
      clearTimeout(id) { clearedTimers.add(id); },
      setTimeout(callback, delay) { const id = ++nextTimerId; timers.set(id, { callback, delay }); return id; },
      AtlasoUiPatterns: {
        createWizard(options) { wizardOptions = options; return wizard; },
        createGrid(config) { gridConfigs.push(config); return {}; },
      },
    },
    HTMLElement: FakeElement,
    HTMLDialogElement: FakeDialog,
    HTMLFormElement: FakeForm,
    HTMLInputElement: FakeInput,
    HTMLButtonElement: FakeButton,
    FormData: class { set() {} },
    fetch: (...args) => fetchHandler(...args),
    MutationObserver: class extends FakeMutationObserver { constructor(callback) { super(callback); observers.push(this); } },
    managementUiPath: (path) => path,
    copyTextToClipboard: async (value, message) => { copiedText.push({ value, message }); },
    showTransientGridStatus: (message) => statuses.push(message),
    markNewRecordRow: (_row, field) => newRecordFields.push(field),
    escapeHtml: (value) => String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]),
  });
  vm.runInContext(`${functionSource("initializeVaultsPage")}; initializeVaultsPage();`, context);
  return {
    form, gridConfig: gridConfigs[0], wizardOptions, wizardOpenOptions: () => wizardOpenOptions,
    copiedText, statuses, newRecordFields, timers, clearedTimers, observers,
    fireTimer(id) { timers.get(id)?.callback(); },
    setFetchHandler(handler) { fetchHandler = handler; },
  };
}

function click(element, event = {}) {
  return element.listeners.get("click")?.({ target: element, ...event });
}

function makePasswordCell() {
  const eye = new FakeButton();
  eye.dataset.vaultPasswordEye = "true";
  const value = new FakeElement();
  value.dataset.vaultPasswordValue = "true";
  value.textContent = "••••••••";
  const cellElement = new FakeElement();
  cellElement.querySelector = (selector) => selector === "[data-vault-password-eye]" ? cellElement.eye
    : selector === "[data-vault-password-value]" ? cellElement.value : null;
  cellElement.eye = eye;
  cellElement.value = value;
  const cell = { getElement: () => cellElement, getRow: () => ({ getData: () => ({ id: 9 }) }) };
  const event = { target: { closest: (selector) => selector === "[data-vault-password-eye]" ? eye : null } };
  return { eye, value, cellElement, cell, event };
}

class FakeImportForm extends FakeForm {
  constructor() {
    super();
    this.candidates = new FakeElement();
    this.summary = new FakeElement();
    this.fingerprint = new FakeElement();
    this.fingerprintConfirm = new FakeInput();
    this.elements = {
      csrf: new FakeInput("fixture-csrf"), source_type: new FakeSelect([["sddc_manager", "SDDC Manager"], ["vcf_installer", "VCF Installer"]]),
      address: new FakeInput("sddc01.example.test"), port: new FakeInput("443"), confirmed_fingerprint: new FakeInput(""),
      username: new FakeInput("operator"), password: new FakeInput("fixture-password"),
      credential_vault_id: new FakeSelect([["", "None"]]), credential_entry_id: new FakeSelect([["", "None"]]),
      vault_id: new FakeSelect([["4", "Primary"]]),
    };
  }

  querySelector(selector) {
    const elements = {
      "[data-vcf-vault-candidates]": this.candidates,
      "[data-vcf-vault-discovery-summary]": this.summary,
      "[data-vcf-vault-fingerprint]": this.fingerprint,
      "[data-vcf-vault-fingerprint-confirm]": this.fingerprintConfirm,
    };
    if (selector === 'input[name="candidate_ids"]:checked') return this.candidates.children[0]?.children[0] || null;
    return elements[selector] || super.querySelector(selector);
  }
}

function makeImportRuntime(payload) {
  const modal = new FakeDialog();
  const form = new FakeImportForm();
  let wizardOptions;
  const context = vm.createContext({
    document: {
      getElementById: (id) => id === "vcf-vault-import-modal" ? modal : null,
      querySelector: (selector) => selector === "[data-vcf-vault-import-form]" ? form : null,
      querySelectorAll: () => [],
      createElement: () => new FakeElement(),
    },
    window: { AtlasoUiPatterns: { createWizard(options) { wizardOptions = options; return {}; } }, location: { assign() {} } },
    HTMLDialogElement: FakeDialog,
    HTMLFormElement: FakeImportForm,
    HTMLInputElement: FakeInput,
    managementUiPath: (path) => path,
    fetch: async () => ({ status: 200, ok: true, json: async () => payload }),
  });
  vm.runInContext(`${functionSource("initializeVcfVaultImport")}; initializeVcfVaultImport();`, context);
  return { form, wizardOptions };
}

test("Vaults grid displays readable names with escaped stable-key tooltips and fallback", () => {
  const { gridConfig } = makeRuntime();
  const nameColumn = gridConfig.options.columns.find((column) => column.field === "display_name");
  assert.ok(nameColumn);
  assert.equal(nameColumn.title, "Name");
  assert.equal(nameColumn.headerFilter, "input");
  const renderedName = nameColumn.formatter({
    getRow: () => ({ getData: () => ({ key: 'vcf.<script>"admin"' }) }),
    getValue: () => "Readable <name>",
  });
  assert.equal(renderedName, '<span title="vcf.&lt;script&gt;&quot;admin&quot;">Readable &lt;name&gt;</span>');
  assert.equal(nameColumn.formatter({ getRow: () => ({ getData: () => ({ key: "vcf.fallback" }) }), getValue: () => "" }), '<span title="vcf.fallback">vcf.fallback</span>');
  const serviceColumn = gridConfig.options.columns.find((column) => column.field === "service_type_label");
  assert.ok(serviceColumn);
  assert.equal(serviceColumn.title, "Service");
  assert.equal(serviceColumn.headerFilter, "input");
  assert.equal(serviceColumn.formatter({ getRow: () => ({ getData: () => ({}) }), getValue: () => "Operations <script>" }), "Operations &lt;script&gt;");
  assert.match(vaultTemplate, /<th>Name<\/th><th>Service<\/th>/);
  assert.match(vaultTemplate, /title="\{\{ entry\.key \}\}"/);
  assert.match(vaultTemplate, /entry\.display_name or entry\.key/);
  assert.match(vaultTemplate, /entry\.service_type_label or "Unknown"/);
  assert.match(vaultTemplate, /<td colspan="4">No passwords are stored/);
  assert.match(vaultTemplate, /stable key is used by scripts and Kickstarts/);
});

test("Vault row Copy key action copies the stable key and keeps duplicate Copy", async () => {
  const { gridConfig, copiedText, statuses } = makeRuntime();
  const row = { id: 9, key: "vcf.operations.admin", display_name: "Operations · vc01 · admin", uris: [] };
  const component = { getData: () => row, getElement: () => new FakeElement() };
  const actions = gridConfig.options.rowContextMenu(null, component);
  const copyKey = actions.find((action) => action.label === "Copy key");
  assert.ok(copyKey);
  assert.ok(actions.some((action) => action.label === "Copy"));
  await copyKey.action(null, component);
  assert.deepEqual(copiedText, [{ value: "vcf.operations.admin", message: "Key copied" }]);
  assert.deepEqual(statuses, []);
});

test("Vault add row keeps the Name cell visible under shared pending-row styles", () => {
  const { gridConfig, newRecordFields } = makeRuntime();
  const row = { getData: () => ({ is_new: true, key: "" }) };
  const nameColumn = gridConfig.options.columns.find((column) => column.title === "Name");
  gridConfig.options.rowFormatter(row);
  assert.deepEqual(newRecordFields, [nameColumn.field]);
  assert.match(nameColumn.formatter({ getRow: () => row }), /\+ Add password here/);
});

test("Vault Name and Service filters retain the add row and match existing labels case-insensitively", () => {
  const { gridConfig, wizardOpenOptions } = makeRuntime();
  const nameColumn = gridConfig.options.columns.find((column) => column.field === "display_name");
  const serviceColumn = gridConfig.options.columns.find((column) => column.field === "service_type_label");
  const entry = { display_name: "Operations · vc01 · admin", service_type_label: "Operations" };
  const addRow = { is_new: true };

  assert.equal(nameColumn.headerFilterFunc("VC01", entry.display_name, entry), true);
  assert.equal(nameColumn.headerFilterFunc("nomatch", entry.display_name, entry), false);
  assert.equal(serviceColumn.headerFilterFunc("OPERATIONS", entry.service_type_label, entry), true);
  assert.equal(serviceColumn.headerFilterFunc("nomatch", entry.service_type_label, entry), false);
  assert.equal(nameColumn.headerFilterFunc("nomatch", "", addRow), true);
  assert.equal(serviceColumn.headerFilterFunc("nomatch", "", addRow), true);
  assert.equal(
    nameColumn.headerFilterFunc("VCF", "VCF Admin", entry)
      && serviceColumn.headerFilterFunc("operations", "Operations", entry),
    true,
  );
  assert.equal(
    nameColumn.headerFilterFunc("nomatch", "VCF Admin", entry)
      && serviceColumn.headerFilterFunc("operations", "Operations", entry),
    false,
  );
  assert.equal(
    nameColumn.headerFilterFunc("VCF", "VCF Admin", entry)
      && serviceColumn.headerFilterFunc("nomatch", "Operations", entry),
    false,
  );

  const launcher = new FakeElement();
  nameColumn.cellClick({}, {
    getRow: () => ({ getData: () => addRow }),
    getElement: () => launcher,
  });
  assert.equal(wizardOpenOptions().context.vaultId, 4);
  assert.equal(wizardOpenOptions().context.row, null);
  assert.equal(wizardOpenOptions().launcher, launcher);
});

test("Vault entry wizard defaults to Unknown and preserves service through Edit, Copy, and Review", () => {
  const { form, wizardOptions } = makeRuntime();
  const existing = { id: 9, key: "vcf.operations.admin", service_type: "operations", username: "admin", uris: [] };

  wizardOptions.onOpen({ context: { vaultId: 4 } });
  assert.equal(form.elements.service_type.value, "unknown");
  wizardOptions.onOpen({ context: { vaultId: 4, row: existing } });
  assert.equal(form.elements.service_type.value, "operations");
  wizardOptions.prepareReview();
  assert.equal(form.review.service.textContent, "Operations");
  wizardOptions.onOpen({ context: { vaultId: 4, row: existing, copy: true, copyKey: "vcf.operations.admin.copy" } });
  assert.equal(form.elements.service_type.value, "operations");
  wizardOptions.prepareReview();
  assert.equal(form.review.service.textContent, "Operations");
});

test("Vault entry reveal starts a fresh 15-second timeout after manual hide", async () => {
  const { form, wizardOptions, timers, clearedTimers, fireTimer } = makeRuntime();
  wizardOptions.onOpen({ context: { vaultId: 4, row: { id: 9 } } });
  const eye = form.passwordEye;

  await click(eye);
  const firstTimer = [...timers.keys()][0];
  assert.equal(timers.get(firstTimer).delay, 15000);
  assert.equal(form.password.type, "text");

  await click(eye);
  assert.ok(clearedTimers.has(firstTimer));
  assert.equal(form.password.type, "password");

  await click(eye);
  const secondTimer = [...timers.keys()][1];
  assert.equal(timers.get(secondTimer).delay, 15000);
  fireTimer(firstTimer);
  assert.equal(form.password.type, "text");
  assert.equal(eye.dataset.revealed, "true");

  fireTimer(secondTimer);
  assert.equal(form.password.type, "password");
  assert.equal(eye.dataset.revealed, "false");
});

test("Vault entry close invalidates a pending password reveal response", async () => {
  const runtime = makeRuntime();
  const { form, wizardOptions } = runtime;
  let resolveFetch;
  runtime.setFetchHandler(() => new Promise((resolve) => { resolveFetch = resolve; }));
  wizardOptions.onOpen({ context: { vaultId: 4, row: { id: 9 } } });
  const pending = click(form.passwordEye);
  wizardOptions.onClose();
  resolveFetch({ ok: true, json: async () => ({ value: "late-value" }) });
  await pending;

  assert.equal(form.password.type, "password");
  assert.equal(form.passwordEye.dataset.revealed, "false");
  assert.equal(form.passwordEye.disabled, false);
});

test("Vault entry close, reset, and reopen cancel active reveal timers", async () => {
  const { form, wizardOptions, timers, clearedTimers, fireTimer } = makeRuntime();
  const context = { vaultId: 4, row: { id: 9 } };
  wizardOptions.onOpen({ context });
  await click(form.passwordEye);
  const firstTimer = [...timers.keys()][0];

  wizardOptions.onClose();
  assert.ok(clearedTimers.has(firstTimer));
  fireTimer(firstTimer);
  assert.equal(form.password.type, "password");

  wizardOptions.onOpen({ context });
  await click(form.passwordEye);
  const secondTimer = [...timers.keys()][1];
  form.reset();
  assert.ok(clearedTimers.has(secondTimer));
  fireTimer(secondTimer);
  assert.equal(form.password.type, "password");

  wizardOptions.onOpen({ context });
  await click(form.passwordEye);
  const thirdTimer = [...timers.keys()][2];
  assert.equal(timers.get(thirdTimer).delay, 15000);
  fireTimer(secondTimer);
  assert.equal(form.password.type, "text");
  fireTimer(thirdTimer);
  assert.equal(form.password.type, "password");
});

test("Vault grid reveal resets after hide and ignores stale timers after control replacement", async () => {
  const { gridConfig, timers, clearedTimers, fireTimer, observers } = makeRuntime();
  const passwordColumn = gridConfig.options.columns.find((column) => column.title === "Password");
  const original = makePasswordCell();

  await passwordColumn.cellClick(original.event, original.cell);
  const firstTimer = [...timers.keys()][0];
  assert.equal(timers.get(firstTimer).delay, 15000);
  assert.equal(original.value.textContent, "fixture-value");

  await passwordColumn.cellClick(original.event, original.cell);
  assert.ok(clearedTimers.has(firstTimer));
  assert.equal(original.value.textContent, "••••••••");

  await passwordColumn.cellClick(original.event, original.cell);
  const secondTimer = [...timers.keys()][1];
  fireTimer(firstTimer);
  assert.equal(original.value.textContent, "fixture-value");

  const replacement = makePasswordCell();
  original.cellElement.eye = replacement.eye;
  original.cellElement.value = replacement.value;
  observers[0].trigger();
  assert.ok(clearedTimers.has(secondTimer));
  assert.equal(original.value.textContent, "••••••••");

  await passwordColumn.cellClick(replacement.event, original.cell);
  const replacementTimer = [...timers.keys()][2];
  assert.equal(timers.get(replacementTimer).delay, 15000);
  fireTimer(secondTimer);
  assert.equal(replacement.value.textContent, "fixture-value");
  fireTimer(replacementTimer);
  assert.equal(replacement.value.textContent, "••••••••");
});

test("Vault grid ignores a reveal response after the row controls are replaced", async () => {
  const runtime = makeRuntime();
  const { gridConfig, observers } = runtime;
  const passwordColumn = gridConfig.options.columns.find((column) => column.title === "Password");
  const original = makePasswordCell();
  let resolveFetch;
  runtime.setFetchHandler(() => new Promise((resolve) => { resolveFetch = resolve; }));
  const pending = passwordColumn.cellClick(original.event, original.cell);

  const replacement = makePasswordCell();
  original.cellElement.eye = replacement.eye;
  original.cellElement.value = replacement.value;
  observers[0].trigger();
  resolveFetch({ ok: true, json: async () => ({ value: "late-value" }) });
  await pending;

  assert.equal(original.value.textContent, "••••••••");
  assert.equal(replacement.value.textContent, "••••••••");
  assert.equal(original.eye.disabled, false);
});

test("Vault grid reveal timers remain independent across cells", async () => {
  const { gridConfig, timers, fireTimer } = makeRuntime();
  const passwordColumn = gridConfig.options.columns.find((column) => column.title === "Password");
  const first = makePasswordCell();
  const second = makePasswordCell();

  await passwordColumn.cellClick(first.event, first.cell);
  await passwordColumn.cellClick(second.event, second.cell);
  const [firstTimer, secondTimer] = [...timers.keys()];
  assert.equal(timers.get(firstTimer).delay, 15000);
  assert.equal(timers.get(secondTimer).delay, 15000);

  fireTimer(firstTimer);
  assert.equal(first.value.textContent, "••••••••");
  assert.equal(second.value.textContent, "fixture-value");
  fireTimer(secondTimer);
  assert.equal(second.value.textContent, "••••••••");
});

test("VCF import candidate account details include the service label as text", async () => {
  const { form, wizardOptions } = makeImportRuntime({
    discovery: { scope: "Fixture source" },
    candidates: [
      { candidate_id: "candidate-1", key: "vcf.operations.admin", display_name: "operations.ops01.admin", service_type: "operations", service_type_label: "Operations", secret_type: "vcf_password", username: "admin", uris: [] },
      { candidate_id: "candidate-2", key: "vcf.unknown.admin", secret_type: "other", username: "operator", uris: [] },
    ],
  });
  await wizardOptions.onNext({ controller: { setError() {} }, step: { id: "credentials" } });
  const accountDescription = form.candidates.children[0].children[1].children[1];
  const name = form.candidates.children[0].children[1].children[0].children[0];
  assert.equal(name.textContent, "operations.ops01.admin");
  assert.equal(name.title, "vcf.operations.admin");
  assert.equal(accountDescription.textContent, "Operations · VCF password · admin");
  assert.equal(form.candidates.children[1].children[1].children[1].textContent, "Unknown · Other credential · operator");
});
