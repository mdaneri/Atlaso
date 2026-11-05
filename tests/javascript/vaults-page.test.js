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

  reset() {}

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
    { id: 9, key: "vcf.operations.admin", service_type: "operations", service_type_label: "Operations", username: "admin", description: "Historical entry", uris: [], has_value: true },
  ]);
  const gridConfigs = [];
  let wizardOptions;
  const wizard = { open() {} };
  const context = vm.createContext({
    document: {
      querySelector: (selector) => selector === "[data-vaults-workspace]" ? workspace : selector === "[data-vault-entry-form]" ? form : null,
      querySelectorAll: (selector) => selector === "[data-vault-entries-table]" ? [table] : [],
      getElementById: (id) => id === "vault-entry-modal" ? dialog : id === "vault-entries-data-4" ? source : null,
      createElement: () => new FakeElement(),
    },
    window: {
      clearTimeout() {},
      setTimeout() { return 1; },
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
    managementUiPath: (path) => path,
    escapeHtml: (value) => String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]),
  });
  vm.runInContext(`${functionSource("initializeVaultsPage")}; initializeVaultsPage();`, context);
  return { form, gridConfig: gridConfigs[0], wizardOptions };
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

test("Vaults grid exposes a safe sortable and filterable service column and readable fallback", () => {
  const { gridConfig } = makeRuntime();
  const serviceColumn = gridConfig.options.columns.find((column) => column.field === "service_type_label");
  assert.ok(serviceColumn);
  assert.equal(serviceColumn.title, "Service");
  assert.equal(serviceColumn.headerFilter, "input");
  assert.equal(serviceColumn.formatter({ getRow: () => ({ getData: () => ({}) }), getValue: () => "Operations <script>" }), "Operations &lt;script&gt;");
  assert.match(vaultTemplate, /<th>Key<\/th><th>Service<\/th>/);
  assert.match(vaultTemplate, /entry\.service_type_label or "Unknown"/);
  assert.match(vaultTemplate, /<td colspan="4">No passwords are stored/);
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

test("VCF import candidate account details include the service label as text", async () => {
  const { form, wizardOptions } = makeImportRuntime({
    discovery: { scope: "Fixture source" },
    candidates: [
      { candidate_id: "candidate-1", key: "vcf.operations.admin", service_type: "operations", service_type_label: "Operations", secret_type: "vcf_password", username: "admin", uris: [] },
      { candidate_id: "candidate-2", key: "vcf.unknown.admin", secret_type: "other", username: "operator", uris: [] },
    ],
  });
  await wizardOptions.onNext({ controller: { setError() {} }, step: { id: "credentials" } });
  const accountDescription = form.candidates.children[0].children[1].children[1];
  assert.equal(accountDescription.textContent, "Operations · VCF password · admin");
  assert.equal(form.candidates.children[1].children[1].children[1].textContent, "Unknown · Other credential · operator");
});
