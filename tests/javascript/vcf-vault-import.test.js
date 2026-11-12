const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const appSource = fs.readFileSync("atlaso/app/static/app.js", "utf8");
const appCss = fs.readFileSync("atlaso/app/static/app.css", "utf8");
const importTemplate = fs.readFileSync("atlaso/app/templates/partials/vcf_vault_import_modal.html", "utf8");

function functionSource(name) {
  const start = appSource.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must exist in app.js`);
  const parametersStart = appSource.indexOf("(", start);
  let parameterDepth = 0;
  let bodyStart = -1;
  for (let index = parametersStart; index < appSource.length; index += 1) {
    if (appSource[index] === "(") parameterDepth += 1;
    if (appSource[index] === ")") {
      parameterDepth -= 1;
      if (parameterDepth === 0) {
        bodyStart = appSource.indexOf("{", index);
        break;
      }
    }
  }
  assert.notEqual(bodyStart, -1, `${name} must have a function body`);
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
    this.textContent = "";
    this.innerHTML = "";
  }

  append(...children) {
    this.children.push(...children);
  }

  replaceChildren(...children) {
    this.children = [...children];
  }

  addEventListener(name, callback) {
    this.listeners.set(name, callback);
  }

  dispatchEvent() { return true; }
}

class FakeDialog extends FakeElement {}

class FakeInput extends FakeElement {
  constructor(value = "") {
    super();
    this.value = value;
    this.checked = false;
    this.type = "";
    this.name = "";
  }
}

class FakeSelect extends FakeElement {
  constructor(value, label = "SDDC Manager") {
    super();
    this.value = value;
    this.selectedOptions = [{ textContent: label }];
  }
}

class FakeForm extends FakeElement {
  constructor() {
    super();
    this.candidates = new FakeElement();
    this.summary = new FakeElement();
    this.fingerprint = new FakeElement();
    this.fingerprintConfirm = new FakeInput();
    this.reviewSource = new FakeElement();
    this.reviewCount = new FakeElement();
    this.reviewPolicy = new FakeElement();
    this.elements = {
      csrf: new FakeInput("fixture-csrf"),
      source_type: new FakeSelect("sddc_manager", "Live inventory"),
      address: new FakeInput("sddc01.lab.example"),
      port: new FakeInput("443"),
      confirmed_fingerprint: new FakeInput("fixture-fingerprint"),
      username: new FakeInput("fixture-operator"),
      password: new FakeInput("fixture-password"),
      credential_vault_id: new FakeSelect(""),
      credential_entry_id: new FakeSelect(""),
      vault_id: new FakeSelect("7"),
    };
  }

  reset() {}

  querySelector(selector) {
    const elements = {
      "[data-vcf-vault-candidates]": this.candidates,
      "[data-vcf-vault-discovery-summary]": this.summary,
      "[data-vcf-vault-fingerprint]": this.fingerprint,
      "[data-vcf-vault-fingerprint-confirm]": this.fingerprintConfirm,
      "[data-vcf-vault-review-source]": this.reviewSource,
      "[data-vcf-vault-review-count]": this.reviewCount,
      "[data-vcf-vault-review-policy]": this.reviewPolicy,
    };
    if (selector === 'input[name="candidate_ids"]:checked') {
      return this.querySelectorAll('input[name="candidate_ids"]:checked')[0] || null;
    }
    return elements[selector] || null;
  }

  querySelectorAll(selector) {
    if (selector === 'input[name="candidate_ids"]:checked') {
      return this.candidates.children
        .map((label) => label.children[0])
        .filter((input) => input.checked);
    }
    if (selector === 'input[name="candidate_ids"]') {
      return this.candidates.children.map((label) => label.children[0]);
    }
    return [];
  }
}

function makeRuntime(responses) {
  const modal = new FakeDialog();
  const form = new FakeForm();
  const launchers = [new FakeElement()];
  const requests = [];
  let wizardOptions;
  const context = vm.createContext({
    document: {
      getElementById: (id) => (id === "vcf-vault-import-modal" ? modal : null),
      querySelector: (selector) => (selector === "[data-vcf-vault-import-form]" ? form : null),
      querySelectorAll: (selector) => (selector === "[data-vcf-vault-import-open]" ? launchers : []),
      createElement: (tagName) => {
        const element = new FakeElement();
        element.tagName = String(tagName || "").toUpperCase();
        return element;
      },
    },
    window: {
      AtlasoUiPatterns: {
        createWizard: (options) => {
          wizardOptions = options;
          return { markClean() {} };
        },
      },
      location: { assign() {} },
    },
    HTMLDialogElement: FakeDialog,
    HTMLFormElement: FakeForm,
    HTMLInputElement: FakeInput,
    managementUiPath: (path) => path,
    fetch: async (url, options) => {
      requests.push({ url, options });
      const payload = responses.shift();
      return {
        status: 200,
        ok: true,
        json: async () => payload,
      };
    },
  });

  vm.runInContext(
    `${functionSource("escapeHtml")}\n${functionSource("initializeVcfVaultImport")}\n` +
      "globalThis.initializeImport = initializeVcfVaultImport;",
    context,
  );
  context.initializeImport();
  return { context, form, requests, getWizardOptions: () => wizardOptions };
}

class CredentialOption extends FakeElement {
  constructor(label, value) {
    super();
    this.textContent = label;
    this.value = value;
  }
}

class CredentialSelect extends FakeElement {
  constructor(value = "") {
    super();
    this._value = value;
    this._selectedIndex = -1;
    this.disabled = false;
  }

  get value() {
    return this._selectedIndex >= 0 ? this.children[this._selectedIndex]?.value || "" : this._value;
  }

  set value(value) {
    this._value = String(value || "");
    this._selectedIndex = this.children.findIndex((option) => option.value === this._value);
  }

  get options() { return this.children; }

  get selectedIndex() { return this._selectedIndex; }

  set selectedIndex(index) {
    this._selectedIndex = Number(index);
    this._value = this.children[this._selectedIndex]?.value || "";
  }

  get selectedOptions() {
    return [this.children[this._selectedIndex] || this.children.find((option) => option.value === this._value) || this.children[0] || new CredentialOption("", "")];
  }

  append(...children) {
    super.append(...children);
    if (this._selectedIndex < 0 && this._value) this._selectedIndex = this.children.findIndex((option) => option.value === this._value);
  }

  replaceChildren(...children) {
    super.replaceChildren(...children);
    this._selectedIndex = children.length ? 0 : -1;
    this._value = children[0]?.value || "";
  }
}

class CredentialForm extends FakeElement {
  constructor() {
    super();
    this.elements = {
      address: new FakeInput(), username: new FakeInput(), password: new FakeInput(), port: new FakeInput(),
    };
    this.elements.namedItem = (name) => this.elements[name] || null;
  }
}

function makeCredentialPickerRuntime({ entries, pickerDataset = {} } = {}) {
  const data = new FakeElement();
  data.textContent = JSON.stringify([{
    id: 7,
    name: "Primary",
    entries: entries || [{
      id: 42, key: "vcf.operations.admin", display_name: "Operations · vc01.lab.example · admin",
      service_type: "vcf_operations", service_type_label: "Operations",
      username: "admin", uris: ["https://vc01.lab.example"],
    }],
  }]);
  const form = new CredentialForm();
  form.elements.product = new CredentialSelect("operations");
  const vaultSelect = new CredentialSelect("7");
  const entrySelect = new CredentialSelect();
  const status = new FakeElement();
  const picker = new FakeElement();
  picker.dataset = { addressField: "address", usernameField: "username", passwordField: "password", portField: "port", addressMode: "server", ...pickerDataset };
  picker.closest = () => form;
  picker.querySelector = (selector) => ({
    "[data-vcf-credential-vault]": vaultSelect,
    "[data-vcf-credential-entry]": entrySelect,
    "[data-vcf-credential-status]": status,
  })[selector] || null;
  const context = vm.createContext({
    document: { getElementById: () => data, querySelectorAll: () => [picker] },
    window: { setTimeout() {} },
    HTMLElement: FakeElement,
    HTMLFormElement: CredentialForm,
    HTMLInputElement: FakeInput,
    HTMLSelectElement: CredentialSelect,
    Option: CredentialOption,
    URL,
    Event: class Event {},
  });
  vm.runInContext(`${functionSource("vaultCredentialChoices")}; window.AtlasoVaultCredentials = { choices: vaultCredentialChoices }; ${functionSource("initializeVcfVaultCredentialPickers")}; initializeVcfVaultCredentialPickers();`, context);
  return { form, entrySelect, status, picker };
}

test("saved credential picker shows the readable name but preserves key and entry identity", () => {
  const { form, entrySelect, status } = makeCredentialPickerRuntime();
  const option = entrySelect.children.find((child) => child.value === "42");

  assert.ok(option);
  assert.equal(option.textContent, "Operations · HTTPS · Operations · vc01.lab.example · admin · admin — https://vc01.lab.example");
  assert.equal(option.title, "vcf.operations.admin");
  assert.equal(option.dataset.endpoint, "https://vc01.lab.example");
  entrySelect.value = "42";
  entrySelect.listeners.get("change")();
  assert.equal(entrySelect.value, "42");
  assert.equal(form.elements.address.value, "vc01.lab.example");
  assert.equal(form.elements.username.value, "admin");
  assert.match(status.textContent, /Using Primary \/ vcf\.operations\.admin\./);
});

test("saved credential picker leaves the placeholder selected and preserves the exact URI when re-ranked", () => {
  const entries = [
    { id: 42, key: "ops-admin", display_name: "Operations · vc01 · admin", service_type: "vcf_operations", service_type_label: "Operations", username: "admin", uris: ["https://vc01.lab.example", "https://vc02.lab.example"] },
    { id: 43, key: "vc-admin", display_name: "vCenter · vc03 · admin", service_type: "vcenter", service_type_label: "vCenter", username: "admin", uris: ["https://vc03.lab.example"] },
  ];
  const { form, entrySelect, status } = makeCredentialPickerRuntime({
    entries,
    pickerDataset: { serviceField: "product", serviceMap: JSON.stringify({ operations: "vcf_operations", vcenter: "vcenter" }) },
  });
  assert.equal(entrySelect.value, "", "a populated picker must not automatically select credentials");

  const secondUriIndex = entrySelect.children.findIndex((option) => option.dataset.endpoint === "https://vc02.lab.example");
  entrySelect.selectedIndex = secondUriIndex;
  entrySelect.listeners.get("change")();
  assert.equal(form.elements.address.value, "vc02.lab.example");
  const statusBeforeRerank = status.textContent;

  form.elements.product.value = "vcenter";
  form.elements.product.listeners.get("change")();

  assert.equal(entrySelect.value, "42");
  assert.equal(entrySelect.selectedOptions[0].dataset.endpoint, "https://vc02.lab.example");
  assert.equal(entrySelect.children[1].dataset.endpoint, "https://vc03.lab.example", "the mapped service should now rank first");
  assert.equal(status.textContent, statusBeforeRerank, "reranking must not reapply credentials or disturb the active form state");
  assert.equal(form.elements.address.value, "vc02.lab.example");
});

function discoveredPayload(candidates) {
  return {
    discovery: {
      scope: "<img src=x onerror=alert(1)>",
      skipped: { "Password missing or masked": 2 },
    },
    candidates,
  };
}

test("VCF vault inspect reports discovery coverage and renders safe URI repair guidance", async () => {
  const runtime = makeRuntime([
    discoveredPayload([
      {
        candidate_id: "candidate-1",
        key: "<script>alert(1)</script>",
        description: "<img src=x onerror=alert(1)>",
        service_type_label: "Operations",
        secret_type: "vcf_password",
        username: "<img src=x onerror=alert(2)>",
        resource_name: "vc01.lab.example",
        uris: ["https://vc01.lab.example"],
      },
      {
        candidate_id: "candidate-2",
        key: "credential-without-endpoint",
        description: "Imported account",
        secret_type: "esx_password",
        username: "root",
        resource_name: "unknown resource",
        uris: [],
      },
    ]),
  ]);
  const controller = { setError() {} };
  const result = await runtime.getWizardOptions().onNext({ controller, step: { id: "credentials" } });

  assert.equal(result, true);
  assert.equal(
    runtime.form.summary.textContent,
    "<img src=x onerror=alert(1)> 2 available. Password missing or masked: 2",
  );
  assert.equal(runtime.form.summary.innerHTML, "");
  assert.equal(runtime.form.candidates.children.length, 2);
  const firstChoice = runtime.form.candidates.children[0];
  assert.equal(firstChoice.tagName, "LABEL");
  assert.equal(firstChoice.className, "scope-choice");
  assert.equal(firstChoice.children[0].type, "checkbox");
  assert.equal(firstChoice.children[0].name, "candidate_ids");
  assert.equal(firstChoice.children[0].checked, true);
  assert.equal(firstChoice.children[1].className, "scope-choice-copy vcf-vault-candidate-copy");
  const verifiedCopy = runtime.form.candidates.children[0].children[1];
  assert.equal(verifiedCopy.innerHTML, "");
  assert.equal(verifiedCopy.children[0].children[0].textContent, "<script>alert(1)</script>");
  assert.equal(verifiedCopy.children[0].innerHTML, "");
  assert.equal(verifiedCopy.children[1].textContent, "Operations · VCF password · <img src=x onerror=alert(2)>");
  assert.equal(verifiedCopy.children[1].innerHTML, "");
  assert.equal(verifiedCopy.children[2].textContent, "<img src=x onerror=alert(1)>");
  assert.equal(verifiedCopy.children[2].innerHTML, "");
  assert.equal(verifiedCopy.children[3].textContent, "https://vc01.lab.example");
  assert.equal(verifiedCopy.children[3].innerHTML, "");
  assert.equal(runtime.form.candidates.children[1].children[1].children[1].textContent, "Unknown · ESX password · root");
  assert.match(
    runtime.form.candidates.children[1].children[1].children[3].textContent,
    /Add a URI in the Vault editor after import\./,
  );
});

test("VCF password candidates use the semantic password choice group and shared tile styles", () => {
  assert.match(importTemplate, /<fieldset class="scope-choice-fieldset"><legend>Passwords to import<\/legend>/);
  assert.match(importTemplate, /<div class="scope-choice-grid vcf-vault-candidate-list" data-vcf-vault-candidates><\/div><\/fieldset>/);
  assert.match(importTemplate, /<p class="muted" role="status" data-vcf-vault-discovery-summary><\/p><fieldset/);
  assert.match(appSource, /label\.className = "scope-choice"/);
  assert.match(appSource, /checkbox\.type = "checkbox"/);
  assert.match(appSource, /label\.append\(checkbox, copy\)/);
  assert.match(appCss, /\.scope-choice:has\(input:checked\)/);
  assert.match(appCss, /\.scope-choice:focus-within/);
  assert.match(appCss, /\.vcf-vault-candidate-list \.scope-choice/);
  assert.match(appCss, /\.vcf-vault-candidate-copy code,\s*\.vcf-vault-candidate-copy small\s*\{\s*overflow-wrap: anywhere;/);
  assert.match(appCss, /\.scope-choice-grid\s*\{[\s\S]*?grid-template-columns: repeat\(2, minmax\(0, 1fr\)\)/);
  assert.match(appCss, /@media \(max-width: 640px\)\s*\{[\s\S]*?\.scope-choice-grid\s*\{\s*grid-template-columns: 1fr;/);
});

test("VCF import source choices explain live versus retained deployment data before authentication", () => {
  assert.match(importTemplate, /value="sddc_manager">Live inventory<\/option>/);
  assert.match(importTemplate, /value="vcf_installer">Deployment passwords<\/option>/);
  assert.match(importTemplate, /data-vcf-vault-source-notice[\s\S]*?live inventory reads SDDC Manager credentials[\s\S]*?VCF Installer 9\.x or converted SDDC Manager 9\.1\.x[\s\S]*?Operations or Automation[\s\S]*?Missing or masked values are unavailable[\s\S]*?stale after rotations[\s\S]*?not a complete live inventory/);
});

test("VCF import review preserves deployment keys and retains live rotation policy", () => {
  const runtime = makeRuntime([]);
  const prepareReview = runtime.getWizardOptions().prepareReview;

  prepareReview();
  assert.match(runtime.form.reviewPolicy.textContent, /Live inventory imports may rotate matching existing keys/);
  runtime.form.elements.source_type.value = "vcf_installer";
  runtime.form.elements.source_type.selectedOptions[0].textContent = "Deployment passwords";
  prepareReview();
  assert.match(runtime.form.reviewSource.textContent, /Deployment passwords/);
  assert.equal(runtime.form.reviewPolicy.textContent, "Deployment-spec imports preserve the destination: existing keys are skipped, never rotated.");
});

test("VCF source fingerprint gate stays ahead of authentication for either source type", async () => {
  const runtime = makeRuntime([{ fingerprint: "sha256-fixture" }]);
  runtime.form.elements.source_type.value = "vcf_installer";
  runtime.form.elements.username.value = "";
  runtime.form.elements.password.value = "";
  const controller = { setError() {} };

  runtime.context.fetch = async (url, options) => {
    runtime.requests.push({ url, options });
    return { status: 409, ok: false, json: async () => ({ fingerprint: "sha256-fixture" }) };
  };
  assert.equal(await runtime.getWizardOptions().onNext({ controller, step: { id: "source" } }), "tls");
  const inspected = JSON.parse(runtime.requests[0].options.body);
  assert.equal(inspected.source_type, "vcf_installer");
  assert.equal(inspected.confirmed_fingerprint, "");
  assert.equal(inspected.username, "");
  assert.equal(inspected.password, "");
  assert.equal(runtime.form.fingerprint.textContent, "sha256-fixture");
});

test("VCF candidate rows distinguish accounts with the same resource and endpoint", async () => {
  const runtime = makeRuntime([
    discoveredPayload([
      {
        candidate_id: "admin-candidate",
        key: "vcf-vault-key",
        service_type_label: "vCenter",
        secret_type: "vcf_password",
        username: "administrator",
        resource_name: "vc01.lab.example",
        description: "VCENTER credential",
        uris: ["https://vc01.lab.example"],
      },
      {
        candidate_id: "audit-candidate",
        key: "vcf-vault-key",
        service_type_label: "Unknown",
        secret_type: "vcf_password",
        username: "audit",
        resource_name: "vc01.lab.example",
        description: "VCENTER credential",
        uris: ["https://vc01.lab.example"],
      },
    ]),
  ]);

  await runtime.getWizardOptions().onNext({ controller: { setError() {} }, step: { id: "credentials" } });

  const accountLabels = runtime.form.candidates.children.map((row) => row.children[1].children[1].textContent);
  assert.deepEqual(accountLabels, ["vCenter · VCF password · administrator", "Unknown · VCF password · audit"]);
  assert.deepEqual(
    runtime.form.candidates.children.map((row) => row.children[1].children[3].textContent),
    ["https://vc01.lab.example", "https://vc01.lab.example"],
  );
});

test("unknown VCF credential types use a readable fallback label", async () => {
  const runtime = makeRuntime([
    discoveredPayload([
      {
        candidate_id: "unknown-type",
        key: "candidate-key",
        secret_type: "constructor",
        username: "operator",
        description: "Other account",
        uris: [],
      },
    ]),
  ]);

  await runtime.getWizardOptions().onNext({ controller: { setError() {} }, step: { id: "credentials" } });

  assert.equal(runtime.form.candidates.children[0].children[1].children[1].textContent, "Unknown · Other credential · operator");
});

test("zero VCF candidates preserve the skip reason and block selection validation", async () => {
  const runtime = makeRuntime([
    {
      discovery: { scope: "Latest installer specification only.", skipped: { "Password masked": 1 } },
      candidates: [],
    },
  ]);
  const controller = { setError() {} };

  assert.equal(await runtime.getWizardOptions().onNext({ controller, step: { id: "credentials" } }), true);
  assert.equal(runtime.form.candidates.children.length, 0);
  assert.match(runtime.form.summary.textContent, /Latest installer specification only\./);
  assert.match(runtime.form.summary.textContent, /Password masked: 1/);
  const validation = runtime.getWizardOptions().validateStep({ step: { id: "selection" } });
  assert.equal(validation.ok, false);
  assert.equal(validation.message, "Select at least one password.");
});

test("VCF vault import submits only the candidate IDs the operator checked", async () => {
  const runtime = makeRuntime([
    discoveredPayload([
      { candidate_id: "selected-id", key: "vcf.vc01.admin", description: "Selected", uris: [] },
      { candidate_id: "unchecked-id", key: "vcf.vc02.admin", description: "Unselected", uris: [] },
    ]),
    { vault_id: 7 },
  ]);
  const controller = { setError() {} };
  await runtime.getWizardOptions().onNext({ controller, step: { id: "credentials" } });
  runtime.form.candidates.children[1].children[0].checked = false;

  const result = await runtime.getWizardOptions().onSubmit();
  const submitted = JSON.parse(runtime.requests[1].options.body);

  assert.deepEqual(submitted.candidate_ids, ["selected-id"]);
  assert.equal(submitted.vault_id, 7);
  assert.equal(result.ok, true);
  assert.equal(runtime.requests[1].url, "/vcf-helper/vault-import");
});
