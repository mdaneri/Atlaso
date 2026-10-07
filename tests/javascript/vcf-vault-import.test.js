const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const appSource = fs.readFileSync("atlaso/app/static/app.js", "utf8");

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
    this.elements = {
      csrf: new FakeInput("fixture-csrf"),
      source_type: new FakeSelect("sddc_manager"),
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
      createElement: () => new FakeElement(),
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
        resource_name: "vc01.lab.example",
        uris: ["https://vc01.lab.example"],
      },
      {
        candidate_id: "candidate-2",
        key: "credential-without-endpoint",
        description: "Imported account",
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
  const verifiedCopy = runtime.form.candidates.children[0].children[1];
  assert.match(verifiedCopy.innerHTML, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.match(verifiedCopy.innerHTML, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.equal(verifiedCopy.children[0].textContent, "https://vc01.lab.example");
  assert.equal(verifiedCopy.children[0].innerHTML, "");
  assert.match(
    runtime.form.candidates.children[1].children[1].children[0].textContent,
    /Add a URI in the Vault editor after import\./,
  );
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
