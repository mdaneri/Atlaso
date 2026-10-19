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

class FakeClassList {
  values = new Set();

  add(value) { this.values.add(value); }
  remove(value) { this.values.delete(value); }
  toggle(value, force) {
    const enabled = force === undefined ? !this.values.has(value) : Boolean(force);
    if (enabled) this.values.add(value);
    else this.values.delete(value);
    return enabled;
  }
  contains(value) { return this.values.has(value); }
}

class FakeElement {
  constructor(name = "") {
    this.name = name;
    this.value = "";
    this.type = "text";
    this.checked = false;
    this.disabled = false;
    this.required = false;
    this.readOnly = false;
    this.textContent = "";
    this.innerHTML = "";
    this.classList = new FakeClassList();
    this.listeners = new Map();
    this.dataset = {};
    this.selectedOptions = [];
    this.children = [];
    this.attributes = {};
  }

  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  setAttribute(name, value) { this.attributes[name] = value; }
  removeAttribute(name) { delete this.attributes[name]; }

  addEventListener(name, callback) {
    const callbacks = this.listeners.get(name) || [];
    callbacks.push(callback);
    this.listeners.set(name, callbacks);
  }

  async dispatch(name, event = {}) {
    for (const callback of this.listeners.get(name) || []) {
      await callback({ currentTarget: this, ...event });
    }
  }
}

class FakeInput extends FakeElement {}
class FakeSelect extends FakeElement {
  get options() { return this.children; }
}
class FakeDialog extends FakeElement {}

class FakeForm extends FakeElement {
  constructor() {
    super();
    const names = [
      "csrf", "credential_source", "credential_mode", "vcenter_id", "vault_id", "entry_id", "uri_index",
      "confirmed_https_fingerprint", "expected_client_fingerprint", "hostname", "username", "password",
      "provider_id", "name", "cluster_id", "enrollment_method", "manual_provider_id", "manual_name",
      "manual_hostname", "manual_certificate_pem", "manual_description", "manual_enabled",
    ];
    this.elements = Object.fromEntries(names.map((name) => [name, name.includes("mode") || name.includes("provider")
      ? new FakeSelect(name)
      : new FakeInput(name)]));
    this.elements.credential_mode.value = "manual";
    this.elements.enrollment_method.value = "enroll";
    this.elements.manual_enabled.type = "checkbox";
    this.elements.credential_source.value = "manual";
    this.elements.csrf.value = "csrf-token";
    this.elements.vault_id.value = "0";
    this.elements.entry_id.value = "0";
    this.elements.uri_index.value = "0";
    this.elements.namedItem = (name) => this.elements[name] || null;
    this.endpoint = new FakeSelect("vault-entry");
    this.endpoint.value = "";
    this.endpoint.dataset = {};
    this.endpointField = new FakeElement();
    this.status = new FakeElement();
    this.tlsConfirm = new FakeInput("tls-confirm");
    this.tlsConfirm.type = "checkbox";
    this.tlsConfirmContainer = new FakeElement();
    this.tlsFingerprint = new FakeElement();
    this.client = new FakeElement();
    this.error = new FakeElement();
    this.review = new FakeElement();
    this.selectorMap = new Map([
      ["[data-vsphere-setup-method]", this.elements.enrollment_method],
      ["[data-vsphere-credential-mode]", this.elements.credential_mode],
      ["[data-vsphere-vault-entry]", this.endpoint],
      ["[data-vsphere-vault-field]", this.endpointField],
      ["[data-vsphere-credential-status]", this.status],
      ["[data-vsphere-tls-confirmation]", this.tlsConfirmContainer],
      ["[data-vsphere-tls-confirm]", this.tlsConfirm],
      ["[data-vsphere-tls-fingerprint]", this.tlsFingerprint],
      ["[data-vsphere-enrollment-client]", this.client],
      ["[data-atlaso-wizard-error]", this.error],
      ["[data-atlaso-resource-review]", this.review],
    ]);
  }

  querySelector(selector) { return this.selectorMap.get(selector) || null; }
  reset() {}
}

class FakeFormData {
  constructor(form) {
    this.values = new Map(Object.entries(form?.elements || {})
      .filter(([name, control]) => name !== "namedItem" && !control.disabled)
      .map(([name, control]) => [name, String(control.value ?? "")]));
  }

  set(name, value) { this.values.set(name, String(value)); }
  delete(name) { this.values.delete(name); }
  get(name) { return this.values.get(name) ?? null; }
  has(name) { return this.values.has(name); }
}

class FakeRow {
  constructor(data) { this.data = { ...data }; }
  getData() { return this.data; }
  async update(data) { Object.assign(this.data, data); }
  async delete() { this.deleted = true; }
}

class FakeTable {
  constructor(rows = []) { this.rows = new Map(rows.map((row) => [String(row.id), new FakeRow(row)])); }
  getRow(id) { return this.rows.get(String(id)); }
  async addRow(data) {
    const row = new FakeRow(data);
    this.rows.set(String(data.id), row);
    return row;
  }
}

function makeRuntime(respond, onSaved = null) {
  const form = new FakeForm();
  const dialog = new FakeDialog();
  const errors = [];
  const skipped = [];
  const shown = [];
  const page = new FakeElement();
  const resets = [];
  let options;
  const context = vm.createContext({
    HTMLFormElement: FakeForm,
    HTMLDialogElement: FakeDialog,
    HTMLInputElement: FakeInput,
    HTMLSelectElement: FakeSelect,
    FormData: FakeFormData,
    window: {
      addEventListener: (name, callback) => page.addEventListener(name, callback),
      AtlasoUiPatterns: {
        createWizard: (wizardOptions) => {
          options = wizardOptions;
          return {
            setSkippedSteps: (steps) => skipped.push([...steps]),
            setError: (message) => errors.push(message),
            showStep: (step, options) => shown.push({ step, options }),
            markClean() {},
            reset: () => { resets.push(true); form.reset(); },
          };
        },
      },
      location: { reload() { reloads.push(true); } },
    },
    atlasoGridWizardRequest: async (url, body) => respond(url, body),
    managementUiPath: (path) => path,
    openVsphereEnrollmentWizard() {},
    renderAtlasoWizardReview: (_form, items) => { form.reviewItems = items; },
  });
  const reloads = [];
  vm.runInContext(`${functionSource("initializeVsphereEnrollmentWizard")}; globalThis.initialize = initializeVsphereEnrollmentWizard;`, context);
  const wizard = context.initialize(form, dialog, null, onSaved);
  options.onOpen({ context: {} });
  return { form, wizard, options, errors, skipped, shown, page, resets, reloads };
}

test("manual enrollment probes without credentials and pins the exact observed fingerprint by checkbox", async () => {
  const requests = [];
  const runtime = makeRuntime(async (url, body) => {
    requests.push({ url, body });
    return { https_fingerprint: "AA:BB:CC", client_fingerprint: "11:22", subject: "vCenter KMIP", expires_at: "2030-01-01", cluster_id: "cluster-1" };
  });
  const { form, options, wizard } = runtime;
  form.elements.hostname.value = "vcsa.lab.example";
  form.elements.username.value = "administrator@vsphere.local";
  form.elements.password.value = "one-time-secret";
  form.elements.provider_id.value = "provider-1";
  form.elements.name.value = "Lab vCenter";
  form.elements.cluster_id.value = "cluster-1";

  assert.equal(await options.onNext({ controller: wizard, step: { id: "server" } }), true);
  assert.equal(requests[0].url, "/vsphere-key-providers/enrollment/probe");
  assert.equal(requests[0].body.get("credential_source"), "manual");
  assert.equal(requests[0].body.has("username"), false);
  assert.equal(requests[0].body.has("password"), false);
  assert.equal(requests[0].body.has("vault_id"), false);
  assert.equal(form.tlsFingerprint.textContent, "AA:BB:CC");

  form.tlsConfirm.checked = true;
  await form.tlsConfirm.dispatch("change");
  assert.equal(form.elements.confirmed_https_fingerprint.value, "AA:BB:CC");
  assert.equal(await options.onNext({ controller: wizard, step: { id: "target" } }), "review");
  assert.equal(requests[1].body.get("username"), "administrator@vsphere.local");
  assert.equal(requests[1].body.get("password"), "one-time-secret");
  assert.equal(form.elements.expected_client_fingerprint.value, "11:22");

  form.elements.hostname.value = "changed.lab.example";
  await form.elements.hostname.dispatch("input");
  assert.equal(form.elements.confirmed_https_fingerprint.value, "");
  assert.equal(form.elements.expected_client_fingerprint.value, "");
  assert.equal(form.tlsConfirm.checked, false);
  assert.equal(form.elements.username.value, "");
  assert.equal(form.elements.password.value, "");
  form.elements.password.value = "clear-on-close";
  options.onClose();
  assert.equal(form.elements.password.value, "");
});

test("Vault enrollment locks the saved URI host, skips Login, and never posts manual credentials", async () => {
  const requests = [];
  const runtime = makeRuntime(async (url, body) => {
    requests.push({ url, body });
    return url.endsWith("/probe")
      ? { https_fingerprint: "AA:BB:CC" }
      : { client_fingerprint: "11:22", subject: "vCenter KMIP", expires_at: "2030-01-01", cluster_id: "cluster-1" };
  });
  const { form, options, wizard, skipped } = runtime;
  form.elements.username.value = "stale-user";
  form.elements.password.value = "stale-password";
  form.elements.credential_mode.value = "vault";
  form.endpoint.value = "3|8|1";
  form.endpoint.selectedOptions = [{ dataset: { hostname: "vcsa.lab.example" } }];
  await form.elements.credential_mode.dispatch("change");
  assert.equal(form.elements.hostname.value, "vcsa.lab.example");
  assert.equal(form.elements.hostname.readOnly, true);
  assert.equal(form.elements.username.disabled, true);
  assert.equal(form.elements.password.value, "");
  assert.deepEqual(skipped.at(-1), ["manual_identity", "manual_certificate", "manual_state", "login"]);
  assert.equal(await options.onNext({ controller: wizard, step: { id: "credential" } }), true);
  assert.equal(await options.onNext({ controller: wizard, step: { id: "server" } }), true);
  assert.equal(requests[0].body.get("credential_source"), "vault");
  assert.equal(requests[0].body.get("vault_id"), "3");
  assert.equal(requests[0].body.get("entry_id"), "8");
  assert.equal(requests[0].body.get("uri_index"), "1");
  assert.equal(requests[0].body.has("username"), false);
  assert.equal(requests[0].body.has("password"), false);

  form.tlsConfirm.checked = true;
  await form.tlsConfirm.dispatch("change");
  form.elements.provider_id.value = "provider-1";
  form.elements.name.value = "Lab vCenter";
  form.elements.cluster_id.value = "cluster-1";
  assert.equal(await options.onNext({ controller: wizard, step: { id: "target" } }), "review");
  assert.equal(requests[1].body.get("vault_id"), "3");
  assert.equal(requests[1].body.has("username"), false);
  assert.equal(requests[1].body.has("password"), false);

  options.onClose();
  assert.equal(form.elements.password.value, "");
});

test("a stale TLS probe response cannot confirm a server whose address changed while it was pending", async () => {
  let resolveProbe;
  const runtime = makeRuntime(() => new Promise((resolve) => { resolveProbe = resolve; }));
  const { form, options, wizard } = runtime;
  form.elements.hostname.value = "old.lab.example";
  const pending = options.onNext({ controller: wizard, step: { id: "server" } });
  form.elements.hostname.value = "new.lab.example";
  await form.elements.hostname.dispatch("change");
  resolveProbe({ https_fingerprint: "AA:BB:CC" });
  assert.equal(await pending, false);
  assert.equal(form.elements.confirmed_https_fingerprint.value, "");
  assert.equal(form.tlsFingerprint.textContent, "Not inspected yet");
});

test("a stale client-certificate inspection cannot authorize a changed KMIP cluster", async () => {
  let resolveInspect;
  const runtime = makeRuntime(() => new Promise((resolve) => { resolveInspect = resolve; }));
  const { form, options, wizard } = runtime;
  form.elements.hostname.value = "vcsa.lab.example";
  form.elements.username.value = "administrator@vsphere.local";
  form.elements.password.value = "one-time-secret";
  form.elements.provider_id.value = "provider-1";
  form.elements.name.value = "Lab vCenter";
  form.elements.cluster_id.value = "cluster-1";
  const pending = options.onNext({ controller: wizard, step: { id: "target" } });
  form.elements.cluster_id.value = "cluster-2";
  await form.elements.cluster_id.dispatch("change");
  resolveInspect({ client_fingerprint: "11:22", subject: "vCenter KMIP", expires_at: "2030-01-01", cluster_id: "cluster-1" });
  assert.equal(await pending, false);
  assert.equal(form.elements.expected_client_fingerprint.value, "");
  assert.equal(form.client.textContent, "Client certificate has not been inspected.");
});

test("closing the wizard invalidates an in-flight probe and clears credentials", async () => {
  let resolveProbe;
  const runtime = makeRuntime(() => new Promise((resolve) => { resolveProbe = resolve; }));
  const { form, options, wizard } = runtime;
  form.elements.hostname.value = "vcsa.lab.example";
  form.elements.username.value = "administrator@vsphere.local";
  form.elements.password.value = "one-time-secret";
  const pending = options.onNext({ controller: wizard, step: { id: "server" } });
  options.onClose();
  resolveProbe({ https_fingerprint: "AA:BB:CC" });
  assert.equal(await pending, false);
  assert.equal(form.elements.password.value, "");
  assert.equal(form.elements.confirmed_https_fingerprint.value, "");
  assert.equal(form.tlsFingerprint.textContent, "Not inspected yet");
  assert.equal(form.tlsConfirmContainer.classList.contains("hidden"), true);
});

test("pagehide clears manual credentials and inspected trust before Back-cache restoration", async () => {
  const requests = [];
  const { form, options, wizard, page } = makeRuntime(async (url) => {
    requests.push(url);
    return {
      https_fingerprint: "AA:BB:CC", client_fingerprint: "11:22",
      subject: "vCenter KMIP", expires_at: "2030-01-01", cluster_id: "cluster-1",
    };
  });
  form.elements.hostname.value = "vcsa.lab.example";
  form.elements.username.value = "administrator@vsphere.local";
  form.elements.password.value = "request-only-password";
  await options.onNext({ controller: wizard, step: { id: "server" } });
  form.tlsConfirm.checked = true;
  await form.tlsConfirm.dispatch("change");
  await options.onNext({ controller: wizard, step: { id: "target" } });
  assert.equal(form.elements.expected_client_fingerprint.value, "11:22");

  await page.dispatch("pagehide", { persisted: true });
  assert.equal(form.elements.username.value, "");
  assert.equal(form.elements.password.value, "");
  assert.equal(form.elements.confirmed_https_fingerprint.value, "");
  assert.equal(form.elements.expected_client_fingerprint.value, "");
  assert.equal(form.tlsConfirm.checked, false);
  assert.equal(form.tlsFingerprint.textContent, "Not inspected yet");
  assert.equal(form.tlsConfirmContainer.classList.contains("hidden"), true);
  const result = await options.onSubmit({ controller: wizard });
  assert.equal(result.valid, false);
  assert.equal(requests.length, 2);
});

test("an inspection finishing after pagehide cannot restore approval state", async () => {
  let resolveInspect;
  const { form, options, wizard, page } = makeRuntime(() => new Promise((resolve) => {
    resolveInspect = resolve;
  }));
  form.elements.username.value = "administrator@vsphere.local";
  form.elements.password.value = "request-only-password";
  form.elements.confirmed_https_fingerprint.value = "AA:BB:CC";
  const pending = options.onNext({ controller: wizard, step: { id: "target" } });
  await page.dispatch("pagehide", { persisted: true });
  resolveInspect({ client_fingerprint: "11:22" });
  assert.equal(await pending, false);
  assert.equal(form.elements.expected_client_fingerprint.value, "");
  assert.equal(form.elements.username.value, "");
  assert.equal(form.elements.password.value, "");
});

test("changing login credentials invalidates client inspection but keeps the confirmed HTTPS pin", async () => {
  const runtime = makeRuntime(async () => ({
    https_fingerprint: "AA:BB:CC",
    client_fingerprint: "11:22",
    subject: "vCenter KMIP",
    expires_at: "2030-01-01",
    cluster_id: "cluster-1",
  }));
  const { form, options, wizard } = runtime;
  form.elements.hostname.value = "vcsa.lab.example";
  form.elements.username.value = "administrator@vsphere.local";
  form.elements.password.value = "one-time-secret";
  form.elements.provider_id.value = "provider-1";
  form.elements.name.value = "Lab vCenter";
  form.elements.cluster_id.value = "cluster-1";
  await options.onNext({ controller: wizard, step: { id: "server" } });
  form.tlsConfirm.checked = true;
  await form.tlsConfirm.dispatch("change");
  await options.onNext({ controller: wizard, step: { id: "target" } });
  assert.equal(form.elements.expected_client_fingerprint.value, "11:22");

  form.elements.password.value = "replacement-password";
  await form.elements.password.dispatch("input");
  assert.equal(form.elements.expected_client_fingerprint.value, "");
  assert.equal(form.elements.confirmed_https_fingerprint.value, "AA:BB:CC");
});

test("HTTPS certificate changes during inspection force a new probe and confirmation", async () => {
  const runtime = makeRuntime(async () => {
    throw new Error("The vCenter HTTPS fingerprint differs from the confirmed value.");
  });
  const { form, options, wizard, shown, errors } = runtime;
  form.elements.hostname.value = "vcsa.lab.example";
  form.elements.username.value = "administrator@vsphere.local";
  form.elements.password.value = "one-time-secret";
  form.elements.confirmed_https_fingerprint.value = "AA:BB:CC";

  assert.equal(await options.onNext({ controller: wizard, step: { id: "target" } }), false);
  assert.equal(shown.at(-1).step, "server");
  assert.equal(shown.at(-1).options.unlock, true);
  assert.equal(form.elements.confirmed_https_fingerprint.value, "");
  assert.equal(form.elements.username.value, "");
  assert.equal(form.elements.password.value, "");
  assert.match(errors.at(-1), /Probe it again/);
});

test("HTTPS identity changes during approval return to Server and clear request credentials", async () => {
  const runtime = makeRuntime(async () => {
    throw new Error("The vCenter HTTPS fingerprint differs from the confirmed value.");
  });
  const { form, options, wizard } = runtime;
  form.elements.hostname.value = "vcsa.lab.example";
  form.elements.username.value = "administrator@vsphere.local";
  form.elements.password.value = "one-time-secret";
  form.elements.confirmed_https_fingerprint.value = "AA:BB:CC";
  form.elements.expected_client_fingerprint.value = "11:22";

  const result = await options.onSubmit({ controller: wizard });
  assert.equal(result.valid, false);
  assert.equal(result.step, "server");
  assert.match(result.message, /Probe it again/);
  assert.equal(form.elements.confirmed_https_fingerprint.value, "");
  assert.equal(form.elements.expected_client_fingerprint.value, "");
  assert.equal(form.elements.username.value, "");
  assert.equal(form.elements.password.value, "");
});

test("unexpected authentication errors remain recoverable without discarding TLS confirmation", async () => {
  const runtime = makeRuntime(async () => { throw new Error("vCenter login was rejected."); });
  const { form, options, wizard, shown, errors } = runtime;
  form.elements.hostname.value = "vcsa.lab.example";
  form.elements.username.value = "administrator@vsphere.local";
  form.elements.password.value = "one-time-secret";
  form.elements.confirmed_https_fingerprint.value = "AA:BB:CC";

  assert.equal(await options.onNext({ controller: wizard, step: { id: "target" } }), false);
  assert.equal(shown.length, 0);
  assert.equal(form.elements.confirmed_https_fingerprint.value, "AA:BB:CC");
  assert.equal(form.elements.password.value, "one-time-secret");
  assert.equal(errors.at(-1), "vCenter login was rejected.");
});

test("client inspection with no fingerprint stays on Target instead of opening an empty Review", async () => {
  const runtime = makeRuntime(async () => ({ subject: "vCenter KMIP" }));
  const { form, options, wizard, shown } = runtime;
  form.elements.hostname.value = "vcsa.lab.example";
  form.elements.provider_id.value = "provider-1";
  form.elements.name.value = "Lab vCenter";
  form.elements.cluster_id.value = "cluster-1";

  assert.equal(await options.onNext({ controller: wizard, step: { id: "target" } }), false);
  assert.equal(shown.length, 0);
  assert.equal(form.elements.expected_client_fingerprint.value, "");
});

test("manual setup skips discovery and submits only the existing manual trust fields", async () => {
  const requests = [];
  const saved = [];
  const { form, options, wizard, skipped, reloads } = makeRuntime(async (url, body) => {
    requests.push({ url, body });
    return {
      trusted_vcenter: {
        id: "trusted-1", provider_id: "provider-1", provider_name: "Lab provider", name: "Manual vCenter",
        hostname: "vcsa.lab.example", enabled: true, certificate_count: 1, usable_certificate_count: 1,
      },
      certificates: [{ id: "certificate-1", provider_id: "provider-1", trusted_vcenter_id: "trusted-1", status: "valid" }],
    };
  }, (result) => saved.push(result));
  form.elements.enrollment_method.value = "manual";
  await form.elements.enrollment_method.dispatch("change");
  assert.deepEqual(skipped.at(-1), ["credential", "server", "tls", "login", "target"]);
  assert.equal(form.elements.password.disabled, true);
  assert.equal(form.elements.hostname.required, false);
  assert.equal(form.tlsConfirm.required, false);
  assert.equal(form.elements.manual_name.required, true);
  assert.equal(await options.onNext({ controller: wizard, step: { id: "method" } }), true);
  form.elements.manual_provider_id.value = "provider-1";
  form.elements.manual_name.value = "Manual vCenter";
  form.elements.manual_hostname.value = "vcsa.lab.example";
  form.elements.manual_certificate_pem.value = "public-certificate";
  form.elements.manual_description.value = "Lab trust";
  form.elements.manual_enabled.checked = true;
  form.elements.password.value = "must-not-be-submitted";
  form.elements.vault_id.value = "99";
  options.prepareReview();
  assert.equal(form.reviewItems[0].value(), "Configure manually");
  assert.equal((await options.onSubmit({ controller: wizard })).valid, true);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].url, "/vsphere-key-providers/trusted-vcenters");
  assert.deepEqual(Object.fromEntries(requests[0].body.values), {
    csrf: "csrf-token", provider_id: "provider-1", name: "Manual vCenter", hostname: "vcsa.lab.example",
    certificate_pem: "public-certificate", description: "Lab trust", enabled: "on",
  });
  assert.equal(saved[0].resource.id, "trusted-1");
  assert.equal(saved[0].payload.certificates[0].id, "certificate-1");
  assert.deepEqual(reloads, []);
});

test("enrollment saves the authoritative server row in place without reloading", async () => {
  const saved = [];
  const resource = {
    id: "trusted-2", provider_id: "provider-1", provider_name: "Lab provider", name: "Enrolled vCenter",
    hostname: "vcsa.lab.example", enabled: true, certificate_count: 1, usable_certificate_count: 1,
  };
  const { form, options, wizard, reloads } = makeRuntime(async (url, body) => {
    assert.equal(url, "/vsphere-key-providers/enrollment/approve");
    assert.equal(body.get("confirmed_https_fingerprint"), "AA:BB:CC");
    assert.equal(body.get("expected_client_fingerprint"), "11:22");
    return { trusted_vcenter: resource, certificates: [{ id: "certificate-2", status: "valid" }] };
  }, (result) => saved.push(result));
  form.elements.provider_id.value = "provider-1";
  form.elements.name.value = "Enrolled vCenter";
  form.elements.hostname.value = "vcsa.lab.example";
  form.elements.cluster_id.value = "cluster-1";
  form.elements.confirmed_https_fingerprint.value = "AA:BB:CC";
  form.elements.expected_client_fingerprint.value = "11:22";

  assert.equal((await options.onSubmit({ controller: wizard })).valid, true);
  assert.equal(saved[0].resource, resource);
  assert.equal(saved[0].payload.certificates[0].id, "certificate-2");
  assert.deepEqual(reloads, []);
});

test("a completed enrollment updates the grid without overwriting a later wizard session", async () => {
  let resolveApproval;
  const saved = [];
  const { form, options, wizard } = makeRuntime(() => new Promise((resolve) => { resolveApproval = resolve; }), (result) => saved.push(result));
  form.elements.provider_id.value = "provider-1";
  form.elements.name.value = "First vCenter";
  form.elements.hostname.value = "first.lab.example";
  form.elements.cluster_id.value = "cluster-1";
  form.elements.confirmed_https_fingerprint.value = "AA:BB:CC";
  form.elements.expected_client_fingerprint.value = "11:22";

  const pending = options.onSubmit({ controller: wizard });
  options.onOpen({ context: { id: "new-row", is_new: true } });
  form.elements.name.value = "Second vCenter in progress";
  resolveApproval({
    trusted_vcenter: {
      id: "trusted-3", provider_id: "provider-1", provider_name: "Lab provider", name: "First vCenter",
      hostname: "first.lab.example", enabled: true, certificate_count: 1, usable_certificate_count: 1,
    },
    certificates: [],
  });

  assert.equal((await pending).valid, true);
  assert.equal(saved.length, 1);
  assert.equal(saved[0].resource.name, "First vCenter");
  assert.equal(form.elements.name.value, "Second vCenter in progress");
});

test("a stale TLS approval failure cannot clear a later wizard session", async () => {
  let rejectApproval;
  const { form, options, wizard } = makeRuntime(() => new Promise((_resolve, reject) => { rejectApproval = reject; }));
  form.elements.provider_id.value = "provider-1";
  form.elements.name.value = "First vCenter";
  form.elements.hostname.value = "first.lab.example";
  form.elements.cluster_id.value = "cluster-1";
  form.elements.username.value = "first-user";
  form.elements.password.value = "first-password";
  form.elements.confirmed_https_fingerprint.value = "AA:BB:CC";
  form.elements.expected_client_fingerprint.value = "11:22";

  const pending = options.onSubmit({ controller: wizard });
  options.onOpen({ context: { id: "new-row", is_new: true } });
  form.elements.name.value = "Second vCenter in progress";
  form.elements.hostname.value = "second.lab.example";
  form.elements.username.value = "second-user";
  form.elements.password.value = "second-password";
  form.elements.confirmed_https_fingerprint.value = "DD:EE:FF";
  rejectApproval(new Error("The vCenter HTTPS fingerprint differs from the confirmed value."));

  assert.equal((await pending).valid, true);
  assert.equal(form.elements.name.value, "Second vCenter in progress");
  assert.equal(form.elements.hostname.value, "second.lab.example");
  assert.equal(form.elements.username.value, "second-user");
  assert.equal(form.elements.password.value, "second-password");
  assert.equal(form.elements.confirmed_https_fingerprint.value, "DD:EE:FF");
});

test("the enrollment callback inserts authoritative vCenter, certificate, and provider rows", async () => {
  const targetSelect = new FakeSelect();
  const vcenterTable = new FakeTable();
  const certificateTable = new FakeTable();
  const providerTable = new FakeTable([{
    id: "provider-1", name: "Stale provider name", trusted_vcenter_count: 0, certificate_count: 0, usable_certificate_count: 0,
  }]);
  const context = vm.createContext({
    HTMLSelectElement: FakeSelect,
    document: { createElement: () => new FakeElement() },
  });
  vm.runInContext(`async ${functionSource("syncVsphereEnrollmentResult")}; globalThis.sync = syncVsphereEnrollmentResult;`, context);
  const resource = {
    id: "trusted-4", provider_id: "provider-1", provider_name: "Lab provider", name: "vCenter one",
    hostname: "vcsa.lab.example", enabled: true, certificate_count: 1, usable_certificate_count: 1,
  };
  const certificate = { id: "certificate-4", provider_id: "provider-1", trusted_vcenter_id: "trusted-4", status: "valid" };
  const upsertOption = (select, value, label) => {
    if (!select) return;
    let option = select.options.find((item) => item.value === value);
    if (!option) {
      option = new FakeElement();
      option.value = value;
      select.append(option);
    }
    option.textContent = label;
  };

  await context.sync({
    payload: {
      trusted_vcenter: resource,
      provider: { id: "provider-1", name: "Authoritative provider name", trusted_vcenter_count: 1, certificate_count: 1, usable_certificate_count: 1 },
      certificates: [certificate],
    },
    resource,
    vcenterTable,
    certificateTable,
    providerTable,
    upsertOption,
    certificateTargetSelect: targetSelect,
  });

  assert.equal(vcenterTable.getRow(resource.id).getData().name, "vCenter one");
  assert.equal(certificateTable.getRow(certificate.id).getData().status, "valid");
  assert.equal(providerTable.getRow("provider-1").getData().name, "Authoritative provider name");
  assert.deepEqual(
    [providerTable.getRow("provider-1").getData().trusted_vcenter_count,
      providerTable.getRow("provider-1").getData().certificate_count,
      providerTable.getRow("provider-1").getData().usable_certificate_count],
    [1, 1, 1],
  );
  assert.equal(targetSelect.options[0].textContent, "Lab provider / vCenter one");
});

test("provider option refresh keeps only enabled providers for enrollment and preserves valid selections", () => {
  const select = new FakeSelect();
  select.value = "provider-2";
  const context = vm.createContext({
    HTMLSelectElement: FakeSelect,
    document: { createElement: () => new FakeElement() },
  });
  vm.runInContext(`${functionSource("syncVsphereProviderSelect")}; globalThis.sync = syncVsphereProviderSelect;`, context);
  const providers = [
    { id: "provider-1", name: "First", enabled: true },
    { id: "provider-2", name: "Second renamed", enabled: true },
    { id: "provider-3", name: "Disabled", enabled: false },
  ];

  context.sync(select, providers, true);
  assert.deepEqual(select.options.map((option) => [option.value, option.textContent]), [
    ["provider-1", "First"], ["provider-2", "Second renamed"],
  ]);
  assert.equal(select.value, "provider-2");

  select.value = "provider-3";
  context.sync(select, providers, true);
  assert.equal(select.value, "provider-1");
  context.sync(select, providers, false);
  assert.deepEqual(select.options.map((option) => option.value), ["provider-1", "provider-2", "provider-3"]);
});

test("switching setup methods invalidates pending discovery and clears credentials and inspected trust", async () => {
  let resolveProbe;
  const { form, options, wizard, skipped, resets } = makeRuntime(() => new Promise((resolve) => { resolveProbe = resolve; }));
  const pending = options.onNext({ controller: wizard, step: { id: "server" } });
  form.elements.password.value = "request-only";
  form.elements.enrollment_method.value = "manual";
  await form.elements.enrollment_method.dispatch("change");
  resolveProbe({ https_fingerprint: "AA:BB:CC" });
  assert.equal(await pending, false);
  assert.equal(form.elements.password.value, "");
  assert.equal(form.elements.confirmed_https_fingerprint.value, "");
  form.elements.manual_certificate_pem.value = "public-certificate";
  form.elements.enrollment_method.value = "enroll";
  await form.elements.enrollment_method.dispatch("change");
  assert.equal(form.elements.manual_certificate_pem.value, "public-certificate");
  assert.equal(form.elements.manual_name.required, false);
  assert.equal(form.elements.manual_name.disabled, true);
  assert.equal(form.elements.password.required, true);
  assert.equal(resets.length, 2);
  assert.deepEqual(skipped.at(-1), ["manual_identity", "manual_certificate", "manual_state"]);
});

test("resetting branch navigation retains entered identity details and manual public trust", async () => {
  const { form } = makeRuntime(async () => ({}));
  form.elements.manual_name.value = "Unsaved vCenter";
  form.elements.manual_description.value = "Keep these details";
  form.elements.manual_enabled.checked = true;
  form.elements.manual_certificate_pem.value = "public-certificate";
  form.elements.password.value = "request-only-secret";
  form.reset = () => {
    for (const name of ["manual_name", "manual_description", "manual_certificate_pem"]) form.elements[name].value = "";
    form.elements.manual_enabled.checked = false;
  };
  form.elements.enrollment_method.value = "manual";
  await form.elements.enrollment_method.dispatch("change");
  assert.equal(form.elements.manual_name.value, "Unsaved vCenter");
  assert.equal(form.elements.manual_description.value, "Keep these details");
  assert.equal(form.elements.manual_enabled.checked, true);
  assert.equal(form.elements.manual_certificate_pem.value, "public-certificate");
  assert.equal(form.elements.password.value, "");
});

test("refreshing an existing trusted vCenter stays in enrollment and skips the setup-method step", async () => {
  const { form, options, wizard, skipped, resets } = makeRuntime(async () => ({}));
  options.onOpen({ context: { id: "existing-trust", provider_id: "provider-1", name: "Existing", hostname: "vcsa.lab.example" } });
  assert.equal(form.elements.enrollment_method.disabled, true);
  assert.deepEqual(skipped.at(-1), ["manual_identity", "manual_certificate", "manual_state", "method"]);
  form.elements.enrollment_method.value = "manual";
  await form.elements.enrollment_method.dispatch("change");
  assert.equal(form.elements.manual_name.disabled, true);
  assert.equal(form.elements.enrollment_method.value, "enroll");
  assert.equal(resets.length, 0);
  assert.equal((await options.onSubmit({ controller: wizard })).valid, false);
  assert.equal(form.elements.vcenter_id.value, "existing-trust");
});

test("the grid add control opens method selection while Edit retains the existing resource wizard", async () => {
  const element = new FakeElement();
  const form = new FakeForm();
  const dialog = new FakeDialog();
  const launcher = new FakeElement();
  const added = [];
  const edited = [];
  const errorStatus = new FakeElement();
  errorStatus.textContent = "Provider still has dependencies.";
  errorStatus.classList.add("error");
  const context = vm.createContext({
    HTMLElement: FakeElement, HTMLFormElement: FakeForm, HTMLDialogElement: FakeDialog,
    HTMLInputElement: FakeInput, HTMLButtonElement: FakeElement,
    document: {
      getElementById: (id) => id === "grid" ? element : dialog,
      querySelector: (selector) => selector === "form" ? form : selector === "#action-error" ? errorStatus : null,
    },
    window: { AtlasoUiPatterns: {
      createGrid: () => ({ table: {} }),
      createWizard: () => ({ open: (options) => edited.push(options) }),
    } },
  });
  vm.runInContext(`${functionSource("initializeAtlasoResourceWizard")}; globalThis.initialize = initializeAtlasoResourceWizard;`, context);
  const newRow = { is_new: true };
  context.initialize({
    elementId: "grid", dialogId: "dialog", formSelector: "form", rows: [], newRow,
    options: { columns: [] }, actionErrorSelector: "#action-error", openCreate: (options) => added.push(options),
  });
  await element.dispatch("click", { target: { closest: () => launcher } });
  assert.equal(added.length, 1);
  assert.equal(added[0].data, newRow);
  assert.equal(added[0].launcher, launcher);
  assert.equal(edited.length, 0);
  const existing = { id: "existing-trust" };
  element.atlasoWizardOpen(existing, launcher);
  assert.equal(edited.length, 1);
  assert.equal(edited[0].context, existing);
  assert.equal(errorStatus.textContent, "");
  assert.equal(errorStatus.classList.contains("hidden"), true);
  assert.equal(errorStatus.classList.contains("error"), false);
  assert.equal(added.length, 1);
});

test("a successful provider deletion retry clears the prior recoverable error", async () => {
  const element = new FakeElement();
  element.dataset = { fallbackId: "fallback", csrf: "csrf-token" };
  const form = new FakeForm();
  const dialog = new FakeDialog();
  const errorStatus = new FakeElement();
  const row = new FakeRow({ id: "provider-1", name: "Lab provider", enabled: false });
  let gridOptions;
  let attempts = 0;
  const context = vm.createContext({
    HTMLElement: FakeElement, HTMLFormElement: FakeForm, HTMLDialogElement: FakeDialog,
    HTMLInputElement: FakeInput, HTMLButtonElement: FakeElement, HTMLSelectElement: FakeSelect,
    FormData: FakeFormData,
    Error,
    document: {
      getElementById: (id) => id === "grid" ? element : id === "dialog" ? dialog : null,
      querySelector: (selector) => selector === "form" ? form : selector === "#provider-error" ? errorStatus : null,
      createElement: () => new FakeElement(),
    },
    window: { AtlasoUiPatterns: {
      createGrid: (options) => { gridOptions = options; return { table: { getRow: () => row } }; },
      createWizard: () => ({ open() {} }),
    } },
    requestConfirmation: async () => true,
    atlasoGridWizardRequest: async () => {
      attempts += 1;
      if (attempts === 1) throw new Error("Apply the disabled and detached provider state before deletion.");
      return {};
    },
    showTransientGridStatus() {},
  });
  vm.runInContext(`${functionSource("initializeAtlasoResourceWizard")}; globalThis.initialize = initializeAtlasoResourceWizard;`, context);
  context.initialize({
    elementId: "grid", dialogId: "dialog", formSelector: "form", rows: [{ id: "provider-1" }],
    includeNewRow: false, resourceName: "provider", options: { columns: [] },
    actionErrorSelector: "#provider-error", deleteResource: true, deleteUrl: (id) => `/providers/${id}/delete`,
    deleteConfirmation: () => ({ title: "Delete provider?", message: "Confirm", confirmLabel: "Delete", tone: "danger" }),
  });

  await gridOptions.rowActions[1].action(null, row);
  assert.equal(errorStatus.textContent, "Apply the disabled and detached provider state before deletion.");
  assert.equal(errorStatus.classList.contains("hidden"), false);
  assert.equal(row.deleted, undefined);

  await gridOptions.rowActions[1].action(null, row);
  assert.equal(errorStatus.textContent, "");
  assert.equal(errorStatus.classList.contains("hidden"), true);
  assert.equal(row.deleted, true);
});

test("the enrollment launcher starts existing refreshes on Credential and new setup on Method", () => {
  const openings = [];
  const context = vm.createContext({ controller: { open: (options) => openings.push(options) } });
  vm.runInContext(`let vsphereEnrollmentWizard = controller; ${functionSource("openVsphereEnrollmentWizard")}; globalThis.openEnrollment = openVsphereEnrollmentWizard;`, context);
  const existing = { id: "existing-trust" };
  context.openEnrollment(existing);
  assert.equal(openings[0].step, "credential");
  assert.equal(openings[0].highestStep, "credential");
  assert.equal(openings[0].context, existing);
  context.openEnrollment({ id: "synthetic-new-row", is_new: true });
  assert.equal(openings[1].step, "method");
  assert.equal(openings[1].highestStep, "method");
  context.openEnrollment();
  assert.equal(openings[2].step, "method");
});

test("health icons preserve literal state labels and keep configured runtime neutral", () => {
  const context = vm.createContext({ document: { createElement: () => new FakeElement() } });
  vm.runInContext(`${functionSource("vsphereHealthStatusFormatter")}; globalThis.format = vsphereHealthStatusFormatter;`, context);
  for (const value of ["ready", "configured", "needs attention", "not reported", "__proto__", '<img src=x onerror="bad()">']) {
    const badge = context.format({ getValue: () => value });
    assert.equal(badge.children[1].textContent, value);
    assert.equal(badge.children[0].attributes["aria-hidden"], "true");
    assert.equal(badge.innerHTML, "");
    if (value === "configured" || value === "not reported") assert.match(badge.className, /muted/);
  }
});

test("key-count icons distinguish unavailable evidence from an observed zero", () => {
  const context = vm.createContext({ document: {
    createElement: () => new FakeElement(), createElementNS: () => new FakeElement(),
  } });
  vm.runInContext(`${functionSource("appendButtonIcon")}\n${functionSource("vsphereKeyCountFormatter")}; globalThis.format = vsphereKeyCountFormatter;`, context);
  for (const value of [null, undefined]) {
    const badge = context.format({ getValue: () => value, getField: () => "total_count" });
    assert.equal(badge.textContent, "Not reported");
    assert.equal(badge.children.length, 0);
  }
  for (const value of [0, 2]) {
    const badge = context.format({ getValue: () => value, getField: () => "active_count" });
    assert.equal(badge.children[1].textContent, String(value));
    assert.equal(badge.children[0].attributes["aria-hidden"], "true");
    assert.equal(badge.classList.contains("active"), true);
  }
});

test("health badges preserve the service-runtime good, warning, and unknown states", () => {
  const context = vm.createContext({ document: { createElement: () => new FakeElement() } });
  vm.runInContext(`${functionSource("vsphereHealthStatusFormatter")}; globalThis.format = vsphereHealthStatusFormatter;`, context);
  for (const [value, tone, symbol] of [
    ["live", "good", "✓"], ["running", "warn", "!"], ["stopped", "warn", "!"],
    ["disabled", "muted", "○"], ["unknown", "muted", "?"], ["pending", "warn", "!"],
  ]) {
    const badge = context.format({ getValue: () => value });
    assert.equal(badge.className, `status-pill vsphere-health-badge ${tone}`);
    assert.equal(badge.children[0].textContent, symbol);
    assert.equal(badge.children[1].textContent, value);
  }
});
