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
  }

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
class FakeSelect extends FakeElement {}
class FakeDialog extends FakeElement {}

class FakeForm extends FakeElement {
  constructor() {
    super();
    const names = [
      "csrf", "credential_source", "credential_mode", "vcenter_id", "vault_id", "entry_id", "uri_index",
      "confirmed_https_fingerprint", "expected_client_fingerprint", "hostname", "username", "password",
      "provider_id", "name", "cluster_id",
    ];
    this.elements = Object.fromEntries(names.map((name) => [name, name.includes("mode") || name.includes("provider")
      ? new FakeSelect(name)
      : new FakeInput(name)]));
    this.elements.credential_mode.value = "manual";
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
    this.values = new Map(Object.entries(form.elements)
      .filter(([name, control]) => name !== "namedItem" && !control.disabled)
      .map(([name, control]) => [name, String(control.value ?? "")]));
  }

  set(name, value) { this.values.set(name, String(value)); }
  delete(name) { this.values.delete(name); }
  get(name) { return this.values.get(name) ?? null; }
  has(name) { return this.values.has(name); }
}

function makeRuntime(respond) {
  const form = new FakeForm();
  const dialog = new FakeDialog();
  const errors = [];
  const skipped = [];
  const shown = [];
  const page = new FakeElement();
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
          };
        },
      },
      location: { reload() {} },
    },
    atlasoGridWizardRequest: async (url, body) => respond(url, body),
    managementUiPath: (path) => path,
    openVsphereEnrollmentWizard() {},
    renderAtlasoWizardReview: (_form, items) => { form.reviewItems = items; },
  });
  vm.runInContext(`${functionSource("initializeVsphereEnrollmentWizard")}; globalThis.initialize = initializeVsphereEnrollmentWizard;`, context);
  const wizard = context.initialize(form, dialog);
  options.onOpen({ context: {} });
  return { form, wizard, options, errors, skipped, shown, page };
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
  assert.deepEqual(skipped.at(-1), ["login"]);
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
