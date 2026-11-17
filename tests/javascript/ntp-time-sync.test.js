const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const appSource = fs.readFileSync("atlaso/app/static/app.js", "utf8");

function functionSource(name) {
  const start = appSource.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must exist in app.js`);
  let argumentDepth = 0;
  let bodyStart = -1;
  for (let index = start; index < appSource.length; index += 1) {
    if (appSource[index] === "(") argumentDepth += 1;
    if (appSource[index] === ")") argumentDepth -= 1;
    if (appSource[index] === "{" && argumentDepth === 0) {
      bodyStart = index;
      break;
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
    this.hidden = false;
    this.disabled = false;
    this.value = "";
    this.listeners = new Map();
    this.dataset = {};
  }

  addEventListener(name, callback) {
    const listeners = this.listeners.get(name) || [];
    listeners.push(callback);
    this.listeners.set(name, listeners);
  }

  emit(name, event = {}) {
    for (const listener of this.listeners.get(name) || []) listener(event);
  }
}

class FakeForm {
  constructor(elements) {
    this.elements = elements;
    this.dataset = {};
    this.listeners = new Map();
  }

  addEventListener(name, callback) {
    const listeners = this.listeners.get(name) || [];
    listeners.push(callback);
    this.listeners.set(name, listeners);
  }

  emit(name, event = {}) {
    for (const listener of this.listeners.get(name) || []) listener(event);
  }

  querySelector(selector) {
    return this.elements[selector] || null;
  }
}

const context = vm.createContext({
  HTMLElement: FakeElement,
  HTMLInputElement: FakeElement,
  HTMLFormElement: FakeForm,
  HTMLSelectElement: FakeElement,
  Number,
  String,
  updateNtpSettingsPreview: () => {},
  updateNtpValidation: () => {},
});
vm.runInContext(
  [
    functionSource("updateNtpTimeSourceControl"),
    functionSource("updateNtpClockDesiredMode"),
    functionSource("initializeNtpSettings"),
    functionSource("formatNTPsecSourceHealthSection"),
    functionSource("formatNTPsecSourceHealthPayload"),
    functionSource("classifyNTPsecSourceHealth"),
    "globalThis.updateNtpTimeSourceControl = updateNtpTimeSourceControl;",
    "globalThis.updateNtpClockDesiredMode = updateNtpClockDesiredMode;",
    "globalThis.initializeNtpSettings = initializeNtpSettings;",
    "globalThis.formatNTPsecSourceHealthPayload = formatNTPsecSourceHealthPayload;",
    "globalThis.classifyNTPsecSourceHealth = classifyNTPsecSourceHealth;",
  ].join("\n"),
  context,
);

test("NTP server mode disables the source selector and preserves its saved choice", () => {
  const timeSourceSelect = new FakeElement();
  const preservedTimeSource = new FakeElement();
  const clientHelp = new FakeElement();
  const serverReason = new FakeElement();
  const form = new FakeForm({
    "[data-time-source-select]": timeSourceSelect,
    "[data-time-source-preserved]": preservedTimeSource,
    "[data-time-source-client-help]": clientHelp,
    "[data-time-source-server-reason]": serverReason,
  });

  context.updateNtpTimeSourceControl(form, false, "vmware_tools");
  assert.equal(timeSourceSelect.disabled, false);
  assert.equal(preservedTimeSource.disabled, true);
  assert.equal(clientHelp.hidden, false);
  assert.equal(serverReason.hidden, true);

  context.updateNtpTimeSourceControl(form, true, "vmware_tools");
  assert.equal(timeSourceSelect.value, "vmware_tools");
  assert.equal(timeSourceSelect.disabled, true);
  assert.equal(preservedTimeSource.value, "vmware_tools");
  assert.equal(preservedTimeSource.disabled, false);
  assert.equal(clientHelp.hidden, true);
  assert.equal(serverReason.hidden, false);

  context.updateNtpTimeSourceControl(form, false, "vmware_tools");
  assert.equal(timeSourceSelect.value, "vmware_tools");
  assert.equal(timeSourceSelect.disabled, false);
  assert.equal(preservedTimeSource.disabled, true);
});

test("autosaved NTP server toggle changes source controls in place", () => {
  const enabledInput = new FakeElement();
  const timeSourceSelect = new FakeElement();
  const preservedTimeSource = new FakeElement();
  const clientHelp = new FakeElement();
  const serverReason = new FakeElement();
  const desiredMode = new FakeElement();
  desiredMode.textContent = "NTP client";
  const form = new FakeForm({
    'input[name="enabled"]': enabledInput,
    "[data-time-source-select]": timeSourceSelect,
    "[data-time-source-preserved]": preservedTimeSource,
    "[data-time-source-client-help]": clientHelp,
    "[data-time-source-server-reason]": serverReason,
  });
  const root = {
    querySelectorAll: () => [form],
    querySelector: () => desiredMode,
  };

  context.initializeNtpSettings(root);
  timeSourceSelect.value = "vmware_tools";
  timeSourceSelect.emit("change");
  enabledInput.checked = true;
  enabledInput.emit("change");

  assert.equal(timeSourceSelect.disabled, true);
  assert.equal(preservedTimeSource.value, "vmware_tools");
  assert.equal(preservedTimeSource.disabled, false);
  assert.equal(clientHelp.hidden, true);
  assert.equal(serverReason.hidden, false);

  form.emit("atlaso:autosave-success", {
    detail: { time_mode: "ntp_server", time_source: "vmware_tools" },
  });
  assert.equal(desiredMode.textContent, "NTP/NTS server");
  enabledInput.checked = false;
  enabledInput.emit("change");
  assert.equal(timeSourceSelect.disabled, false);
  assert.equal(preservedTimeSource.disabled, true);
  assert.equal(timeSourceSelect.value, "vmware_tools");

  form.emit("atlaso:autosave-success", {
    detail: { time_mode: "vmware_tools", time_source: "vmware_tools" },
  });
  assert.equal(desiredMode.textContent, "VMware Tools");
});

test("NTP health requires synchronization health and leaves dry runs neutral", () => {
  let health = context.classifyNTPsecSourceHealth(true, {
    ok: true,
    status: { synchronization: { healthy: true } },
  });
  assert.equal(health.text, "healthy");
  assert.equal(health.state, "good");

  health = context.classifyNTPsecSourceHealth(true, {
    ok: true,
    status: { synchronization: { healthy: false } },
  });
  assert.equal(health.text, "needs attention");
  assert.equal(health.state, "warn");

  health = context.classifyNTPsecSourceHealth(true, {
    ok: true,
    dry_run: true,
    status: { synchronization: { healthy: false } },
  });
  assert.equal(health.text, "dry-run");
  assert.equal(health.state, "muted");

  health = context.classifyNTPsecSourceHealth(true, { ok: true, status: {} });
  assert.equal(health.text, "needs attention");
  assert.equal(health.state, "warn");
});

test("VMware Tools health ignores NTP probe errors but requires reported synchronization health", () => {
  const failedNtpProbes = {
    peers: { returncode: 1, stderr: "ntpq is unavailable" },
    variables: { returncode: 1, stderr: "ntpq is unavailable" },
    nts: { returncode: 1, stderr: "ntpq is unavailable" },
  };
  const payload = {
    ok: true,
    status: {
      mode: "vmware_tools",
      selected_controller: {
        name: "vmware_tools",
        active: true,
        detail: "VMware Tools time synchronization is enabled.",
      },
      daemon_conflicts: {},
      synchronization: {
        state: "synchronized",
        healthy: true,
        detail: "VMware Tools time synchronization is healthy.",
      },
      ...failedNtpProbes,
    },
  };

  let health = context.classifyNTPsecSourceHealth(true, payload);
  assert.equal(health.text, "healthy");
  assert.equal(health.state, "good");

  payload.status.synchronization.healthy = false;
  payload.status.synchronization.state = "unsynchronized";
  health = context.classifyNTPsecSourceHealth(true, payload);
  assert.equal(health.text, "needs attention");
  assert.equal(health.state, "warn");
  payload.status.synchronization.healthy = null;
  payload.status.synchronization.state = "unavailable";
  health = context.classifyNTPsecSourceHealth(true, payload);
  assert.equal(health.text, "needs attention");
  assert.equal(health.state, "warn");
  payload.status.synchronization.healthy = false;
  payload.status.synchronization.state = "unsynchronized";
  payload.status.daemon_conflicts.chronyd = { active: true, detail: "chronyd is active" };
  health = context.classifyNTPsecSourceHealth(true, payload);
  assert.equal(health.text, "needs attention");
});

test("NTP client and server modes still treat failed NTP probes as unhealthy", () => {
  for (const mode of ["ntp_client", "ntp_server"]) {
    const health = context.classifyNTPsecSourceHealth(true, {
      ok: true,
      status: {
        mode,
        peers: { returncode: 1, stderr: "ntpq probe failed" },
        synchronization: { state: "synchronized", healthy: true },
      },
    });
    assert.equal(health.text, "needs attention");
    assert.equal(health.state, "warn");
  }
});

test("NTP health details include effective mode, controller, conflicts, and sync state", () => {
  const rendered = context.formatNTPsecSourceHealthPayload({
    ok: true,
    status: {
      mode: "ntp_server",
      selected_controller: {
        name: "ntpd",
        active: true,
        detail: "NTPsec is active.",
      },
      daemon_conflicts: {
        vmware_tools: { active: true, detail: "guest sync is enabled" },
      },
      synchronization: {
        state: "unsynchronized",
        healthy: false,
        detail: "No system peer is available.",
      },
      peers: { returncode: 0, stdout: "no_sys_peer" },
    },
  });

  assert.match(rendered, /Effective mode: NTP\/NTS server/);
  assert.match(rendered, /Selected controller: NTPsec \(active\)/);
  assert.match(rendered, /VMware Tools time sync: active/);
  assert.match(rendered, /NTP synchronization: unsynchronized \(unhealthy\)/);
  assert.match(rendered, /No system peer is available\./);
  assert.match(rendered, /no_sys_peer/);
});


test("rapid Time edits wait for the previous autosave revision", async () => {
  const form = new FakeForm({});
  form.dataset.autosaveSerialize = "";
  form.revision = "initial";
  form.selectedSource = "manual";
  form.getAttribute = () => "/settings/time";
  form.querySelectorAll = () => [];
  form.dispatchEvent = (event) => form.emit(event.type, event);
  form.addEventListener("atlaso:autosave-success", (event) => { form.revision = event.detail.revision; });
  const writes = [];
  const root = { querySelectorAll: () => [form] };
  const browser = {
    root,
    HTMLFormElement: FakeForm,
    HTMLProgressElement: FakeElement,
    CustomEvent,
    AbortController,
    URL,
    window: { clearTimeout, setTimeout, location: { href: "https://atlaso.example/" } },
    document: { getElementById: () => null },
    setAutosaveStatus: () => {},
    updateDerivedListenAddressSummary: () => {},
    FormData: class {
      constructor(submitted) {
        this.revision = submitted.revision;
        this.selectedSource = submitted.selectedSource;
      }
    },
    fetch: (_url, options) => new Promise((respond) => {
      writes.push({
        revision: options.body.revision,
        source: options.body.selectedSource,
        signal: options.signal,
        succeed: (revision) => respond({ ok: true, json: async () => ({ revision }) }),
      });
    }),
  };
  vm.runInNewContext(functionSource("initializeAutosaveForms") + "\ninitializeAutosaveForms(root);", browser);
  const first = form.atlasoSaveNow();
  await new Promise(setImmediate);
  form.selectedSource = "ntp_client";
  const second = form.atlasoSaveNow();
  await new Promise(setImmediate);
  assert.equal(writes.length, 1);
  assert.equal(writes[0].signal.aborted, false);
  writes[0].succeed("first");
  assert.equal((await first).valid, true);
  await new Promise(setImmediate);
  assert.deepEqual(writes.map(({ revision, source }) => ({ revision, source })), [
    { revision: "initial", source: "manual" },
    { revision: "first", source: "ntp_client" },
  ]);
  writes[1].succeed("second");
  assert.equal((await second).valid, true);
  assert.equal(form.revision, "second");
});
