const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync("atlaso/app/static/settings-hardware.js", "utf8");

function functionSource(name) {
  let start = source.indexOf(`async function ${name}(`);
  if (start < 0) start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must exist in settings-hardware.js`);
  const signatureEnd = source.indexOf(") {", start);
  assert.notEqual(signatureEnd, -1, `${name} must have a function body`);
  const bodyStart = signatureEnd + 2;
  let depth = 0;
  for (let index = bodyStart; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    if (source[index] === "}") depth -= 1;
    if (depth === 0) return source.slice(start, index + 1);
  }
  throw new Error(`Unable to extract ${name}`);
}

class Element {
  constructor() {
    this.textContent = "";
    this.className = "";
    this.disabled = false;
    this.value = "";
    this.dataset = {};
    this.attributes = new Map();
    this.classes = new Set();
    this.classList = {
      remove: (name) => { this.classes.delete(name); },
      add: (name) => { this.classes.add(name); },
      toggle: (name, force) => {
        const shouldAdd = force === undefined ? !this.classes.has(name) : Boolean(force);
        if (shouldAdd) this.classes.add(name);
        else this.classes.delete(name);
        return shouldAdd;
      },
      contains: (name) => this.classes.has(name),
    };
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }
}

class Form extends Element {}

function inventoryHarness() {
  const bodyFor = () => {
    const body = { rows: [] };
    body.replaceChildren = () => { body.rows = []; };
    body.insertRow = () => {
      const row = { cells: [], insertCell() { const cell = { textContent: "" }; this.cells.push(cell); return cell; } };
      body.rows.push(row);
      return row;
    };
    return body;
  };
  const grids = new Map();
  const fallbacks = new Map();
  const hardwareLoadState = new Element();
  const refreshButton = new Element();
  let response = null;
  ["settings-disks-grid", "settings-network-grid"].forEach((id, index) => {
    const fallbackId = index === 0 ? "settings-disks-fallback" : "settings-network-fallback";
    const grid = new Element();
    grid.dataset = { fallbackId };
    grid.classList.add("hidden");
    grids.set(id, grid);
    const fallback = new Element();
    fallback.tBodies = [bodyFor()];
    fallbacks.set(fallbackId, fallback);
  });
  const root = {
    dataset: { statusUrl: "/settings/hardware/status" },
    querySelector(selector) {
      if (selector === "[data-hardware-load-state]") return hardwareLoadState;
      if (selector === "[data-hardware-refresh]") return refreshButton;
      const id = selector.match(/^#(.+)$/)?.[1];
      return grids.get(id) || fallbacks.get(id) || null;
    },
  };
  const controllers = [];
  const context = vm.createContext({
    fetch: async () => response,
    document: { querySelector: (selector) => root.querySelector(selector) },
    window: {
      Tabulator: function Tabulator() {},
      AtlasoUiPatterns: {
        createGrid(config) {
          const element = config.element;
          const fallback = root.querySelector(config.fallback);
          const callbacks = new Map();
          const controller = {
            state: "ready",
            setState(state) { this.state = state; },
            setError() {
              this.state = "error";
              element.classList.add("hidden");
              fallback.classList.remove("hidden");
            },
          };
          const table = {
            data: config.options.data,
            on(name, callback) {
              const registered = callbacks.get(name) || [];
              registered.push(callback);
              callbacks.set(name, registered);
            },
            setData(rows) {
              this.data = rows;
              controller.state = rows.length ? "ready" : "empty";
              element.classList.remove("hidden");
              fallback.classList.add("hidden");
              (callbacks.get("dataLoaded") || []).forEach((callback) => callback(rows));
            },
          };
          controller.table = table;
          element.classList.remove("hidden");
          fallback.classList.add("hidden");
          config.onReady?.(table);
          controllers.push(controller);
          return controller;
        },
      },
    },
  });
  vm.runInContext(
    "function updateSummary() {} function updateGuestTools() {}\n" +
      ["gridValue", "readableBytes", "initializeHardwareGrid", "setInventoryState", "updateFallbackTable",
        "setInventoryGridError", "setInventoryGridData", "updateInventory", "refreshHardware"]
        .map(functionSource).join("\n") + "\nglobalThis.updateInventory = updateInventory; globalThis.refreshHardware = refreshHardware;",
    context,
  );
  return {
    context, root, grids, fallbacks, controllers, hardwareLoadState, refreshButton,
    setResponse(value) { response = value; },
  };
}

function guestToolsHarness() {
  const nodes = new Map();
  [
    "[data-guest-tools-state]", "[data-guest-tools-provider]", "[data-guest-tools-version]", "[data-guest-tools-available-version]",
    "[data-guest-tools-source]", "[data-guest-tools-services]", "[data-guest-tools-effective-services]",
    "[data-guest-tools-reboot]", "[data-guest-tools-clock]", "[data-guest-tools-summary]",
    "[data-guest-tools-action-message]", "[data-guest-tools-review-digest]",
    "[data-guest-tools-check-button]", "[data-guest-tools-install-button]",
  ].forEach((selector) => nodes.set(selector, new Element()));
  const providerInputs = [new Element(), new Element()];
  const installForm = new Form();
  const root = {
    querySelector: (selector) => selector === "[data-guest-tools-install]" ? installForm : nodes.get(selector) || null,
    querySelectorAll: (selector) => selector === "[data-guest-tools-provider-input]" ? providerInputs : [],
  };
  const context = vm.createContext({});
  vm.runInContext(
    ["safeText", "formatGuestToolVersion", "guestToolPackageName", "verifiedGuestToolPackage", "offlinePayloadAvailable", "availableGuestToolVersion", "describeServiceChanges", "describeClockSafety", "actionsRequireServiceWork", "updateGuestTools"]
      .map(functionSource).join("\n") + "\nglobalThis.updateGuestTools = updateGuestTools;",
    context,
  );
  return { context, root, nodes, providerInputs, installForm };
}

function reviewPayload(overrides = {}) {
  return {
    provider: "qemu",
    state: "missing",
    version: "",
    available: true,
    review_digest: "a".repeat(64),
    reason: "The supported guest tools package is not installed.",
    reboot_impact: "No reboot is expected; service state is verified after maintenance.",
    clock_safety: {
      status: "pending",
      authority: "ntp_client",
      protected: false,
      reason: "The reviewed operation will block QEMU guest time-setting RPCs persistently.",
    },
    packages: [
      { name: "open-vm-tools", version: "99.0", installed: true },
      { name: "foreign-agent", version: "1.0", installed: true },
    ],
    services: [{ unit: "foreign-agent.service", active: true, enabled: true }],
    target_packages: [
      { name: "atlaso-qemu-guest-agent", version: "1:2.3-4", architecture: "x86_64", path: "/private/payload/agent.rpm" },
      { name: "dependency", version: "5.6-7", architecture: "noarch", path: "/private/payload/dependency.rpm" },
    ],
    plan: {
      package_change: true,
      target_version: "1:2.3-4",
      actions: ["verify-clock-safety", "install-or-repair-agent", "enable-required-services"],
    },
    ...overrides,
  };
}

test("inventory unknown, success, whole-request failure, and retry keep grid states truthful", async () => {
  const harness = inventoryHarness();
  const disksGrid = harness.grids.get("settings-disks-grid");
  const disksFallback = harness.fallbacks.get("settings-disks-fallback");
  const statusResponse = (hardware) => ({ ok: true, json: async () => ({ hardware, guest_tools: {} }) });

  harness.setResponse(statusResponse({ disks_state: "unknown", interfaces_state: "unknown" }));
  await harness.context.refreshHardware(harness.root);
  assert.equal(harness.controllers.length, 0);
  assert.equal(disksGrid.classList.contains("hidden"), true);
  assert.match(disksFallback.tBodies[0].rows[0].cells[0].textContent, /unavailable/);

  harness.setResponse(statusResponse({
    disks_state: "available",
    interfaces_state: "available",
    disks: [{ device_path: "/dev/sda", model: "Disk A", size_bytes: 1024 }],
    interfaces: [],
  }));
  await harness.context.refreshHardware(harness.root);
  assert.equal(harness.controllers.length, 2);
  assert.equal(disksGrid.classList.contains("hidden"), false);
  assert.equal(disksFallback.classList.contains("hidden"), true);
  assert.equal(disksGrid.atlasoHardwareTable.data[0].device_path, "/dev/sda");

  harness.setResponse({ ok: false, status: 503 });
  await harness.context.refreshHardware(harness.root);
  assert.equal(disksGrid.atlasoHardwareController.state, "error");
  assert.equal(disksGrid.classList.contains("hidden"), true);
  assert.equal(disksFallback.classList.contains("hidden"), false);
  assert.match(disksFallback.tBodies[0].rows[0].cells[0].textContent, /check failed/);

  harness.setResponse(statusResponse({
    disks_state: "available",
    interfaces_state: "available",
    disks: [{ device_path: "/dev/vdb", model: "Disk B", size_bytes: 2048 }],
    interfaces: [],
  }));
  await harness.context.refreshHardware(harness.root);
  assert.equal(disksGrid.atlasoHardwareController.state, "ready");
  assert.equal(disksGrid.atlasoHardwareTable.data[0].device_path, "/dev/vdb");
  assert.equal(disksGrid.classList.contains("hidden"), false);
  assert.equal(disksFallback.classList.contains("hidden"), true);
});

test("guest-tools review shows concise tool versions without listing the offline dependency closure", () => {
  const harness = guestToolsHarness();
  const dependencies = Array.from({length: 84}, (_, index) => ({
    name: `dependency-${index}`,
    version: `5.${index}-7`,
    architecture: "noarch",
    path: `/private/payload/dependency-${index}.rpm`,
  }));
  harness.context.updateGuestTools(harness.root, reviewPayload({
    target_packages: [
      { name: "atlaso-qemu-guest-agent", version: "1:2.3-4", architecture: "x86_64", path: "/private/payload/agent.rpm" },
      ...dependencies,
    ],
  }));

  assert.equal(harness.nodes.get("[data-guest-tools-provider]").textContent, "KVM / QEMU guest agent");
  assert.equal(harness.nodes.get("[data-guest-tools-version]").textContent, "Not installed");
  assert.equal(harness.nodes.get("[data-guest-tools-available-version]").textContent, "2.3");
  assert.equal(harness.nodes.get("[data-guest-tools-services]").textContent, "Enable and start qemu-guest-agent.service.");
  assert.match(harness.nodes.get("[data-guest-tools-clock]").textContent, /Authority: NTP client\. Guard: pending; not yet protected\./);
  assert.match(harness.nodes.get("[data-guest-tools-clock]").textContent, /block QEMU guest time-setting RPCs/);
  assert.match(harness.installForm.dataset.confirmMessage, /Installed version: Not installed\./);
  assert.match(harness.installForm.dataset.confirmMessage, /Available version: 2\.3\./);
  assert.match(harness.installForm.dataset.confirmMessage, /qemu-guest-agent\.service/);
  assert.match(harness.installForm.dataset.confirmMessage, /No reboot is expected/);
  assert.doesNotMatch(harness.installForm.dataset.confirmMessage, /dependency-|agent\.rpm|private\/payload/);
  assert.doesNotMatch(harness.installForm.dataset.confirmMessage, /\[object Object\]/);
});

test("installed VMware version and fallback target-package matching use only the provider agent", () => {
  const harness = guestToolsHarness();
  harness.context.updateGuestTools(harness.root, reviewPayload({
    provider: "vmware",
    state: "healthy",
    version: "0:13.1.0-2.ph5",
    target_packages: [
      { name: "unrelated-package", version: "99.0-1", architecture: "noarch" },
      { name: "open-vm-tools", version: "0:13.2.0-1.ph5", architecture: "x86_64" },
    ],
    plan: { package_change: true, actions: ["install-or-repair-agent"] },
  }));

  assert.equal(harness.nodes.get("[data-guest-tools-version]").textContent, "13.1.0");
  assert.equal(harness.nodes.get("[data-guest-tools-available-version]").textContent, "13.2.0");
  assert.doesNotMatch(harness.installForm.dataset.confirmMessage, /unrelated-package|99\.0/);
});

test("missing offline payload and unknown provider do not imply an available tool version", () => {
  const harness = guestToolsHarness();
  harness.context.updateGuestTools(harness.root, reviewPayload({
    available: true,
    payload: { available: false },
    plan: { package_change: true, target_version: "1:2.3-4", actions: [] },
  }));
  assert.equal(harness.nodes.get("[data-guest-tools-available-version]").textContent, "Unavailable offline");
  assert.equal(harness.nodes.get("[data-guest-tools-source]").textContent, "Verified package closure unavailable");

  harness.context.updateGuestTools(harness.root, reviewPayload({
    provider: "unknown",
    available: true,
    plan: { package_change: true, target_version: "1:2.3-4", actions: [] },
  }));
  assert.equal(harness.nodes.get("[data-guest-tools-available-version]").textContent, "Unknown");
});

test("offline payload version remains visible when clock safety blocks maintenance", () => {
  const harness = guestToolsHarness();
  harness.context.updateGuestTools(harness.root, reviewPayload({
    available: false,
    payload: { available: true },
    plan: { package_change: true, target_version: "1:2.3-4", actions: ["install-or-repair-agent"] },
  }));

  assert.equal(harness.nodes.get("[data-guest-tools-available-version]").textContent, "2.3");
  assert.equal(harness.nodes.get("[data-guest-tools-source]").textContent, "Verified offline package closure");
  assert.equal(harness.nodes.get("[data-guest-tools-install-button]").disabled, true);
});

test("maintenance permission does not imply an offline payload is available", () => {
  const harness = guestToolsHarness();
  harness.context.updateGuestTools(harness.root, reviewPayload({
    available: true,
    payload: { available: false },
    plan: { package_change: true, target_version: "1:2.3-4", actions: ["install-or-repair-agent"] },
  }));

  assert.equal(harness.nodes.get("[data-guest-tools-available-version]").textContent, "Unavailable offline");
  assert.equal(harness.nodes.get("[data-guest-tools-install-button]").disabled, false);
});

test("upstream prerelease versions without RPM release metadata remain intact", () => {
  const harness = guestToolsHarness();
  harness.context.updateGuestTools(harness.root, reviewPayload({
    state: "healthy",
    version: "2.3-rc1",
    target_packages: [{ name: "atlaso-qemu-guest-agent", version: "2.4-beta2", architecture: "x86_64" }],
    plan: { package_change: true, target_version: "2.4-beta2", actions: [] },
  }));

  assert.equal(harness.nodes.get("[data-guest-tools-version]").textContent, "2.3-rc1");
  assert.equal(harness.nodes.get("[data-guest-tools-available-version]").textContent, "2.4-beta2");
});

test("effective services and active maintenance remain distinct from package updates", () => {
  const harness = guestToolsHarness();
  harness.root.dataset = {maintenanceActive: "true"};
  harness.context.updateGuestTools(harness.root, reviewPayload({
    services: [{unit:"qemu-guest-agent.service",load_state:"loaded",active_state:"inactive",enabled_state:"disabled"}],
  }));
  assert.match(harness.nodes.get("[data-guest-tools-effective-services]").textContent, /inactive \/ disabled/);
  assert.equal(harness.nodes.get("[data-guest-tools-check-button]").disabled, true);
  assert.equal(harness.nodes.get("[data-guest-tools-install-button]").disabled, true);
  harness.root.dataset.maintenanceActive = "false";
  harness.context.updateGuestTools(harness.root, reviewPayload({state:"healthy"}));
  assert.equal(harness.nodes.get("[data-guest-tools-install-button]").disabled, false);
});

test("no package transaction is distinct from selected-provider service repair", () => {
  const harness = guestToolsHarness();
  harness.context.updateGuestTools(harness.root, reviewPayload({
    provider: "hyperv",
    target_packages: [],
    payload: { available: true },
    plan: { package_change: false, target_version: "1:2.3-4", actions: ["enable-required-services"] },
    clock_safety: { status: "verified", authority: "ntp_server", protected: true, reason: "" },
  }));

  assert.equal(harness.nodes.get("[data-guest-tools-available-version]").textContent, "2.3");
  assert.equal(harness.nodes.get("[data-guest-tools-source]").textContent, "No package transaction required");
  assert.equal(harness.nodes.get("[data-guest-tools-services]").textContent,
    "Disable and stop hv_fcopy_daemon.service; enable and start hv_kvp_daemon.service and hv_vss_daemon.service.");
  assert.match(harness.nodes.get("[data-guest-tools-reboot]").textContent, /may start or stop services/);
  assert.match(harness.nodes.get("[data-guest-tools-clock]").textContent, /Authority: NTP server\. Guard: verified; protected\./);
});

test("guest-tools summary transitions from unknown to known and back to a failed, disabled review", () => {
  const harness = guestToolsHarness();
  harness.context.updateGuestTools(harness.root, { provider: "unknown", state: "unknown", reason: "Detect failed." });
  assert.equal(harness.nodes.get("[data-guest-tools-install-button]").disabled, true);
  assert.equal(harness.nodes.get("[data-guest-tools-available-version]").textContent, "Unknown");

  harness.context.updateGuestTools(harness.root, reviewPayload());
  assert.equal(harness.nodes.get("[data-guest-tools-install-button]").disabled, false);
  assert.equal(harness.nodes.get("[data-guest-tools-available-version]").textContent, "2.3");

  harness.context.updateGuestTools(harness.root, { provider: "unknown", state: "unknown", reason: "Status request failed." });
  assert.equal(harness.nodes.get("[data-guest-tools-install-button]").disabled, true);
  assert.equal(harness.nodes.get("[data-guest-tools-state]").textContent, "Status unknown");
  assert.equal(harness.nodes.get("[data-guest-tools-available-version]").textContent, "Unknown");
  assert.match(harness.nodes.get("[data-guest-tools-summary]").textContent, /Status request failed/);
  assert.doesNotMatch(harness.nodes.get("[data-guest-tools-clock]").textContent, /\[object Object\]/);
});

test("external tab controls relay autosave events to their associated form", () => {
  const ownerForm = new Form();
  ownerForm.id = "appliance-settings-form";
  ownerForm.dispatched = [];
  ownerForm.contains = () => false;
  ownerForm.dispatchEvent = (event) => ownerForm.dispatched.push(event.type);
  const input = new Element();
  input.form = ownerForm;
  const document = { getElementById: (id) => id === ownerForm.id ? ownerForm : null };
  const context = vm.createContext({
    document,
    HTMLElement: Element,
    HTMLFormElement: Form,
    CSS: { escape: (value) => String(value) },
    Event: class { constructor(type) { this.type = type; } },
  });
  vm.runInContext(
    `const settingsFormIds = new Set(["appliance-settings-form"]);\n${functionSource("forwardExternalAutosaveInput")}\nglobalThis.forward = forwardExternalAutosaveInput;`,
    context,
  );

  context.forward({ target: input, type: "input" });
  context.forward({ target: input, type: "change" });
  assert.deepEqual(ownerForm.dispatched, ["change", "change"]);

  const token = new Element();
  let requestedSelector = "";
  const list = { querySelectorAll(selector) { requestedSelector = selector; return [token]; } };
  const editor = new Element();
  editor.dataset = { tagName: "web_terminal_interfaces", formId: ownerForm.id };
  editor.querySelector = (selector) => selector === "[data-tag-list]" ? list : null;
  editor.closest = (selector) => selector === "[data-tag-editor]" ? editor : null;
  context.forward({ target: editor, type: "tag-editor:change" });
  assert.deepEqual(ownerForm.dispatched, ["change", "change", "tag-editor:change"]);
  assert.equal(token.attributes.get("form"), ownerForm.id);
  assert.match(requestedSelector, /web_terminal_interfaces/);
});
