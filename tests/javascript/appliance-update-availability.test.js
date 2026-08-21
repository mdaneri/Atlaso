const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const appSource = fs.readFileSync("atlaso/app/static/app.js", "utf8");

function functionSource(name) {
  const start = appSource.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must exist in app.js`);
  const bodyStart = appSource.indexOf("{", start);
  let depth = 0;
  for (let index = bodyStart; index < appSource.length; index += 1) {
    if (appSource[index] === "{") depth += 1;
    if (appSource[index] === "}") depth -= 1;
    if (depth === 0) return appSource.slice(start, index + 1);
  }
  throw new Error(`Unable to extract ${name}`);
}

class Element {
  constructor() {
    this.dataset = {};
    this.disabled = false;
    this.textContent = "";
    this.classList = { toggle() {} };
  }
}
class HTMLInputElement extends Element {}
class HTMLButtonElement extends Element {}
class HTMLElement extends Element {}
class HTMLFormElement extends HTMLElement {
  constructor(inputs) {
    super();
    this.inputs = inputs;
  }

  querySelectorAll() {
    return this.inputs;
  }

  toggleAttribute() {}
}

function scenario({ streams, inputs }) {
  const checkButton = new HTMLButtonElement();
  const installButton = new HTMLButtonElement();
  const status = new HTMLElement();
  const form = new HTMLFormElement(inputs);
  const page = new HTMLElement();
  page.dataset.taskType = "appliance-update";
  const nodes = new Map([
    ["[data-tasks-page]", page],
    ["[data-appliance-update-submit-form]", form],
    ["[data-appliance-update-check-action]", checkButton],
    ["[data-appliance-update-install-action]", installButton],
    ["[data-appliance-update-action-status]", status],
  ]);
  const context = vm.createContext({
    document: { querySelector: (selector) => nodes.get(selector) || null },
    HTMLInputElement,
    HTMLButtonElement,
    HTMLFormElement,
    HTMLElement,
  });
  vm.runInContext(
    `let atlasoUpdateAvailability = ${JSON.stringify({ streams })}; let atlasoTasks = [];
     function taskStatusActive(status) { return status === "pending" || status === "running"; }
     function setApplianceUpdateSourceSyncDisabled() {}
     function updateApplianceUpdateResultSummary() {}
     ${functionSource("selectedUnsynchronizedUpdateStreams")}
     ${functionSource("selectedApplianceUpdateStreamIds")}
     ${functionSource("availabilityStream")}
     ${functionSource("updateApplianceUpdateActions")}
     globalThis.run = updateApplianceUpdateActions;`,
    context,
  );
  context.run([]);
  return { checkButton, installButton, status };
}

function selectedInput(value, label, synchronized = true) {
  const input = new HTMLInputElement();
  input.value = value;
  input.dataset.applianceUpdateStreamLabel = label;
  input.dataset.applianceUpdateSourceSyncRequired = "true";
  input.dataset.applianceUpdateSourceSyncReady = synchronized ? "true" : "false";
  return input;
}

test("unsynchronized repositories allow checks but block installation with an exact reason", () => {
  const input = selectedInput("powershell_modules", "PowerShell Modules", false);
  const result = scenario({
    inputs: [input],
    streams: [{
      id: "powershell_modules",
      label: "PowerShell Modules",
      stale: false,
      last_attempt: { success: false, remediation: "Synchronize repositories and check again." },
      confirmed: null,
    }],
  });
  assert.equal(result.checkButton.disabled, false);
  assert.equal(result.installButton.disabled, true);
  assert.equal(result.status.textContent, "Synchronize repositories and check again.");
});

test("a fresh mixed selection installs when every stream succeeded and one has an update", () => {
  const result = scenario({
    inputs: [
      selectedInput("photon_os", "Photon OS"),
      selectedInput("powershell_modules", "PowerShell Modules"),
    ],
    streams: [
      {
        id: "photon_os",
        label: "Photon OS",
        stale: false,
        last_attempt: { success: true },
        confirmed: { update_available: true },
      },
      {
        id: "powershell_modules",
        label: "PowerShell Modules",
        stale: false,
        last_attempt: { success: true },
        confirmed: { update_available: false },
      },
    ],
  });
  assert.equal(result.checkButton.disabled, false);
  assert.equal(result.installButton.disabled, false);
  assert.equal(result.status.textContent, "");
});

test("stale confirmations require another check", () => {
  const result = scenario({
    inputs: [selectedInput("atlaso_release", "Atlaso Release")],
    streams: [{
      id: "atlaso_release",
      label: "Atlaso Release",
      stale: true,
      last_attempt: { success: true },
      confirmed: null,
    }],
  });
  assert.equal(result.installButton.disabled, true);
  assert.equal(
    result.status.textContent,
    "Atlaso Release must be checked again because its update configuration changed.",
  );
});

test("availability polling is visibility aware and uses a one-minute cadence", () => {
  assert.match(appSource, /if \(document\.hidden\) return;/);
  assert.match(appSource, /document\.addEventListener\("visibilitychange"/);
  assert.match(appSource, /}, 60000\);/);
  assert.match(appSource, /cache: "no-store"/);
});

test("terminal appliance update tasks refresh availability once per observed parent", () => {
  const context = vm.createContext({ calls: 0, Set, Promise });
  vm.runInContext(
    `const atlasoAvailabilityTerminalTaskIds = new Set();
     function taskStatusActive(status) { return status === "pending" || status === "running"; }
     function refreshApplianceUpdateAvailability() { calls += 1; return Promise.resolve(); }
     ${functionSource("refreshAvailabilityForTerminalUpdateTasks")}
     globalThis.run = refreshAvailabilityForTerminalUpdateTasks;`,
    context,
  );
  const running = { id: "job-running", type: "appliance-update", status: "running" };
  const terminal = { id: "job-terminal", type: "appliance-update", status: "succeeded" };
  const failed = { id: "job-failed", type: "appliance-update", status: "failed" };
  context.run([
    running,
    terminal,
    failed,
    { id: "job-step", type: "appliance-update", status: "failed", is_step: true },
    { id: "job-other", type: "managed-script", status: "succeeded" },
  ]);
  assert.equal(context.calls, 1);
  context.run([terminal, failed]);
  assert.equal(context.calls, 1);
  context.run([{ ...running, status: "succeeded" }]);
  assert.equal(context.calls, 2);
});
