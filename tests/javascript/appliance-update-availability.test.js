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
    this.attributes = new Map();
    this.classList = { toggle() {} };
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  getAttribute(name) {
    return this.attributes.get(name) ?? null;
  }

  removeAttribute(name) {
    this.attributes.delete(name);
  }
}
class HTMLInputElement extends Element {}
class HTMLButtonElement extends Element {}
class HTMLElement extends Element {}
class HTMLAnchorElement extends HTMLElement {
  constructor() {
    super();
    this.count = new HTMLElement();
    this.onRemove = null;
  }

  cloneNode() {
    return new HTMLAnchorElement();
  }

  querySelector(selector) {
    return selector === "[data-update-availability-count]" ? this.count : null;
  }

  remove() {
    this.onRemove?.();
  }
}
class HTMLTemplateElement extends HTMLElement {
  constructor(prototype) {
    super();
    this.prototype = prototype;
    this.onBefore = null;
    this.content = {
      querySelector: (selector) => selector === "[data-update-availability-prototype]" ? this.prototype : null,
    };
  }

  before(node) {
    this.onBefore?.(node);
  }
}
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

function availabilityIndicatorScenario() {
  let indicator = null;
  let fetchResponse = { ok: false };
  const prototype = new HTMLAnchorElement();
  const template = new HTMLTemplateElement(prototype);
  const bindIndicator = (node) => {
    indicator = node;
    node.onRemove = () => { indicator = null; };
  };
  template.onBefore = bindIndicator;
  const document = {
    querySelector(selector) {
      if (selector === "[data-update-availability-indicator]") return indicator;
      if (selector === "[data-update-availability-template]") return template;
      return null;
    },
  };
  const context = vm.createContext({
    document,
    fetch: () => Promise.resolve(fetchResponse),
    HTMLAnchorElement,
    HTMLElement,
    HTMLTemplateElement,
    URL,
    CSS: { escape: (value) => String(value) },
  });
  vm.runInContext(
    `let atlasoUpdateAvailability = { available: false, affected_stream_count: 0, streams: [] };
     let atlasoUpdateAvailabilityRequest = null;
     function updateApplianceUpdateResultSummary() {}
     function updateApplianceUpdateActions() {}
     ${functionSource("createApplianceUpdateAvailabilityIndicator")}
     ${functionSource("validApplianceUpdateAvailabilityPayload")}
     ${functionSource("renderApplianceUpdateAvailability")}
     ${functionSource("refreshApplianceUpdateAvailability")}
     globalThis.render = renderApplianceUpdateAvailability;
     globalThis.refresh = refreshApplianceUpdateAvailability;`,
    context,
  );
  return {
    context,
    setFetchResponse(response) { fetchResponse = response; },
    get indicator() { return indicator; },
  };
}

function availabilityStreams(availableIds = []) {
  return ["photon_os", "powershell_modules", "atlaso_release"].map((id) => ({
    id,
    label: id,
    stale: false,
    last_attempt: {
      success: true,
      state: availableIds.includes(id) ? "available" : "up_to_date",
      remediation: "",
    },
    confirmed: {
      update_available: availableIds.includes(id),
      current: "current",
      target: "target",
      change_count: 0,
      changes: [],
      details_incomplete: false,
      summary: "",
      release_notes_url: "",
    },
  }));
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

test("availability rendering creates, updates, and removes exactly one positive indicator", () => {
  const scenario = availabilityIndicatorScenario();
  scenario.context.render({ available: false, affected_stream_count: 0, streams: [] });
  assert.equal(scenario.indicator, null);

  scenario.context.render({ available: true, affected_stream_count: 1, streams: [] });
  const first = scenario.indicator;
  assert.ok(first instanceof HTMLAnchorElement);
  assert.equal(first.getAttribute("aria-label"), "Update available for 1 update stream");
  assert.equal(first.count.textContent, "1");

  scenario.context.render({ available: true, affected_stream_count: 2, streams: [] });
  assert.equal(scenario.indicator, first);
  assert.equal(first.getAttribute("aria-label"), "Update available for 2 update streams");
  assert.equal(first.count.textContent, "2");

  scenario.context.render({ available: false, affected_stream_count: 0, streams: [] });
  assert.equal(scenario.indicator, null);
});

test("validated polling creates, updates, and removes the positive indicator", async () => {
  const scenario = availabilityIndicatorScenario();
  scenario.setFetchResponse({
    ok: true,
    json: () => Promise.resolve({
      available: true,
      affected_stream_count: 1,
      streams: availabilityStreams(["atlaso_release"]).map((stream) => (
        stream.id === "atlaso_release"
          ? {
            ...stream,
            confirmed: {
              ...stream.confirmed,
              release_notes_url: "https://example.test/releases/v0.9.186",
            },
          }
          : stream
      )),
    }),
  });
  await scenario.context.refresh();
  const first = scenario.indicator;
  assert.equal(first.count.textContent, "1");

  scenario.setFetchResponse({
    ok: true,
    json: () => Promise.resolve({
      available: true,
      affected_stream_count: 2,
      streams: availabilityStreams(["atlaso_release", "photon_os"]),
    }),
  });
  await scenario.context.refresh();
  assert.equal(scenario.indicator, first);
  assert.equal(first.count.textContent, "2");

  scenario.setFetchResponse({
    ok: true,
    json: () => Promise.resolve({
      available: false,
      affected_stream_count: 0,
      streams: availabilityStreams(),
    }),
  });
  await scenario.context.refresh();
  assert.equal(scenario.indicator, null);
});

test("failed polling preserves only an existing positive indicator", async () => {
  const positive = availabilityIndicatorScenario();
  positive.context.render({ available: true, affected_stream_count: 2, streams: [] });
  const lastKnown = positive.indicator;
  await assert.rejects(positive.context.refresh(), /Unable to refresh update availability/);
  assert.equal(positive.indicator, lastKnown);
  assert.equal(positive.indicator.count.textContent, "2");
  positive.setFetchResponse({ ok: true, json: () => Promise.resolve({ streams: [] }) });
  await assert.rejects(positive.context.refresh(), /Unable to refresh update availability/);
  assert.equal(positive.indicator, lastKnown);
  for (const unsafeReleaseNotesUrl of [
    "javascript:alert(1)",
    "https://user:pass@example.test/notes",
  ]) {
    positive.setFetchResponse({
      ok: true,
      json: () => Promise.resolve({
        available: true,
        affected_stream_count: 1,
        streams: availabilityStreams(["atlaso_release"]).map((stream, index) => (
          index === 0
            ? { ...stream, confirmed: { ...stream.confirmed, release_notes_url: unsafeReleaseNotesUrl } }
            : stream
        )),
      }),
    });
    await assert.rejects(positive.context.refresh(), /Unable to refresh update availability/);
    assert.equal(positive.indicator, lastKnown);
  }
  positive.setFetchResponse({
    ok: true,
    json: () => Promise.resolve({
      available: true,
      affected_stream_count: 1,
      streams: availabilityStreams(["atlaso_release"]).map((stream, index) => (
        index === 0
          ? {
            ...stream,
            confirmed: {
              ...stream.confirmed,
              change_count: 21,
              changes: Array.from({ length: 21 }, (_value, changeIndex) => ({
                name: `Change ${changeIndex + 1}`,
              })),
            },
          }
          : stream
      )),
    }),
  });
  await assert.rejects(positive.context.refresh(), /Unable to refresh update availability/);
  assert.equal(positive.indicator, lastKnown);
  positive.setFetchResponse({
    ok: true,
    json: () => Promise.resolve({ available: false, affected_stream_count: 2, streams: [] }),
  });
  await assert.rejects(positive.context.refresh(), /Unable to refresh update availability/);
  assert.equal(positive.indicator, lastKnown);
  positive.setFetchResponse({
    ok: true,
    json: () => Promise.resolve({ available: true, affected_stream_count: 1, streams: [] }),
  });
  await assert.rejects(positive.context.refresh(), /Unable to refresh update availability/);
  assert.equal(positive.indicator, lastKnown);
  positive.setFetchResponse({
    ok: true,
    json: () => Promise.resolve({ available: false, affected_stream_count: 0, streams: [] }),
  });
  await assert.rejects(positive.context.refresh(), /Unable to refresh update availability/);
  assert.equal(positive.indicator, lastKnown);
  positive.setFetchResponse({
    ok: true,
    json: () => Promise.resolve({
      available: true,
      affected_stream_count: 1,
      streams: availabilityStreams(["atlaso_release"]).map((stream, index) => (
        index === 0
          ? { ...stream, confirmed: { ...stream.confirmed, change_count: 1, changes: [[]] } }
          : stream
      )),
    }),
  });
  await assert.rejects(positive.context.refresh(), /Unable to refresh update availability/);
  assert.equal(positive.indicator, lastKnown);
  positive.setFetchResponse({
    ok: true,
    json: () => Promise.resolve({
      available: true,
      affected_stream_count: 1,
      streams: availabilityStreams(["atlaso_release"]).map((stream, index) => (
        index === 0 ? { ...stream, last_attempt: { state: "up_to_date", remediation: "" } } : stream
      )),
    }),
  });
  await assert.rejects(positive.context.refresh(), /Unable to refresh update availability/);
  assert.equal(positive.indicator, lastKnown);
  positive.setFetchResponse({
    ok: true,
    json: () => Promise.resolve({
      available: true,
      affected_stream_count: 1,
      streams: [
        { id: "photon_os", stale: false, confirmed: { update_available: true } },
        { id: "photon_os", stale: false, confirmed: { update_available: false } },
        { id: "atlaso_release", stale: false, confirmed: { update_available: false } },
      ],
    }),
  });
  await assert.rejects(positive.context.refresh(), /Unable to refresh update availability/);
  assert.equal(positive.indicator, lastKnown);
  positive.setFetchResponse({
    ok: true,
    json: () => Promise.resolve({
      available: true,
      affected_stream_count: 1,
      streams: [{ confirmed: { update_available: true } }],
    }),
  });
  await assert.rejects(positive.context.refresh(), /Unable to refresh update availability/);
  assert.equal(positive.indicator, lastKnown);
  positive.setFetchResponse({
    ok: true,
    json: () => Promise.resolve({
      available: true,
      affected_stream_count: 1,
      streams: [{ stale: true, confirmed: { update_available: true } }],
    }),
  });
  await assert.rejects(positive.context.refresh(), /Unable to refresh update availability/);
  assert.equal(positive.indicator, lastKnown);

  const zero = availabilityIndicatorScenario();
  await assert.rejects(zero.context.refresh(), /Unable to refresh update availability/);
  assert.equal(zero.indicator, null);
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
