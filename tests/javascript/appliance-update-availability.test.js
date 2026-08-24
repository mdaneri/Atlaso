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
    this.checked = false;
    this.textContent = "";
    this.attributes = new Map();
    this.classList = { toggle() {} };
    this.focused = false;
  }

  focus() {
    this.focused = true;
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
    CSS: { escape: (value) => String(value) },
    URL,
  });
  vm.runInContext(
    `let atlasoUpdateAvailability = { available: false, affected_stream_count: 0, streams: [] };
     let atlasoUpdateAvailabilityRequest = null;
     let atlasoUpdateAvailabilityRequestSequence = 0;
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
    setFetchResponse(response, { addSchemaVersion = true } = {}) {
      fetchResponse = addSchemaVersion && typeof response?.json === "function"
        ? {
          ...response,
          json: async () => ({ schema_version: 1, ...(await response.json()) }),
        }
        : response;
    },
    get indicator() { return indicator; },
  };
}

function availabilityStreams(availableIds = []) {
  const labels = {
    photon_os: "Photon OS",
    powershell_modules: "PowerShell Modules",
    atlaso_release: "Atlaso Release",
  };
  return ["photon_os", "powershell_modules", "atlaso_release"].map((id) => ({
    id,
    label: labels[id],
    stale: false,
    check_required: false,
    source_sync: {
      required: id !== "atlaso_release",
      ready: true,
      state: "ready",
      source_kind: id === "photon_os" ? "photon" : id === "powershell_modules" ? "powershell" : "atlaso",
      repositories: [],
      repository_count: 0,
      repositories_omitted: 0,
      reason: "",
    },
    last_attempt: {
      checked_at: "2026-08-23T04:00:00+00:00",
      success: true,
      state: availableIds.includes(id) ? "available" : "up_to_date",
      current: "current",
      target: "target",
      remediation: "",
    },
    confirmed: {
      state: availableIds.includes(id) ? "available" : "up_to_date",
      update_available: availableIds.includes(id),
      current: "current",
      target: "target",
      change_count: 0,
      changes: [],
      details_incomplete: false,
      summary: "",
      release_notes_url: "",
      remediation: "",
      checked_at: "2026-08-23T04:00:00+00:00",
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
  input.checked = true;
  input.dataset.applianceUpdateStreamLabel = label;
  input.dataset.applianceUpdateSourceSyncRequired = "true";
  input.dataset.applianceUpdateSourceSyncReady = synchronized ? "true" : "false";
  return input;
}

test("an unsynchronized repository stream is excluded and blocks both actions when no ready stream is selected", () => {
  const input = selectedInput("powershell_modules", "PowerShell Modules", false);
  input.disabled = true;
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
  assert.equal(result.checkButton.disabled, true);
  assert.equal(result.installButton.disabled, true);
  assert.equal(
    result.status.textContent,
    "Select a ready update stream. Repository setup is required for PowerShell Modules.",
  );
});

test("a ready stream remains independently usable beside a blocked stream", () => {
  const blocked = selectedInput("powershell_modules", "PowerShell Modules", false);
  blocked.disabled = true;
  const result = scenario({
    inputs: [
      selectedInput("photon_os", "Photon OS"),
      blocked,
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
              current: "😀".repeat(200),
              release_notes_url: "https://example.test:bad/releases/\uFEFFv0.9.186",
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
      affected_stream_count: 1,
      streams: availabilityStreams(["atlaso_release"]).map((stream) => (
        stream.id === "atlaso_release"
          ? {
            ...stream,
            last_attempt: {
              ...stream.last_attempt,
              success: false,
              state: "failed",
              remediation: "Try the check again.",
            },
            confirmed: {
              ...stream.confirmed,
              release_notes_url: "https://[fe80::1%25eth0]:99999/releases/v0.9.186",
            },
          }
          : stream
      )),
    }),
  });
  await scenario.context.refresh();
  assert.equal(scenario.indicator, first);
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

  const blockedStreams = availabilityStreams(["powershell_modules"]);
  const blockedPowerShell = blockedStreams.find((stream) => stream.id === "powershell_modules");
  const longRepositoryName = "R".repeat(160);
  blockedPowerShell.source_sync = {
    ...blockedPowerShell.source_sync,
    ready: false,
    state: "required",
    repositories: ["Internal  Mirror", longRepositoryName],
    repository_count: 2,
    reason: `Synchronize repositories for Internal  Mirror, ${longRepositoryName} before checking or installing PowerShell Modules.`,
  };
  scenario.setFetchResponse({
    ok: true,
    json: () => Promise.resolve({
      available: false,
      affected_stream_count: 0,
      streams: blockedStreams,
    }),
  });
  await scenario.context.refresh();
  assert.equal(scenario.indicator, null);

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
  for (const versionPayload of [
    {},
    { schema_version: 2 },
  ]) {
    positive.setFetchResponse({
      ok: true,
      json: () => Promise.resolve({
        ...versionPayload,
        available: false,
        affected_stream_count: 0,
        streams: availabilityStreams(),
      }),
    }, { addSchemaVersion: false });
    await assert.rejects(positive.context.refresh(), /Unable to refresh update availability/);
    assert.equal(positive.indicator, lastKnown);
  }
  for (const unsafeReleaseNotesUrl of [
    "javascript:alert(1)",
    "httpſ://evil.example/notes",
    "https://example.com\u0085/notes",
    "https://example.com／notes",
    "https://[/notes",
    "https://[example.com]/notes",
    "https://user:pass@example.test/notes",
    `https://example.test/${"a".repeat(2049)}`,
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
  for (const noncanonicalSummary of ["\n", " leading", "trailing ", "two  spaces", "nonbreaking\u00A0space"]) {
    positive.setFetchResponse({
      ok: true,
      json: () => Promise.resolve({
        available: false,
        affected_stream_count: 0,
        streams: availabilityStreams().map((stream, index) => (
          index === 0
            ? { ...stream, confirmed: { ...stream.confirmed, summary: noncanonicalSummary } }
            : stream
        )),
      }),
    });
    await assert.rejects(positive.context.refresh(), /Unable to refresh update availability/);
    assert.equal(positive.indicator, lastKnown);
  }
  for (const inconsistentUpToDate of [
    { change_count: 1, changes: [] },
    { change_count: 0, changes: [{ name: "Unexpected change" }] },
  ]) {
    positive.setFetchResponse({
      ok: true,
      json: () => Promise.resolve({
        available: false,
        affected_stream_count: 0,
        streams: availabilityStreams().map((stream, index) => (
          index === 0
            ? { ...stream, confirmed: { ...stream.confirmed, ...inconsistentUpToDate } }
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
  const failedConfirmedStreams = availabilityStreams();
  const failedConfirmedStream = failedConfirmedStreams.find((stream) => stream.id === "atlaso_release");
  failedConfirmedStream.last_attempt = {
    ...failedConfirmedStream.last_attempt,
    success: false,
    state: "failed",
    remediation: "Check failed.",
  };
  failedConfirmedStream.confirmed = {
    ...failedConfirmedStream.confirmed,
    state: "failed",
    update_available: false,
  };
  positive.setFetchResponse({
    ok: true,
    json: () => Promise.resolve({
      available: false,
      affected_stream_count: 0,
      streams: failedConfirmedStreams,
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
  const availableAttempt = availabilityStreams(["atlaso_release"])
    .find((stream) => stream.id === "atlaso_release").last_attempt;
  for (const invalidLastAttempt of [
    { ...availableAttempt, success: undefined },
    { ...availableAttempt, success: true, state: "failed", remediation: "Check failed." },
    { ...availableAttempt, success: false, state: "available" },
  ]) {
    positive.setFetchResponse({
      ok: true,
      json: () => Promise.resolve({
        available: true,
        affected_stream_count: 1,
        streams: availabilityStreams(["atlaso_release"]).map((stream, index) => (
          index === 0 ? { ...stream, last_attempt: invalidLastAttempt } : stream
        )),
      }),
    });
    await assert.rejects(positive.context.refresh(), /Unable to refresh update availability/);
    assert.equal(positive.indicator, lastKnown);
  }
  const invalidStreamMutators = [
    (stream) => { stream.label = "x".repeat(501); },
    (stream) => { stream.last_attempt.remediation = "x".repeat(301); },
    (stream) => { stream.last_attempt.current = "x".repeat(201); },
    (stream) => { stream.confirmed.target = "x".repeat(201); },
    (stream) => { stream.confirmed.summary = "x".repeat(241); },
    (stream) => { stream.confirmed.remediation = "x".repeat(301); },
    (stream) => { stream.check_required = "false"; },
    (stream) => { stream.source_sync.ready = "true"; },
    (stream) => { stream.source_sync.state = "required"; },
    (stream) => { stream.source_sync.repositories = ["x".repeat(161)]; },
    (stream) => { stream.source_sync.repository_count = -1; },
    (stream) => { stream.source_sync.reason = "x".repeat(1201); },
    (stream) => {
      stream.confirmed.change_count = 1;
      stream.confirmed.changes = [{ name: "x".repeat(161) }];
    },
    (stream) => { stream.last_attempt.state = "up_to_date"; },
    (stream) => {
      stream.last_attempt.state = "up_to_date";
      stream.confirmed.state = "up_to_date";
    },
  ];
  for (const mutateStream of invalidStreamMutators) {
    const streams = availabilityStreams(["atlaso_release"]);
    mutateStream(streams.find((stream) => stream.id === "atlaso_release"));
    positive.setFetchResponse({
      ok: true,
      json: () => Promise.resolve({
        available: true,
        affected_stream_count: 1,
        streams,
      }),
    });
    await assert.rejects(positive.context.refresh(), /Unable to refresh update availability/);
    assert.equal(positive.indicator, lastKnown);
  }
  const staleConfirmedStreams = availabilityStreams(["atlaso_release"]);
  staleConfirmedStreams.find((stream) => stream.id === "atlaso_release").stale = true;
  positive.setFetchResponse({
    ok: true,
    json: () => Promise.resolve({
      available: false,
      affected_stream_count: 0,
      streams: staleConfirmedStreams,
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

test("successful repository synchronization promptly forces one readiness refresh per task state", () => {
  const context = vm.createContext({ calls: 0, Promise });
  vm.runInContext(
    `let atlasoNewTaskId = "job-sync";
     let atlasoLastSourceSyncTaskState = "";
     function refreshApplianceUpdateAvailability(options) {
       if (options?.force === true) calls += 1;
       return Promise.resolve();
     }
     ${functionSource("updateApplianceUpdateSourceSyncState")}
     globalThis.run = updateApplianceUpdateSourceSyncState;`,
    context,
  );
  const running = { id: "job-sync", status: "running", result: { mode: "source_sync" } };
  const succeeded = { id: "job-sync", status: "succeeded", result: { mode: "source_sync" } };
  context.run(running);
  context.run(running);
  context.run(succeeded);
  context.run({ ...succeeded, id: "job-other" });
  context.run({ ...succeeded, is_step: true });
  assert.equal(context.calls, 2);
});

test("a newer forced availability response wins over an older response", async () => {
  const pending = [];
  const rendered = [];
  const context = vm.createContext({
    fetch: () => new Promise((resolve) => pending.push(resolve)),
    rendered,
  });
  vm.runInContext(
    `let atlasoUpdateAvailabilityRequest = null;
     let atlasoUpdateAvailabilityRequestSequence = 0;
     function validApplianceUpdateAvailabilityPayload() { return true; }
     function renderApplianceUpdateAvailability(payload) { rendered.push(payload.id); }
     ${functionSource("refreshApplianceUpdateAvailability")}
     globalThis.run = refreshApplianceUpdateAvailability;`,
    context,
  );
  const older = context.run({ force: true });
  const newer = context.run({ force: true });
  pending[1]({ ok: true, json: () => Promise.resolve({ id: "newer" }) });
  await newer;
  pending[0]({ ok: true, json: () => Promise.resolve({ id: "older" }) });
  await older;
  assert.deepEqual(rendered, ["newer"]);
});

test("repository remediation opens the source workspace and focuses synchronization", () => {
  assert.match(appSource, /data-appliance-update-source-remediation/);
  assert.match(appSource, /document\.createElement\("button"\)/);
  assert.match(appSource, /result\.append\(remediation\)/);
  assert.match(appSource, /event\.target\.closest\("\[data-appliance-update-source-remediation\]"\)/);
  assert.match(appSource, /data-tab-target="appliance-update-sources"/);
  assert.match(appSource, /update-source-group-\$\{kind\}/);
  assert.match(appSource, /data-appliance-update-source-sync-action/);
  assert.match(appSource, /syncAction instanceof HTMLButtonElement && !syncAction\.disabled/);
  assert.match(appSource, /sourcesTab\.focus\(\{ preventScroll: true \}\)/);
});

test("repository remediation retains visible focus while synchronization is active", () => {
  let clickHandler = null;
  const remediation = new HTMLButtonElement();
  remediation.dataset.applianceUpdateSourceKind = "powershell";
  remediation.closest = () => remediation;
  const sourcesTab = new HTMLButtonElement();
  sourcesTab.click = () => {};
  const syncAction = new HTMLButtonElement();
  syncAction.disabled = true;
  class HTMLDetailsElement extends Element {
    scrollIntoView() {}
  }
  const sourceGroup = new HTMLDetailsElement();
  const context = vm.createContext({
    Element,
    HTMLButtonElement,
    HTMLDetailsElement,
    document: {
      addEventListener: (_event, handler) => { clickHandler = handler; },
      getElementById: () => sourceGroup,
      querySelector: (selector) => selector.includes("data-tab-target") ? sourcesTab : syncAction,
    },
    managementUiPath: (path) => path,
    window: {
      history: { replaceState() {} },
      requestAnimationFrame: (callback) => callback(),
    },
  });
  vm.runInContext(`${functionSource("initializeApplianceUpdateSourceRemediation")}\ninitializeApplianceUpdateSourceRemediation();`, context);
  clickHandler({ target: remediation });
  assert.equal(syncAction.focused, false);
  assert.equal(sourcesTab.focused, true);
});
