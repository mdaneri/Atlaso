const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const appSource = fs.readFileSync("atlaso/app/static/app.js", "utf8");

function functionSource(name) {
  const plainStart = appSource.indexOf(`function ${name}(`);
  const asyncStart = appSource.indexOf(`async function ${name}(`);
  const start = [plainStart, asyncStart].filter((value) => value >= 0).sort((left, right) => left - right)[0];
  assert.notEqual(start, undefined, `${name} must exist in app.js`);
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

class ClassList {
  constructor() {
    this.values = new Set();
  }

  add(...values) {
    values.forEach((value) => this.values.add(value));
  }

  remove(...values) {
    values.forEach((value) => this.values.delete(value));
  }

  toggle(value, force) {
    if (force === undefined ? !this.values.has(value) : force) this.values.add(value);
    else this.values.delete(value);
  }

  contains(value) {
    return this.values.has(value);
  }
}

class FakeElement {
  constructor(tagName = "div") {
    this.tagName = tagName.toUpperCase();
    this.attributes = new Map();
    this.classList = new ClassList();
    this.children = [];
    this.textContent = "";
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  getAttribute(name) {
    return this.attributes.get(name) || null;
  }

  replaceChildren(...children) {
    this.children = children;
    this.textContent = "";
  }

  addEventListener(name, callback) {
    this[`on${name}`] = callback;
  }
}

test("standard VCFDT feedback reuses one accessible transient notification", () => {
  const elements = new Map();
  const body = new FakeElement("body");
  body.appendChild = (element) => {
    elements.set(element.id, element);
  };
  let timeoutCallback = null;
  const context = vm.createContext({
    document: {
      body,
      createElement: (tagName) => new FakeElement(tagName),
      getElementById: (id) => elements.get(id) || null,
    },
    window: {
      clearTimeout: () => {},
      setTimeout: (callback) => {
        timeoutCallback = callback;
        return 1;
      },
    },
    HTMLElement: FakeElement,
  });
  vm.runInContext(
    `${functionSource("showTransientGridStatus")}\n${functionSource("showTransientGridError")}\n` +
      "globalThis.showTransientGridStatus = showTransientGridStatus; globalThis.showTransientGridError = showTransientGridError;",
    context,
  );

  context.showTransientGridStatus("Queued task job_1");
  const toast = elements.get("grid-status-toast");
  assert.equal(elements.size, 1);
  assert.equal(toast.getAttribute("role"), "status");
  assert.equal(toast.getAttribute("aria-live"), "polite");
  assert.equal(toast.textContent, "Queued task job_1");
  assert.equal(toast.classList.contains("visible"), true);
  timeoutCallback();
  assert.equal(toast.classList.contains("visible"), false);

  context.showTransientGridStatus("Queued task job_2");
  assert.equal(elements.size, 1);
  assert.equal(toast.textContent, "Queued task job_2");
  context.showTransientGridError("Profile is already queued. Wait for it to finish.");
  assert.equal(elements.size, 1);
  assert.equal(toast.getAttribute("role"), "alert");
  assert.equal(toast.getAttribute("aria-live"), "assertive");
  assert.equal(toast.children[0].textContent, "Profile is already queued. Wait for it to finish.");
  assert.equal(toast.children[1].textContent, "Dismiss");
  toast.children[1].onclick();
  assert.equal(toast.classList.contains("visible"), false);
});

test("manual VCFDT start reports accepted and failed actions through transient feedback", async () => {
  const statuses = [];
  const errors = [];
  const updates = [];
  const row = {
    getData: () => ({ id: 9, name: "Metadata", enabled: true, can_start: true, download_active: false }),
    update: async (value) => updates.push(value),
  };
  const context = vm.createContext({
    FormData: class {
      set() {}
    },
    document: { querySelector: () => null },
    fetch: async () => ({
      ok: true,
      json: async () => ({
        job_id: "job_profile_9",
        job_status: "pending",
        profile_name: "Metadata",
        profile_status: "ready",
      }),
    }),
    managementUiPath: (value) => value,
    HTMLElement: FakeElement,
    refreshTasksPage: async () => {},
    showTransientGridStatus: (message) => statuses.push(message),
    showTransientGridError: (message) => errors.push(message),
  });
  vm.runInContext(
    "let atlasoNewTaskId = ''; let atlasoSelectedTaskId = ''; let atlasoTasksTable = null;\n" +
      `${functionSource("startVcfDepotProfileDownload")}\n` +
      "globalThis.startVcfDepotProfileDownload = startVcfDepotProfileDownload;",
    context,
  );

  await context.startVcfDepotProfileDownload(row, "csrf");
  assert.deepEqual(statuses, ["Queued VCFDT task job_profile_9 for Metadata."]);
  assert.deepEqual(errors, []);
  assert.equal(updates[0].download_active, true);
  assert.equal(updates[0].active_task_status, "pending");

  context.fetch = async () => ({
    ok: false,
    json: async () => ({ detail: "Profile Metadata already has queued task job_profile_9. Wait for it to finish." }),
  });
  await context.startVcfDepotProfileDownload(row, "csrf");
  assert.equal(errors.at(-1), "Profile Metadata already has queued task job_profile_9. Wait for it to finish.");
});

test("VCFDT schedule action opens the selected profile in the in-page wizard", () => {
  class FakeForm extends FakeElement {}
  const opened = [];
  const errors = [];
  const form = new FakeForm("form");
  form.atlasoOpenScheduleWizard = (data, launcher) => opened.push({ data, launcher });
  const launcher = new FakeElement("button");
  const context = vm.createContext({
    document: { querySelector: () => form },
    HTMLFormElement: FakeForm,
    showTransientGridError: (message) => errors.push(message),
  });
  vm.runInContext(
    `${functionSource("scheduleVcfDepotProfileDownload")}\n` +
      "globalThis.scheduleVcfDepotProfileDownload = scheduleVcfDepotProfileDownload;",
    context,
  );

  const row = {
    getData: () => ({ id: 9, name: "Metadata", enabled: true }),
    getElement: () => new FakeElement("div"),
  };
  context.scheduleVcfDepotProfileDownload(row, launcher);
  assert.equal(opened.length, 1);
  assert.equal(opened[0].data.id, 9);
  assert.equal(opened[0].launcher, launcher);
  assert.deepEqual(errors, []);

  row.getData = () => ({ id: 10, name: "Disabled", enabled: false });
  context.scheduleVcfDepotProfileDownload(row, launcher);
  assert.equal(opened.length, 1);
  assert.equal(errors.at(-1), "Enable the VCFDT download profile before scheduling it.");
});

test("VCFDT schedule context action uses the persistent profile row as launcher", () => {
  assert.match(
    appSource,
    /action: \(_event, row\) => scheduleVcfDepotProfileDownload\(row, row\.getElement\(\)\)/,
  );
});

test("VCFDT task refresh preserves an exclusive-operation blocker", () => {
  const updates = [];
  const row = {
    getData: () => ({ id: 9, is_new: false }),
    update: (value) => updates.push(value),
  };
  const context = vm.createContext({
    Boolean,
    Map,
    Number,
    String,
  });
  vm.runInContext(
    "let vcfDepotProfilesTable = { getRows: () => [globalThis.testRow] };\n" +
      `${functionSource("setVcfDepotDownloadStates")}\n` +
      "globalThis.setVcfDepotDownloadStates = setVcfDepotDownloadStates;",
    context,
  );
  context.testRow = row;

  context.setVcfDepotDownloadStates([], {
    job_id: "job_software_id",
    status: "pending",
    type: "vcf-depot-software-id",
    detail: "Wait for Software Depot ID replacement to finish.",
  });

  assert.equal(updates.at(-1).download_active, true);
  assert.equal(updates.at(-1).active_job_id, "");
  assert.equal(updates.at(-1).active_task_status, "");
  assert.equal(
    updates.at(-1).active_task_blocker,
    "Wait for Software Depot ID replacement to finish.",
  );

  context.setVcfDepotDownloadStates([], null);
  assert.equal(updates.at(-1).download_active, false);
  assert.equal(updates.at(-1).active_task_blocker, "");
});
