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

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function sourceBetween(startMarker, endMarker) {
  const start = appSource.indexOf(startMarker);
  const end = appSource.indexOf(endMarker, start);
  assert.notEqual(start, -1, `${startMarker} must exist in app.js`);
  assert.notEqual(end, -1, `${endMarker} must exist after ${startMarker} in app.js`);
  return appSource.slice(start, end);
}

function taskLogHarness() {
  class FakeElement {
    constructor() {
      this.textContent = "";
    }
    querySelector() { return null; }
    addEventListener(name, action) { this[name] = action; }
    setAttribute() {}
    append(node) { this.textContent += node.textContent; }
    contains(node) { return node === this; }
  }

  class FakeDialog extends FakeElement {
    constructor() {
      super();
      this.open = false;
    }

    showModal() {
      this.open = true;
    }

    close() {
      this.open = false;
    }
  }

  const modal = new FakeDialog();
  const title = new FakeElement();
  const meta = new FakeElement();
  const content = new FakeElement();
  const buttons = [];
  const requests = [];
  const timers = new Map();
  let timerId = 0;
  const taskLogContext = vm.createContext({
    AbortController,
    URL,
    HTMLElement: FakeElement,
    HTMLDialogElement: FakeDialog,
    document: {
      createElement: () => { const element = new FakeElement(); buttons.push(element); return element; },
      createTextNode: (textContent) => ({ textContent }),
      addEventListener() {},
      removeEventListener() {},
      getElementById: (id) => id === "task-log-modal" ? modal : null,
      querySelector: (selector) => ({
        "[data-task-log-title]": title,
        "[data-task-log-meta]": meta,
        "[data-task-log-content]": content,
      })[selector] || null,
    },
    fetch: (url, options) => {
      const request = deferred();
      requests.push({ ...request, options, url });
      return request.promise;
    },
    highlightConfigPreviewElement: () => {},
    managementUiPath: (path) => path,
    taskById: () => null,
    window: {
      location: { href: "https://atlaso.test/" },
      getSelection: () => null,
      setTimeout: (callback, delay) => { timers.set(++timerId, { callback, delay }); return timerId; },
      clearTimeout: (id) => timers.delete(id),
      addEventListener() {},
      removeEventListener() {},
    },
  });
  vm.runInContext(fs.readFileSync("atlaso/app/static/log-viewer.js", "utf8"), taskLogContext);
  vm.runInContext(
    "let atlasoTaskLogRequest = null; let atlasoTaskLogRequestSequence = 0;\n" +
      `${sourceBetween("async function openTaskLog", "async function cancelTask")}\n` +
      "globalThis.openTaskLog = openTaskLog; globalThis.closeTaskLogModal = closeTaskLogModal;",
    taskLogContext,
  );
  const complete = (index, payload, ok = true) => {
    requests[index].resolve({ ok, json: async () => payload });
  };
  return { buttons, complete, content, context: taskLogContext, meta, modal, requests, title, timers };
}

const context = vm.createContext({});
vm.runInContext(
  `${functionSource("expandedTaskRowIds")}\n${functionSource("restoreExpandedTaskRows")}\n` +
  "globalThis.expandedTaskRowIds = expandedTaskRowIds; globalThis.restoreExpandedTaskRows = restoreExpandedTaskRows;",
  context,
);

test("expandedTaskRowIds retains only expanded task parents", () => {
  const rows = [
    { getTreeChildren: () => [{}], isTreeExpanded: () => true, getData: () => ({ id: "job-expanded" }) },
    { getTreeChildren: () => [{}], isTreeExpanded: () => false, getData: () => ({ id: "job-collapsed" }) },
    { getTreeChildren: () => [], isTreeExpanded: () => true, getData: () => ({ id: "job-leaf" }) },
  ];
  assert.deepEqual(Array.from(context.expandedTaskRowIds({ getRows: () => rows })), ["job-expanded"]);
});

test("restoreExpandedTaskRows reopens surviving parents after refresh", () => {
  const expanded = [];
  const rows = new Map([
    ["job-expanded", { treeExpand: () => expanded.push("job-expanded") }],
  ]);
  context.restoreExpandedTaskRows({ getRow: (id) => rows.get(id) }, ["job-expanded", "job-removed"]);
  assert.deepEqual(expanded, ["job-expanded"]);
});

test("task refresh continues while any VCFDT operation is active", () => {
  assert.match(
    appSource,
    /payload\.active_downloads\.some\(\(task\) => taskStatusActive\(task\.status\)\)/,
  );
  assert.match(appSource, /taskStatusActive\(payload\.active_exclusive_operation\?\.status\)/);
});

test("latest task log selection wins when the newer response finishes first", async () => {
  const harness = taskLogHarness();
  const first = harness.context.openTaskLog({ id: "A", log_url: "/logs/A" });
  const second = harness.context.openTaskLog({ id: "B", log_url: "/logs/B" });

  assert.equal(harness.requests[0].options.signal.aborted, true);
  harness.complete(1, { job_id: "B", status: "succeeded", text: "B log", title: "B title" });
  await second;
  harness.complete(0, { job_id: "A", status: "failed", text: "A log", title: "A title" });
  await first;

  assert.equal(harness.title.textContent, "B title");
  assert.match(harness.meta.textContent, /^B · succeeded · /);
  assert.equal(harness.content.textContent, "B log");
});

test("latest task log selection wins when the older response finishes first", async () => {
  const harness = taskLogHarness();
  const first = harness.context.openTaskLog({ id: "A", log_url: "/logs/A" });
  const second = harness.context.openTaskLog({ id: "B", log_url: "/logs/B" });

  harness.complete(0, { job_id: "A", status: "succeeded", text: "A log", title: "A title" });
  await first;
  assert.equal(harness.title.textContent, "Task log");
  assert.equal(harness.meta.textContent, "B");
  assert.equal(harness.content.textContent, "Loading task log…");

  harness.complete(1, { job_id: "B", status: "failed", text: "B log", title: "B title" });
  await second;
  assert.equal(harness.title.textContent, "B title");
  assert.match(harness.meta.textContent, /^B · failed · /);
  assert.equal(harness.content.textContent, "B log");
});

test("stale task log errors cannot replace a newer loading state", async () => {
  const harness = taskLogHarness();
  const first = harness.context.openTaskLog({ id: "A", log_url: "/logs/A" });
  const second = harness.context.openTaskLog({ id: "B", log_url: "/logs/B" });

  harness.complete(0, { detail: "A failed late" }, false);
  await first;
  assert.equal(harness.content.textContent, "Loading task log…");
  assert.equal(harness.meta.textContent, "B");

  harness.complete(1, { job_id: "B", status: "succeeded", text: "B log" });
  await second;
  assert.equal(harness.content.textContent, "B log");
});

test("closing and reopening the task log invalidates the prior request", async () => {
  const harness = taskLogHarness();
  const first = harness.context.openTaskLog({ id: "A", log_url: "/logs/A" });
  harness.context.closeTaskLogModal();
  assert.equal(harness.modal.open, false);
  assert.equal(harness.requests[0].options.signal.aborted, true);

  const second = harness.context.openTaskLog({ id: "B", log_url: "/logs/B" });
  harness.complete(0, { job_id: "A", status: "failed", text: "A log", title: "A title" });
  await first;
  assert.equal(harness.content.textContent, "Loading task log…");
  assert.equal(harness.meta.textContent, "B");

  harness.complete(1, { job_id: "B", status: "succeeded", text: "B log", title: "B title" });
  await second;
  assert.equal(harness.title.textContent, "B title");
  assert.equal(harness.content.textContent, "B log");
});

test("task log dismissal invalidates pending ownership for button and keyboard closes", () => {
  assert.match(appSource, /addEventListener\("click", closeTaskLogModal\)/);
  assert.match(appSource, /taskLogModal\?\.addEventListener\("cancel"/);
  assert.match(appSource, /taskLogModal\?\.addEventListener\("close"/);
});

function fireTimer(harness, delay) {
  const entry = [...harness.timers].find(([, timer]) => timer.delay === delay);
  assert.ok(entry, `expected a ${delay}ms timer`);
  harness.timers.delete(entry[0]);
  return entry[1].callback();
}

test("running task logs append and perform a final trailing read before stopping", async () => {
  const harness = taskLogHarness();
  const initial = harness.context.openTaskLog({ id: "A" });
  harness.complete(0, { job_id: "A", status: "running", text: "first" });
  await initial;
  const next = fireTimer(harness, 5000);
  harness.complete(1, { job_id: "A", status: "succeeded", text: "first\nfinished" });
  await next;
  assert.equal(harness.content.textContent, "first\nfinished");
  const trailing = fireTimer(harness, 5000);
  harness.complete(2, { job_id: "A", status: "succeeded", text: "first\nfinished\ntrailing" });
  await trailing;
  assert.equal(harness.content.textContent, "first\nfinished\ntrailing");
  assert.equal(harness.timers.size, 0);
});

test("reading older output preserves scroll and selection until the reader follows", async () => {
  const harness = taskLogHarness();
  const scroll = { scrollTop: 900, scrollHeight: 1000, clientHeight: 100 };
  harness.content.parentElement = scroll;
  const initial = harness.context.openTaskLog({ id: "A" });
  harness.complete(0, { status: "running", text: "first" });
  await initial;
  scroll.scrollTop = 100;
  harness.context.window.getSelection = () => ({ isCollapsed: false, anchorNode: harness.content });
  const next = fireTimer(harness, 5000);
  harness.complete(1, { status: "running", text: "first\nsecond" });
  await next;
  assert.equal(harness.content.textContent, "first");
  assert.equal(scroll.scrollTop, 100);
  assert.match(harness.meta.textContent, /New output available/);
  harness.context.closeTaskLogModal();
  assert.equal(harness.timers.size, 0);
});

test("deadline failure retains output and reconnects with bounded backoff", async () => {
  const harness = taskLogHarness();
  const initial = harness.context.openTaskLog({ id: "A" });
  harness.complete(0, { status: "running", text: "useful output" });
  await initial;
  const next = fireTimer(harness, 5000);
  fireTimer(harness, 20000);
  assert.equal(harness.requests[1].options.signal.aborted, true);
  harness.requests[1].reject(new Error("aborted"));
  await next;
  assert.equal(harness.content.textContent, "useful output");
  assert.match(harness.meta.textContent, /may be stale/);
  assert.equal([...harness.timers.values()][0].delay, 5000);
  harness.context.closeTaskLogModal();
});

test("revoked access stops polling without clearing the retained page", async () => {
  const harness = taskLogHarness();
  const initial = harness.context.openTaskLog({ id: "A" });
  harness.complete(0, { status: "running", text: "useful output" });
  await initial;
  const next = fireTimer(harness, 5000);
  harness.requests[1].resolve({ ok: false, status: 403 });
  await next;
  assert.equal(harness.content.textContent, "useful output");
  assert.match(harness.meta.textContent, /Access expired/);
  assert.equal(harness.timers.size, 0);
});

test("the scrolling code element owns follow and reading-position preservation", async () => {
  const harness = taskLogHarness();
  Object.assign(harness.content, { scrollTop: 0, scrollHeight: 1000, clientHeight: 100 });
  harness.content.parentElement = { scrollTop: 0, scrollHeight: 100, clientHeight: 100 };
  harness.context.window.getComputedStyle = () => ({ overflowY: "auto" });
  const initial = harness.context.openTaskLog({ id: "A" });
  harness.complete(0, { status: "running", text: "first" });
  await initial;
  assert.equal(harness.content.scrollTop, 1000);
  assert.equal(harness.content.parentElement.scrollTop, 0);
  harness.content.scrollTop = 100;
  const next = fireTimer(harness, 5000);
  harness.complete(1, { status: "running", text: "first\nsecond" });
  await next;
  assert.equal(harness.content.scrollTop, 100);
  assert.equal(harness.content.textContent, "first");
  assert.match(harness.meta.textContent, /reading position preserved/);
  harness.buttons.find((button) => button.textContent === "Follow live").click();
  const resumed = fireTimer(harness, 0);
  assert.equal(new URL(harness.requests[2].url).searchParams.get("tail"), "1");
  harness.complete(2, { status: "running", text: "latest" });
  await resumed;
  assert.equal(harness.content.textContent, "latest");
  assert.equal(harness.content.scrollTop, 1000);
  harness.context.closeTaskLogModal();
});

test("an authentication redirect stops the live viewer", async () => {
  const harness = taskLogHarness();
  const initial = harness.context.openTaskLog({ id: "A" });
  harness.requests[0].resolve({ ok: true, redirected: true, status: 200,
    url: "https://atlaso.test/ui/management/login?next=/tasks" });
  await initial;
  assert.match(harness.meta.textContent, /Access expired/);
  assert.equal(harness.timers.size, 0);
});

test("task logs open at the tail and keep the returned stable page cursor", async () => {
  const harness = taskLogHarness();
  const initial = harness.context.openTaskLog({ id: "A" });
  assert.equal(new URL(harness.requests[0].url).searchParams.get("tail"), "1");
  harness.complete(0, { status: "running", text: "latest", cursor: "stable-start", next_cursor: "latest-end" });
  await initial;
  const refresh = fireTimer(harness, 5000);
  const url = new URL(harness.requests[1].url);
  assert.equal(url.searchParams.get("cursor"), "stable-start");
  assert.equal(url.searchParams.get("tail"), null);
  harness.complete(1, { status: "running", text: "latest\nnew", cursor: "stable-start", next_cursor: "new-end" });
  await refresh;
  harness.context.closeTaskLogModal();
});


test("Previous page navigates directly from the initial live tail", async () => {
  const harness = taskLogHarness();
  const initial = harness.context.openTaskLog({ id: "A" });
  harness.complete(0, { status: "running", text: "latest", cursor: "tail-start", previous_cursor: "before-tail" });
  await initial;
  const button = harness.buttons.find((element) => element.textContent === "Previous page");
  assert.equal(button.disabled, false);
  button.click();
  const older = fireTimer(harness, 0);
  assert.equal(new URL(harness.requests[1].url).searchParams.get("cursor"), "before-tail");
  harness.complete(1, { status: "running", text: "preceding group", cursor: "older-start" });
  await older;
  assert.equal(harness.content.textContent, "preceding group");
  harness.context.closeTaskLogModal();
});


test("navigation serializes asynchronous renders and ignores stale completion", async () => {
  const harness = taskLogHarness();
  const delayed = deferred(), started = deferred();
  const rendered = [], published = [];
  let calls = 0;
  const viewer = harness.context.window.AtlasoLogViewer.create({
    output: harness.content, status: harness.meta, initialCursor: "tail",
    fetchPage: async () => ({ text: ++calls === 1 ? "stale" : "current", status: "running" }),
    renderPage: async (page, { isCurrent }) => {
      if (page.text === "stale") { started.resolve(); await delayed.promise; }
      rendered.push(page.text);
      if (isCurrent()) harness.content.textContent = page.text;
    },
    onPage: (page) => published.push(page.text),
  });
  await started.promise;
  harness.buttons.find((button) => button.textContent === "From beginning").click();
  const current = fireTimer(harness, 0);
  await Promise.resolve();
  assert.deepEqual(rendered, []);
  delayed.resolve();
  await viewer.ready;
  await current;
  assert.deepEqual(rendered, ["stale", "current"]);
  assert.deepEqual(published, ["current"]);
  assert.equal(harness.content.textContent, "current");
  viewer.close();
});

for (const status of ["no-op", "partial-failure"]) {
  test(`${status} task logs stop after the final trailing read`, async () => {
    const harness = taskLogHarness();
    const initial = harness.context.openTaskLog({ id: "A" });
    harness.complete(0, { status, text: "terminal output" });
    await initial;
    const trailing = fireTimer(harness, 5000);
    harness.complete(1, { status, text: "terminal output" });
    await trailing;
    assert.equal(harness.requests.length, 2);
    assert.equal(harness.timers.size, 0);
    harness.context.closeTaskLogModal();
  });
}

test("log availability re-enables new sources without stealing an available selection", () => {
  let active = null;
  const clicks = [];
  const tab = (id, disabled) => ({ dataset: { logSourceTab: id }, disabled,
    setAttribute(name, value) { this[name] = value; },
    click() { active = this; clicks.push(id); } });
  const app = tab("app", true), kms = tab("kms", true), nginx = tab("nginx", false);
  active = nginx;
  const root = { querySelectorAll: () => [app, kms, nginx], querySelector: () => active };
  const context = vm.createContext({});
  vm.runInContext(functionSource("applyLogSourceAvailability"), context);
  context.applyLogSourceAvailability(root, [{ id: "kms", available: true }]);
  assert.equal(kms.disabled, false);
  assert.equal(kms["aria-disabled"], "false");
  assert.deepEqual(clicks, []);
  context.applyLogSourceAvailability(root, [{ id: "nginx", available: false }]);
  assert.equal(nginx.disabled, true);
  assert.deepEqual(clicks, ["kms"]);
  context.applyLogSourceAvailability(root, [{ id: "app", available: true }]);
  assert.equal(app.disabled, false);
  assert.deepEqual(clicks, ["kms"]);
});


test("terminal historical pages stop polling but manual Next remains usable", async () => {
  const harness = taskLogHarness();
  const initial = harness.context.openTaskLog({ id: "A" });
  harness.complete(0, { status: "succeeded", text: "tail", previous_cursor: "older" });
  await initial;
  harness.buttons.find((button) => button.textContent === "Previous page").click();
  const older = fireTimer(harness, 0);
  harness.complete(1, { status: "succeeded", text: "older", cursor: "older", next_cursor: "tail", has_more: true });
  await older;
  const trailing = fireTimer(harness, 5000);
  harness.complete(2, { status: "succeeded", text: "older", cursor: "older", next_cursor: "tail", has_more: true });
  await trailing;
  assert.equal(harness.timers.size, 0);
  const next = harness.buttons.find((button) => button.textContent === "Next page");
  assert.equal(next.disabled, false);
  next.click();
  const resumed = fireTimer(harness, 0);
  harness.complete(3, { status: "succeeded", text: "tail" });
  await resumed;
  assert.equal(harness.content.textContent, "tail");
  harness.context.closeTaskLogModal();
});

for (const dir of ["asc", "desc"]) {
  test(`Audit follows the newest local page with Time ${dir}`, async () => {
    const holder = { scrollTop: 0, scrollHeight: 1000, clientHeight: 100 };
    class Element {
      constructor() { this.dataset = {}; this.clientHeight = 500; }
      querySelector() { return holder; }
    }
    const element = new Element();
    let options, built, page = 1;
    const table = { getSorters: () => [{ field: "created_at", dir }], getPage: () => page,
      getPageMax: () => 4, replaceData: async () => {},
      setPage: async (value) => { page = value === "last" ? 4 : value; },
      on: (_event, callback) => { built = callback; } };
    const context = vm.createContext({ HTMLElement: Element, Tabulator: {}, atlasoBooleanFormatter: () => {},
      ResizeObserver: class { observe() {} },
      document: { getElementById: (id) => id === "audit-events-table" ? element : null, querySelector: () => null },
      window: { AtlasoUiPatterns: { createGrid: () => ({ table }) }, AtlasoLogViewer: { create: (value) => { options = value; } } } });
    vm.runInContext(functionSource("auditNewestFirst") + functionSource("initializeAuditEventsTable"), context);
    context.initializeAuditEventsTable();
    built();
    await options.renderPage({ rows: [] }, { following: true, navigated: true, isCurrent: () => true });
    assert.equal(page, dir === "desc" ? 1 : 4);
    assert.equal(options.holdPage(), false);
    page = dir === "desc" ? 2 : 3;
    assert.equal(options.holdPage(), true);
    await options.renderPage({ rows: [] }, { following: false, navigated: false, isCurrent: () => true });
    assert.equal(page, dir === "desc" ? 2 : 3);
  });
}


for (const stored of ["200", "500", "invalid", null, "unavailable"]) {
  test(`log page size restores and saves browser preference: ${stored}`, () => {
    const requests = [], writes = [];
    const selector = { value: "100", addEventListener: (_name, callback) => { selector.change = callback; } };
    class Element {
      constructor() { this.dataset = {}; }
      querySelector() { return null; }
      addEventListener() {}
    }
    const root = new Element(), output = new Element();
    const tab = { dataset: { logSourceTab: "app" }, disabled: false };
    root.querySelector = (query) => query === "[data-log-lines]" ? selector : query.includes("data-log-source-tab") ? tab : null;
    const panel = { hidden: false, querySelector: () => output };
    const context = vm.createContext({ HTMLElement: Element, URL, managementUiPath: (path) => path,
      document: { querySelector: () => root, getElementById: () => panel, createElement: () => new Element() },
      window: { location: { href: "https://atlaso.test/ui/management/logs" }, localStorage: {
        getItem: () => { if (stored === "unavailable") throw new Error("denied"); return stored; },
        setItem: (key, value) => { if (stored === "unavailable") throw new Error("denied"); writes.push([key, value]); },
      }, AtlasoLogViewer: { create: (options) => {
        if (options.initialCursor) options.fetchPage("tail", null);
        return { close() {} };
      }, fetchJson: (url) => requests.push(url.searchParams.get("lines")) } } });
    vm.runInContext(functionSource("initializeLogsPage"), context);
    context.initializeLogsPage();
    assert.equal(requests[0], ["200", "500"].includes(stored) ? stored : "100");
    selector.value = "500";
    selector.change();
    assert.equal(requests[1], "500");
    assert.deepEqual(writes, stored === "unavailable" ? [] : [["atlaso:logs:line-count", "500"]]);
  });
}


test("completed task keeps retrying pending tail preparation before trailing stop", async () => {
  const harness = taskLogHarness();
  let request = harness.context.openTaskLog({ id: "A" });
  for (let index = 0; index < 4; index += 1) {
    harness.complete(index, { status: "succeeded", text: "", pending: true, has_more: false });
    await request;
    request = fireTimer(harness, 5000);
  }
  harness.complete(4, { status: "succeeded", text: "prepared output" });
  await request;
  const trailing = fireTimer(harness, 5000);
  harness.complete(5, { status: "succeeded", text: "prepared output" });
  await trailing;
  assert.equal(harness.content.textContent, "prepared output");
  assert.equal(harness.timers.size, 0);
  harness.context.closeTaskLogModal();
});
