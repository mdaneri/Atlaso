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
    addEventListener() {}
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
  const requests = [];
  const timers = new Map();
  let timerId = 0;
  const taskLogContext = vm.createContext({
    AbortController,
    URL,
    HTMLElement: FakeElement,
    HTMLDialogElement: FakeDialog,
    document: {
      createElement: () => new FakeElement(),
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
  return { complete, content, context: taskLogContext, meta, modal, requests, title, timers };
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
