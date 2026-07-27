const assert = require("node:assert/strict");
const test = require("node:test");

class FakeClassList {
  constructor(initial = []) {
    this.values = new Set(initial);
  }

  add(value) {
    this.values.add(value);
  }

  remove(value) {
    this.values.delete(value);
  }

  contains(value) {
    return this.values.has(value);
  }

  toggle(value, force) {
    if (force === undefined) {
      force = !this.values.has(value);
    }
    if (force) this.values.add(value);
    else this.values.delete(value);
    return force;
  }
}

class FakeElement {
  constructor({ classes = [], dataset = {}, tagName = "DIV" } = {}) {
    this.classList = new FakeClassList(classes);
    this.dataset = { ...dataset };
    this.tagName = tagName;
    this.attributes = new Map();
    this.listeners = new Map();
    this.queries = new Map();
    this.disabled = false;
    this.hidden = false;
    this.textContent = "";
    this.tabIndex = -1;
    this.parentPage = null;
    this.dispatched = [];
  }

  setQuery(selector, values) {
    this.queries.set(selector, Array.isArray(values) ? values : [values]);
  }

  querySelectorAll(selector) {
    if (this.queries.has(selector)) return this.queries.get(selector);
    if (selector.includes("a[href]")) return this.queries.get("focusable") || [];
    return [];
  }

  querySelector(selector) {
    return this.querySelectorAll(selector)[0] || null;
  }

  closest(selector) {
    if (selector === "dialog") return this.dialog || null;
    if (selector === "[hidden], .hidden" && this.parentPage) {
      return this.parentPage.hidden || this.parentPage.classList.contains("hidden")
        ? this.parentPage
        : null;
    }
    return null;
  }

  addEventListener(type, handler) {
    const handlers = this.listeners.get(type) || [];
    handlers.push(handler);
    this.listeners.set(type, handlers);
  }

  async emit(type, event = {}) {
    event.type = type;
    event.target ||= this;
    event.currentTarget ||= this;
    event.preventDefault ||= () => {
      event.defaultPrevented = true;
    };
    for (const handler of this.listeners.get(type) || []) {
      await handler(event);
    }
    return event;
  }

  dispatchEvent(event) {
    this.dispatched.push(event);
    return true;
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

  hasAttribute(name) {
    return this.attributes.has(name);
  }

  toggleAttribute(name, force) {
    if (force) this.attributes.set(name, "");
    else this.attributes.delete(name);
    if (name === "hidden") this.hidden = Boolean(force);
  }

  focus() {
    global.document.activeElement = this;
    this.focused = true;
  }

  getBoundingClientRect() {
    return { left: 10, top: 20, height: 28 };
  }
}

class FakeControl extends FakeElement {
  constructor(name, valid = true) {
    super({ tagName: "INPUT" });
    this.name = name;
    this.valid = valid;
  }

  checkValidity() {
    return this.valid;
  }

  reportValidity() {
    this.reported = true;
  }
}

function installBrowserGlobals() {
  global.document = {
    activeElement: null,
    querySelector: () => null,
  };
  global.requestAnimationFrame = (callback) => callback();
  global.CSS = { escape: (value) => String(value) };
  global.MouseEvent = class MouseEvent {
    constructor(type, options) {
      this.type = type;
      Object.assign(this, options);
    }
  };
}

installBrowserGlobals();
const { createGrid, createWizard } = require("../../atlaso/app/static/ui-patterns.js");

class TabulatorStub {
  constructor(element, options) {
    this.element = element;
    this.options = options;
    this.listeners = new Map();
    this.rowCount = 1;
    TabulatorStub.last = this;
  }

  on(type, handler) {
    this.listeners.set(type, handler);
  }

  emit(type, value) {
    this.listeners.get(type)?.(value);
  }

  getDataCount() {
    return this.rowCount;
  }

  destroy() {
    this.destroyed = true;
  }
}

function wizardFixture(stepIds = ["identity", "review"]) {
  const dialog = new FakeElement({ tagName: "DIALOG" });
  const form = new FakeElement({ tagName: "FORM" });
  form.dialog = dialog;
  form.reset = () => {
    form.resetCount = (form.resetCount || 0) + 1;
  };
  form.submit = () => {
    form.submitCount = (form.submitCount || 0) + 1;
  };
  form.elements = {
    controls: new Map(),
    namedItem(name) {
      return this.controls.get(name) || null;
    },
  };
  const pages = stepIds.map((id, index) => {
    const page = new FakeElement({
      classes: index ? ["hidden"] : [],
      dataset: { atlasoWizardStep: id },
    });
    page.hidden = index > 0;
    return page;
  });
  const nav = stepIds.map((id, index) => {
    const button = new FakeElement({ dataset: { atlasoWizardNav: id }, tagName: "BUTTON" });
    button.disabled = index > 0;
    return button;
  });
  const controls = stepIds.map((id, index) => {
    const control = new FakeControl(`${id}_field`);
    control.parentPage = pages[index];
    pages[index].setQuery("input, select, textarea", [control]);
    pages[index].setQuery("focusable", [control]);
    form.elements.controls.set(control.name, control);
    return control;
  });
  const kicker = new FakeElement();
  const title = new FakeElement();
  const description = new FakeElement();
  const error = new FakeElement({ classes: ["hidden"] });
  const back = new FakeElement({ classes: ["hidden"], tagName: "BUTTON" });
  const next = new FakeElement({ tagName: "BUTTON" });
  const submit = new FakeElement({ classes: ["hidden"], tagName: "BUTTON" });
  const cancel = new FakeElement({ tagName: "BUTTON" });
  form.setQuery("[data-atlaso-wizard-step]", pages);
  form.setQuery("[data-atlaso-wizard-nav]", nav);
  form.setQuery("[data-atlaso-wizard-kicker]", kicker);
  form.setQuery("[data-atlaso-wizard-title]", title);
  form.setQuery("[data-atlaso-wizard-description]", description);
  form.setQuery("[data-atlaso-wizard-error]", error);
  form.setQuery("[data-atlaso-wizard-back]", back);
  form.setQuery("[data-atlaso-wizard-next]", next);
  form.setQuery("[data-atlaso-wizard-submit]", submit);
  form.setQuery("[data-atlaso-wizard-cancel]", [cancel]);
  dialog.setQuery("focusable", [...controls, back, next, submit, cancel]);
  dialog.showModal = () => {
    dialog.open = true;
  };
  dialog.close = (returnValue) => {
    dialog.open = false;
    dialog.returnValue = returnValue;
  };
  return {
    dialog,
    form,
    pages,
    nav,
    controls,
    kicker,
    title,
    description,
    error,
    back,
    next,
    submit,
    cancel,
  };
}

test("createGrid keeps fallback until Tabulator is ready and exposes ready state", () => {
  installBrowserGlobals();
  global.Tabulator = TabulatorStub;
  const element = new FakeElement({ classes: ["hidden"], dataset: { fallbackId: "fallback" } });
  const fallback = new FakeElement();
  const status = new FakeElement({ classes: ["hidden"] });

  const controller = createGrid({
    element,
    fallback,
    status,
    pattern: "read-only",
    options: { data: [{ id: 1 }], placeholder: "No rows." },
  });

  assert.equal(controller.state, "loading");
  assert.equal(controller.table, TabulatorStub.last);
  assert.equal(fallback.classList.contains("hidden"), false);
  TabulatorStub.last.emit("tableBuilt");
  assert.equal(controller.state, "ready");
  assert.equal(fallback.classList.contains("hidden"), true);
  assert.equal(element.classList.contains("hidden"), false);
  assert.equal(element.dataset.atlasoGridPattern, "read-only");
});

test("createGrid restores fallback on construction failure", () => {
  installBrowserGlobals();
  delete global.Tabulator;
  const element = new FakeElement();
  const fallback = new FakeElement({ classes: ["hidden"] });

  const controller = createGrid({ element, fallback, pattern: "direct-edit" });

  assert.equal(controller.state, "error");
  assert.equal(fallback.classList.contains("hidden"), false);
  assert.equal(element.classList.contains("hidden"), true);
});

test("createGrid preserves initial remote-load errors after table creation", () => {
  installBrowserGlobals();
  global.Tabulator = TabulatorStub;
  const element = new FakeElement();
  const fallback = new FakeElement({ classes: ["hidden"] });
  const controller = createGrid({ element, fallback, pattern: "read-only" });

  TabulatorStub.last.emit("dataLoadError", new Error("Remote unavailable."));
  TabulatorStub.last.emit("tableBuilt");

  assert.equal(controller.state, "error");
  assert.equal(fallback.classList.contains("hidden"), false);
  assert.equal(element.classList.contains("hidden"), true);
});

test("createGrid restores a remote grid after a successful retry", () => {
  installBrowserGlobals();
  global.Tabulator = TabulatorStub;
  const element = new FakeElement();
  const fallback = new FakeElement({ classes: ["hidden"] });
  const controller = createGrid({ element, fallback, pattern: "read-only" });

  TabulatorStub.last.emit("tableBuilt");
  TabulatorStub.last.emit("dataLoadError", new Error("Transient failure."));
  assert.equal(controller.state, "error");

  TabulatorStub.last.emit("dataLoaded", [{ id: 1 }]);

  assert.equal(controller.state, "ready");
  assert.equal(fallback.classList.contains("hidden"), true);
  assert.equal(element.classList.contains("hidden"), false);
});

test("createGrid keeps synthetic add rows last for ascending and descending sorts", () => {
  installBrowserGlobals();
  global.Tabulator = TabulatorStub;
  createGrid({
    element: new FakeElement(),
    pattern: "direct-edit",
    options: {
      columns: [
        { title: "Name", field: "name" },
        { title: "State", field: "enabled", headerSort: false },
      ],
    },
  });

  const sorter = TabulatorStub.last.options.columns[0].sorter;
  const addRow = { getData: () => ({ is_new: true, name: "" }) };
  const recordRow = { getData: () => ({ is_new: false, name: "alpha" }) };

  assert.equal(sorter("", "alpha", addRow, recordRow, null, "asc"), 1);
  assert.equal(sorter("alpha", "", recordRow, addRow, null, "desc"), 1);
  assert.equal(sorter("", "alpha", addRow, recordRow, null, "desc"), -1);
  assert.equal(sorter("item 2", "item 10", recordRow, recordRow, null, "asc"), -1);
  assert.equal(TabulatorStub.last.options.columns[1].sorter, undefined);
});

test("createGrid applies permission state and keyboard context-menu behavior", async () => {
  installBrowserGlobals();
  global.Tabulator = TabulatorStub;
  const element = new FakeElement();
  const rowElement = new FakeElement();
  const row = {
    getElement: () => rowElement,
    getData: () => ({ id: 1 }),
  };
  const controller = createGrid({
    element,
    pattern: "wizard-backed",
    permission: { allowed: false, message: "Read-only role." },
    rowActions: [{ label: "Edit" }],
  });

  assert.deepEqual(TabulatorStub.last.options.rowContextMenu, []);
  assert.equal(TabulatorStub.last.options.rowFormatter, undefined);
  assert.equal(rowElement.dispatched.length, 0);
  TabulatorStub.last.emit("tableBuilt");
  assert.equal(controller.state, "permission-denied");

  const editableRowElement = new FakeElement();
  const editableRow = {
    getElement: () => editableRowElement,
    getData: () => ({ id: 2 }),
  };
  let openedRow = null;
  createGrid({
    element: new FakeElement(),
    pattern: "wizard-backed",
    rowActions: [{ label: "Edit" }],
    onOpenRow: (rowData) => {
      openedRow = rowData;
    },
  });
  TabulatorStub.last.options.rowFormatter(editableRow);
  await editableRowElement.emit("keydown", { key: "Enter" });
  assert.deepEqual(openedRow, { id: 2 });
  await editableRowElement.emit("keydown", { key: "F10", shiftKey: true });
  assert.equal(editableRowElement.dispatched[0].type, "contextmenu");
});

test("createWizard locks future steps and supports async validation and review", async () => {
  installBrowserGlobals();
  const fixture = wizardFixture(["identity", "config", "review"]);
  let configValid = false;
  let reviewPrepared = false;
  const controller = createWizard({
    form: fixture.form,
    dialog: fixture.dialog,
    steps: [
      { id: "identity", title: "Identity" },
      { id: "config", title: "Configuration" },
      { id: "review", title: "Review" },
    ],
    validateStep: async ({ step }) => {
      if (step.id === "config" && !configValid) {
        return { valid: false, message: "Configuration is incomplete.", field: "config_field" };
      }
      return true;
    },
    prepareReview: () => {
      reviewPrepared = true;
    },
  });

  assert.equal(fixture.nav[1].disabled, true);
  assert.equal(await controller.next(), true);
  assert.equal(controller.currentStepId, "config");
  assert.equal(await controller.next(), false);
  assert.equal(fixture.error.textContent, "Configuration is incomplete.");
  assert.equal(fixture.controls[1].getAttribute("aria-invalid"), "true");
  configValid = true;
  assert.equal(await controller.next(), true);
  assert.equal(controller.currentStepId, "review");
  assert.equal(reviewPrepared, true);
});

test("createWizard confirms dirty cancellation and restores launcher focus", async () => {
  installBrowserGlobals();
  const fixture = wizardFixture(["identity", "review"]);
  const launcher = new FakeElement({ tagName: "BUTTON" });
  let allowDiscard = false;
  const controller = createWizard({
    form: fixture.form,
    dialog: fixture.dialog,
    steps: [
      { id: "identity", title: "Identity" },
      { id: "review", title: "Review" },
    ],
    confirmDiscard: () => allowDiscard,
  });

  await controller.open({ launcher });
  await fixture.form.emit("input");
  assert.equal(controller.isDirty, true);
  assert.equal(await controller.requestClose(), false);
  assert.equal(fixture.dialog.open, true);
  allowDiscard = true;
  assert.equal(await controller.requestClose(), true);
  assert.equal(fixture.dialog.open, false);
  assert.equal(launcher.focused, true);
});

test("createWizard keeps recoverable submit errors open and can complete without closing", async () => {
  installBrowserGlobals();
  const fixture = wizardFixture(["review"]);
  let succeeds = false;
  const controller = createWizard({
    form: fixture.form,
    dialog: fixture.dialog,
    steps: [{ id: "review", title: "Review" }],
    onSubmit: async () => succeeds
      ? { ok: true, close: false }
      : { ok: false, message: "Server validation failed.", field: "review_field" },
  });
  await controller.open();
  await fixture.form.emit("input");

  await fixture.form.emit("submit");
  assert.equal(fixture.dialog.open, true);
  assert.equal(fixture.error.textContent, "Server validation failed.");
  assert.equal(controller.isDirty, true);
  succeeds = true;
  await fixture.form.emit("submit");
  assert.equal(fixture.dialog.open, true);
  assert.equal(controller.isDirty, false);
});
