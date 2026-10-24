const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const app = fs.readFileSync("atlaso/app/static/app.js", "utf8");
const heightStart = app.indexOf("function dnsRecordsGridHeight(");
const heightEnd = app.indexOf("\nfunction resizeDnsRecordsTableElement(", heightStart);
const initStart = app.indexOf("function initializeCaCertificatesTable()");
const initEnd = app.indexOf("\nfunction caRequestStatusFormatter(", initStart);
assert(heightStart >= 0 && heightEnd > heightStart, "Missing production grid-height helper");
assert(initStart >= 0 && initEnd > initStart, "Missing production CA table initializer");

function createResizeHarness({ initiallyHidden = false, footerHeight = 0, resizeObserverEnabled = true } = {}) {
  const frames = new Map();
  let nextFrame = 0;
  const windowEvents = new Map();
  const observerTargets = [];
  const callbacks = new Map();
  const calls = { setHeight: [], redraw: 0 };
  const tabButtons = new Map();
  const panel = {
    querySelectorAll(selector) { return selector === "[data-tab-target]" ? [...tabButtons.values()] : []; },
  };
  let hidden = initiallyHidden;
  let width = 1200;
  let top = 120;
  const makeTabButton = (target) => {
    const listeners = new Map();
    const button = {
      dataset: { tabTarget: target },
      addEventListener(name, callback) { listeners.set(name, callback); },
      click() { listeners.get("click")?.(); },
    };
    tabButtons.set(target, button);
    return button;
  };
  makeTabButton("ca-certificates-panel");
  makeTabButton("ca-csr-panel");

  class Element {
    constructor() {
      this.dataset = { profileOptions: "[]", certificates: "[]" };
      this.style = { height: "" };
      this.isConnected = true;
    }
    addEventListener(name, callback) { this.listeners ??= new Map(); this.listeners.set(name, callback); }
    closest(selector) {
      if (selector === "[hidden], .hidden") return hidden ? {} : null;
      if (selector === ".wide-panel") return panel;
      return null;
    }
    getBoundingClientRect() { return { width, top }; }
  }
  class Observer {
    constructor(callback) { this.callback = callback; observerTargets.push(this); }
    observe(target) { this.targets ??= []; this.targets.push(target); }
  }
  const element = new Element();
  const table = {
    on(name, callback) { callbacks.set(name, callback); },
    setHeight(value) { calls.setHeight.push(value); },
    redraw() { calls.redraw += 1; },
  };
  const context = vm.createContext({
    HTMLElement: Element,
    ResizeObserver: resizeObserverEnabled ? Observer : undefined,
    JSON,
    document: {
      getElementById: () => element,
      querySelector: (selector) => selector === ".management-info-footnote"
        ? { getBoundingClientRect: () => ({ height: footerHeight }) }
        : null,
      querySelectorAll: () => [],
    },
    window: {
      innerWidth: 1600,
      innerHeight: 1000,
      addEventListener(name, callback) { windowEvents.set(name, callback); },
      requestAnimationFrame(callback) { const id = ++nextFrame; frames.set(id, callback); return id; },
      cancelAnimationFrame(id) { frames.delete(id); },
    },
    initializeAtlasoResourceWizard: () => ({ table }),
    newCaCertificateRow: () => ({}),
    managementUiPath: (path) => path,
  });
  vm.runInContext(
    `${app.slice(heightStart, heightEnd)}\n${app.slice(initStart, initEnd)}\ninitializeCaCertificatesTable();`,
    context,
  );
  const flushFrame = () => {
    const pending = [...frames.values()];
    frames.clear();
    pending.forEach((callback) => callback());
  };
  const setViewport = (viewportWidth, viewportHeight) => {
    context.window.innerWidth = viewportWidth;
    context.window.innerHeight = viewportHeight;
  };
  return {
    calls, callbacks, element, flushFrame, frames, observerTargets, setViewport, table, windowEvents,
    set hidden(value) { hidden = value; },
    clickCertificateTab() { hidden = false; tabButtons.get("ca-certificates-panel").click(); },
    clickAwayTab() { hidden = true; tabButtons.get("ca-csr-panel").click(); },
    panel,
    set connected(value) { element.isConnected = value; },
    set width(value) { width = value; },
    set top(value) { top = value; },
  };
}

test("CA grid resize waits for Tabulator tableBuilt before sizing", () => {
  const h = createResizeHarness();
  h.flushFrame();
  assert.deepEqual(h.calls.setHeight, []);
  assert.equal(h.calls.redraw, 0);

  h.callbacks.get("tableBuilt")();
  h.flushFrame();
  assert.deepEqual(h.calls.setHeight, ["856px"]);
  assert.equal(h.calls.redraw, 1);

  h.windowEvents.get("resize")();
  h.flushFrame();
  assert.deepEqual(h.calls.setHeight, ["856px"], "an unchanged visible height does not redraw the grid");
  assert.equal(h.calls.redraw, 1);
});

test("CA grid waits while initially hidden, then sizes after the certificate tab is selected", () => {
  const h = createResizeHarness({ initiallyHidden: true });
  h.callbacks.get("tableBuilt")();
  h.flushFrame();
  assert.deepEqual(h.calls.setHeight, []);
  assert.equal(h.calls.redraw, 0);

  h.clickCertificateTab();
  h.flushFrame();
  assert.deepEqual(h.calls.setHeight, ["856px"]);
  assert.equal(h.calls.redraw, 1);
});

test("selecting another CA tab clears the grid height without resizing the hidden grid", () => {
  const h = createResizeHarness();
  h.callbacks.get("tableBuilt")();
  h.flushFrame();
  assert.equal(h.element.style.height, "856px");

  h.clickAwayTab();
  h.flushFrame();
  assert.equal(h.element.style.height, "");
  assert.deepEqual(h.calls.setHeight, ["856px"]);
  assert.equal(h.calls.redraw, 1);
});

test("CA grid resize clears the CSS height without touching Tabulator while hidden", () => {
  const h = createResizeHarness();
  h.callbacks.get("tableBuilt")();
  h.flushFrame();
  assert.deepEqual(h.calls.setHeight, ["856px"]);

  h.hidden = true;
  h.element.style.height = "856px";
  h.windowEvents.get("resize")();
  h.flushFrame();
  assert.equal(h.element.style.height, "");
  assert.deepEqual(h.calls.setHeight, ["856px"]);
  assert.equal(h.calls.redraw, 1);
});

test("CA grid resize safely reapplies the same height when the tab becomes visible", () => {
  const h = createResizeHarness();
  h.callbacks.get("tableBuilt")();
  h.flushFrame();
  h.hidden = true;
  h.windowEvents.get("resize")();
  h.flushFrame();
  h.hidden = false;
  h.windowEvents.get("resize")();
  h.flushFrame();

  assert.equal(h.element.style.height, "856px");
  assert.deepEqual(h.calls.setHeight, ["856px", "856px"]);
  assert.equal(h.calls.redraw, 2);
});

test("CA grid resize observer safely handles hidden and visible transitions", () => {
  const h = createResizeHarness();
  h.callbacks.get("tableBuilt")();
  h.flushFrame();
  const [observer] = h.observerTargets;
  assert.ok(observer);
  assert.deepEqual(observer.targets, [h.element, h.panel]);

  h.hidden = true;
  observer.callback();
  h.flushFrame();
  assert.equal(h.element.style.height, "");
  assert.deepEqual(h.calls.setHeight, ["856px"]);

  h.hidden = false;
  observer.callback();
  h.flushFrame();
  assert.equal(h.element.style.height, "856px");
  assert.deepEqual(h.calls.setHeight, ["856px", "856px"]);
  assert.equal(h.calls.redraw, 2);
});

test("CA tab switching schedules resize when ResizeObserver is unavailable", () => {
  const h = createResizeHarness({ resizeObserverEnabled: false });
  h.callbacks.get("tableBuilt")();
  h.flushFrame();
  h.clickAwayTab();
  h.flushFrame();
  assert.equal(h.element.style.height, "");

  h.clickCertificateTab();
  h.flushFrame();
  assert.equal(h.element.style.height, "856px");
  assert.deepEqual(h.calls.setHeight, ["856px", "856px"]);
  assert.equal(h.calls.redraw, 2);
});

test("CA grid resize clears dynamic height for zero-width, disconnected, and narrow layouts", () => {
  const h = createResizeHarness();
  h.callbacks.get("tableBuilt")();
  h.flushFrame();
  h.width = 0;
  h.element.style.height = "856px";
  h.windowEvents.get("resize")();
  h.flushFrame();
  assert.equal(h.element.style.height, "");
  assert.deepEqual(h.calls.setHeight, ["856px"]);

  h.width = 1200;
  h.element.style.height = "856px";
  h.connected = false;
  h.windowEvents.get("resize")();
  h.flushFrame();
  assert.equal(h.element.style.height, "");
  assert.deepEqual(h.calls.setHeight, ["856px"]);

  h.connected = true;
  h.element.style.height = "856px";
  h.setViewport(900, 1200);
  h.windowEvents.get("resize")();
  h.flushFrame();
  assert.equal(h.element.style.height, "");
  assert.deepEqual(h.calls.setHeight, ["856px", ""]);
  assert.equal(h.calls.redraw, 2);
});

test("CA grid resize accounts for the footer and keeps its practical minimum height", () => {
  const h = createResizeHarness({ footerHeight: 40 });
  h.callbacks.get("tableBuilt")();
  h.flushFrame();
  assert.deepEqual(h.calls.setHeight, ["816px"]);

  h.top = 950;
  h.windowEvents.get("resize")();
  h.flushFrame();
  assert.deepEqual(h.calls.setHeight, ["816px", "300px"]);
});

test("CA grid resize coalesces callbacks into one animation frame", () => {
  const h = createResizeHarness();
  assert.equal(h.frames.size, 1);
  h.windowEvents.get("resize")();
  h.windowEvents.get("resize")();
  assert.equal(h.frames.size, 1);
  h.flushFrame();
  assert.deepEqual(h.calls.setHeight, []);
  assert.equal(h.observerTargets.length, 1);
});
