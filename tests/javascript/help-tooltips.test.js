const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync("atlaso/app/static/app.js", "utf8");
const start = source.indexOf("function initializeHelpTooltips() {");
const end = source.indexOf("function initializeSecretToggles()", start);
assert.ok(start >= 0 && end > start);
const initialize = source.slice(start, end) + "\ninitializeHelpTooltips();";

class Element {
  constructor(tag = "div") {
    this.tag = tag;
    this.attrs = new Map();
    this.style = {};
    this.dataset = {};
    this.children = [];
    this.listeners = new Map();
    this.hidden = false;
    this.isConnected = true;
    this.offsetWidth = 180;
    this.offsetHeight = 60;
    this.textContent = "";
    this.rect = { left: 100, top: 100, width: 16, height: 16, bottom: 116 };
  }
  get childNodes() { return this.children; }

  append(child) {
    if (child.parent) child.parent.children = child.parent.children.filter((item) => item !== child);
    child.parent = this; child.parentElement = this; this.children.push(child);
  }
  setAttribute(name, value) { this.attrs.set(name, value); }
  getAttribute(name) { return this.attrs.get(name) ?? null; }
  hasAttribute(name) { return this.attrs.has(name); }
  removeAttribute(name) { this.attrs.delete(name); }
  matches(selector) {
    if (selector === ":popover-open") return !!this.popoverOpen;
    if (selector === ".help-icon[data-help]") return this.tag === "button" && this.className === "help-icon" && !!this.dataset.help;
    return false;
  }
  closest(selector) {
    for (let current = this; current; current = current.parent) {
      if (selector === "button.help-icon[data-help]" && current.matches(".help-icon[data-help]")) return current;
      if (selector === ".field-label" && current.className === "field-label") return current;
      if (selector === "dialog[open]" && current.tag === "dialog" && current.hasAttribute("open")) return current;
    }
    return null;
  }
  contains(other) {
    for (let current = other; current; current = current.parent) if (current === this) return true;
    return false;
  }
  querySelector(selector) {
    if (selector === ":scope > span:first-child") return this.children.find((child) => child.tag === "span") || null;
    if (selector === "[aria-label], [title]") {
      for (const child of this.children) {
        if (child.hasAttribute("aria-label") || child.hasAttribute("title")) return child;
        const nested = child.querySelector(selector);
        if (nested) return nested;
      }
    }
    return null;
  }
  querySelectorAll(selector) {
    const found = [];
    for (const child of this.children) {
      if (selector === "button.help-icon[data-help]" && child.matches(".help-icon[data-help]")) found.push(child);
      found.push(...child.querySelectorAll(selector));
    }
    return found;
  }
  addEventListener(name, callback) { (this.listeners.get(name) || this.listeners.set(name, []).get(name)).push(callback); }
  emit(name, event = {}) { for (const callback of this.listeners.get(name) || []) callback(event); }
  getBoundingClientRect() { return this.rect; }
  showPopover() { this.popoverOpen = true; }
  hidePopover() { this.popoverOpen = false; }
}
class HTMLButtonElement extends Element { constructor() { super("button"); this.className = "help-icon"; this.textContent = "i"; } }

function fixture() {
  let notifyMutation;
  const body = new Element("body");
  const label = new Element("label"); label.className = "field-label";
  const title = new Element("span"); title.textContent = "Server address";
  const button = new HTMLButtonElement(); button.dataset.help = "Long help text"; button.setAttribute("tabindex", "-1");
  label.append(title); label.append(button); body.append(label);
  const document = new Element("document");
  document.body = body;
  document.documentElement = { classList: { names: new Set(), add(name) { this.names.add(name); } } };
  document.querySelectorAll = (selector) => body.querySelectorAll(selector);
  document.createElement = (tag) => new Element(tag);
  document.activeElement = body;
  const window = new Element("window"); window.innerWidth = 320; window.innerHeight = 240;
  const context = { document, window, Element, HTMLButtonElement, MutationObserver: class {
    constructor(callback) { notifyMutation = callback; }
    observe() {}
  } };
  vm.runInNewContext(initialize, context);
  const tooltip = body.children.at(-1);
  const event = (target, relatedTarget = null) => ({ target, relatedTarget, prevented: false,
    preventDefault() { this.prevented = true; }, stopPropagation() {} });
  return { body, button, document, window, tooltip, event, notifyMutation };
}

test("only the help button opens the tooltip; hover exit closes it", () => {
  const { body, button, document, tooltip, event } = fixture();
  assert.equal(button.getAttribute("tabindex"), null);
  assert.equal(button.getAttribute("aria-label"), "Help for Server address");
  assert.equal(document.documentElement.classList.names.has("atlaso-help-ready"), true);
  document.emit("pointerover", event(body));
  assert.equal(tooltip.hidden, true);
  document.emit("pointerover", event(button));
  assert.equal(tooltip.textContent, "Long help text");
  assert.equal(tooltip.popoverOpen, true);
  assert.equal(button.getAttribute("aria-describedby"), tooltip.id);
  document.emit("pointerout", event(button, body));
  assert.equal(tooltip.hidden, true);
  assert.equal(button.getAttribute("aria-describedby"), null);
});

test("focus exposes help, Escape dismisses it, and click can pin or toggle it", () => {
  const { body, button, document, tooltip, event } = fixture();
  document.activeElement = button;
  document.emit("focusin", event(button));
  assert.equal(tooltip.hidden, false);
  const escape = { key: "Escape", prevented: false, preventDefault() { this.prevented = true; }, stopPropagation() {} };
  document.emit("keydown", escape);
  assert.equal(escape.prevented, true);
  assert.equal(tooltip.hidden, true);
  const click = event(button);
  document.emit("click", click);
  assert.equal(click.prevented, true);
  document.emit("pointerout", event(button, body));
  assert.equal(tooltip.hidden, false);
  document.emit("click", event(button));
  assert.equal(tooltip.hidden, true);
  document.emit("click", event(button));
  document.emit("click", event(body));
  assert.equal(tooltip.hidden, true);
});

test("viewport placement flips and shifts the top-layer tooltip", () => {
  const { button, document, window, tooltip, event } = fixture();
  button.rect = { left: 295, top: 5, width: 16, height: 16, bottom: 21, right: 311 };
  document.emit("pointerover", event(button));
  assert.equal(tooltip.style.left, "132px");
  assert.equal(tooltip.style.top, "29px");
  button.rect = { left: 2, top: 215, width: 16, height: 16, bottom: 231, right: 18 };
  window.emit("scroll");
  assert.equal(tooltip.style.left, "8px");
  assert.equal(tooltip.style.top, "147px");
  button.rect = { left: 2, top: -40, width: 16, height: 16, bottom: -24, right: 18 };
  window.emit("scroll");
  assert.equal(tooltip.hidden, true);
  const css = fs.readFileSync("atlaso/app/static/app.css", "utf8");
  assert.match(css, /\.atlaso-help-tooltip\s*\{[^}]*position: fixed;/s);
  assert.match(css, /html:not\(\.atlaso-help-ready\) \.help-icon\[data-help\]::after/);
  assert.match(css, /content: attr\(data-help\);/);
  assert.match(css, /html:not\(\.atlaso-help-ready\) \.help-icon\[data-help\]::after\s*\{[^}]*max-height:[^;]+;[^}]*overflow-y: auto;/s);
  assert.match(css, /html:not\(\.atlaso-help-ready\) \.help-icon\[data-help\]:focus::after\s*\{[^}]*visibility: visible;[^}]*pointer-events: auto;/s);
});

test("help inside a modal stays in the modal's accessible subtree", () => {
  const { body, button, document, tooltip, event } = fixture();
  const dialog = new Element("dialog"); dialog.setAttribute("open", "");
  body.append(dialog);
  dialog.append(button.parent);
  document.activeElement = button;
  document.emit("focusin", event(button));
  assert.equal(tooltip.parentElement, dialog);
  assert.equal(tooltip.popoverOpen, true);
  assert.equal(button.getAttribute("aria-describedby"), tooltip.id);
  const escape = { key: "Escape", prevented: false, preventDefault() { this.prevented = true; }, stopPropagation() {} };
  document.emit("keydown", escape);
  assert.equal(escape.prevented, true);
  assert.equal(tooltip.hidden, true);
  assert.equal(dialog.hasAttribute("open"), true);
});

test("generated help names follow changing headings while authored names stay intact", () => {
  const { button, document, event, notifyMutation } = fixture();
  assert.equal(button.getAttribute("aria-label"), "Help for Server address");
  button.parent.children[0].textContent = "Signed release base URL";
  notifyMutation([{ target: button.parent.children[0], addedNodes: [] }]);
  assert.equal(button.getAttribute("aria-label"), "Help for Signed release base URL");
  button.parent.children[0].textContent = "Another URL label";
  document.emit("pointerover", event(button));
  assert.equal(button.getAttribute("aria-label"), "Help for Another URL label");
  button.setAttribute("aria-label", "Authored help name");
  button.parent.children[0].textContent = "Repository URL";
  document.emit("focusin", event(button));
  assert.equal(button.getAttribute("aria-label"), "Authored help name");
});

test("icon-only sibling actions name their help from the action's accessible label", () => {
  const { body, document, event } = fixture();
  const label = new Element("span"); label.className = "field-label";
  const action = new Element("button"); action.textContent = "↻";
  action.setAttribute("aria-label", "Synchronize repositories");
  const help = new HTMLButtonElement(); help.dataset.help = "Synchronization details";
  label.append(action); label.append(help); body.append(label);
  document.activeElement = help;
  document.emit("focusin", event(help));
  assert.equal(help.getAttribute("aria-label"), "Help for Synchronize repositories");
});

test("zoom help uses the nested input's accessible label instead of its percent suffix", () => {
  const { body, document, event } = fixture();
  const label = new Element("span"); label.className = "field-label";
  const display = new Element("span"); display.textContent = "%";
  const input = new Element("input"); input.setAttribute("aria-label", "Chart zoom percentage");
  display.append(input);
  const help = new HTMLButtonElement(); help.dataset.help = "Zoom details";
  label.append(display); label.append(help); body.append(label);
  document.activeElement = help;
  document.emit("focusin", event(help));
  assert.equal(help.getAttribute("aria-label"), "Help for Chart zoom percentage");
});
