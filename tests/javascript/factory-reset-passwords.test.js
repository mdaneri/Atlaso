const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function fixture() {
  class Element {
    constructor() {
      this.events = {}; this.dataset = {}; this.value = ""; this.checked = false;
      this.classes = new Set(); this.classList = { add: (name) => this.classes.add(name) };
    }
    addEventListener(name, handler) { (this.events[name] ||= []).push(handler); }
    emit(name) {
      const event = { currentTarget: this, preventDefault() {}, stopImmediatePropagation() {} };
      for (const handler of this.events[name] || []) handler(event);
    }
    focus() { this.focused = true; }
    setCustomValidity(message) { this.validation = message; }
  }
  class Form extends Element {}
  class Dialog extends Element {
    showModal() { this.open = true; }
    close() { this.open = false; this.emit("close"); }
  }
  const form = new Form();
  const editor = new Form();
  const dialog = new Dialog();
  const title = new Element();
  const cancel = new Element();
  const window = new Element();
  const password = new Element();
  const confirmation = new Element();
  editor.elements = { namedItem: (name) => name === "password" ? password : confirmation };
  editor.reset = () => { password.value = ""; confirmation.value = ""; };
  editor.reportValidity = () => Boolean(password.value && confirmation.value && !confirmation.validation);
  dialog.querySelector = () => cancel;
  const fields = {};
  const selectors = {};
  const accounts = {};
  for (const account of ["admin", "root"]) {
    accounts[account] = {};
    for (const name of ["password", "password_confirm"]) fields[`${account}_${name}`] = new Element();
    for (const action of ["keep", "change"]) {
      const input = new Element();
      input.checked = action === "keep";
      accounts[account][action] = input;
      selectors[`input[name="${account}_password_action"][value="${action}"]`] = input;
    }
    for (const key of ["status", "fields", "controls", "open"]) {
      selectors[`[data-reset-password-${key}="${account}"]`] = accounts[account][key] = new Element();
    }
  }
  form.elements = { namedItem: (name) => fields[name] };
  form.querySelector = (selector) => selectors[selector];
  const document = {
    querySelector: () => form,
    getElementById: (id) => ({
      "factory-reset-password-modal": dialog,
      "factory-reset-password-dialog-form": editor,
      "factory-reset-password-title": title,
    })[id],
  };
  const source = fs.readFileSync(path.join(__dirname, "../../atlaso/app/static/app.js"), "utf8");
  const start = source.indexOf("function initializeFactoryResetPasswords() {");
  const end = source.indexOf("function initializeUserPasswordForm()", start);
  vm.runInNewContext(`${source.slice(start, end)}\ninitializeFactoryResetPasswords();`, {
    document, window, HTMLFormElement: Form, HTMLDialogElement: Dialog, HTMLInputElement: Element,
    initializePasswordToggles() {}, resetPasswordVisibility() {},
  });
  return { form, editor, dialog, cancel, password, confirmation, fields, accounts, window };
}

for (const account of ["admin", "root"]) {
  test(`${account}: prepare, cancel edits, keep and page exit clear values`, () => {
    const f = fixture();
    const a = f.accounts[account];
    assert.equal(a.fields.hidden, true);
    assert.equal(a.fields.classes.has("hidden"), true);
    a.open.emit("click");
    f.password.value = "synthetic-test-value";
    f.confirmation.value = "different";
    f.editor.emit("submit");
    assert.equal(f.dialog.open, true);
    assert.equal(f.fields[`${account}_password`].value, "");
    f.confirmation.value = f.password.value;
    f.editor.emit("submit");
    assert.equal(f.dialog.open, false);
    assert.equal(a.change.checked, true);
    assert.equal(f.fields[`${account}_password`].value, "synthetic-test-value");
    assert.equal(f.password.value, "");
    a.open.emit("click");
    f.password.value = "discard-this-edit";
    f.cancel.emit("click");
    assert.equal(f.fields[`${account}_password`].value, "synthetic-test-value");
    assert.equal(f.password.value, "");
    a.keep.checked = true;
    a.keep.emit("change");
    assert.equal(f.fields[`${account}_password`].value, "");
    f.fields[`${account}_password`].value = "ephemeral";
    f.window.emit("pagehide");
    assert.equal(f.fields[`${account}_password`].value, "");
  });
}

test("missing prepared password opens editor before reset confirmation", () => {
  const f = fixture();
  f.accounts.admin.change.checked = true;
  f.form.emit("submit");
  assert.equal(f.dialog.open, true);
  f.cancel.emit("click");
  assert.equal(f.accounts.admin.keep.checked, true);
});
