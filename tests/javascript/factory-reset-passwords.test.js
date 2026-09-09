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
    close(value) { this.returnValue = value; this.open = false; this.emit("close"); }
  }
  const form = new Form();
  const editor = new Form();
  const dialog = new Dialog();
  const title = new Element();
  const error = new Element();
  const confirmationCalls = [];
  const final = { accepted: false };
  form.requestSubmit = () => { form.submitted = true; };
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
      "factory-reset-password-error": error,
    })[id],
  };
  const source = fs.readFileSync(path.join(__dirname, "../../atlaso/app/static/app.js"), "utf8");
  const start = source.indexOf("function initializeFactoryResetPasswords() {");
  const end = source.indexOf("function initializeUserPasswordForm()", start);
  vm.runInNewContext(`${source.slice(start, end)}\ninitializeFactoryResetPasswords();`, {
    document, window, HTMLFormElement: Form, HTMLDialogElement: Dialog, HTMLInputElement: Element,
    initializePasswordToggles() {}, resetPasswordVisibility() {},
    requestConfirmation: async (options) => { confirmationCalls.push(options); return final.accepted; },
  });
  return { form, editor, dialog, cancel, password, confirmation, fields, accounts, window, error, confirmationCalls, final };
}


const settle = () => new Promise((resolve) => setImmediate(resolve));
for (const account of ["admin", "root"]) {
  test(`${account}: defer editor until reset and validate inline`, async () => {
    const f = fixture();
    f.accounts[account].change.checked = true;
    f.accounts[account].change.emit("change");
    assert.equal(f.dialog.open, undefined);
    assert.equal(f.accounts[account].fields.classes.has("hidden"), true);
    f.form.emit("submit");
    assert.equal(f.dialog.open, true);
    f.editor.emit("submit");
    assert.match(f.error.textContent, /Enter and confirm/);
    f.password.value = "synthetic-test-value";
    f.confirmation.value = "different";
    f.editor.emit("submit");
    assert.match(f.error.textContent, /does not match/);
    f.confirmation.value = f.password.value;
    f.editor.emit("submit");
    await settle();
    assert.equal(f.confirmationCalls.length, 1);
    assert.equal(f.form.submitted, undefined);
    assert.equal(f.fields[`${account}_password`].value, "");
  });
}
test("both changes are collected in order before final confirmation", async () => {
  const f = fixture();
  f.accounts.admin.change.checked = f.accounts.root.change.checked = true;
  f.final.accepted = true;
  f.form.emit("submit");
  f.password.value = f.confirmation.value = "administrator-test";
  f.editor.emit("submit");
  await settle();
  assert.equal(f.dialog.open, true);
  assert.equal(f.confirmationCalls.length, 0);
  f.password.value = f.confirmation.value = "root-test";
  f.editor.emit("submit");
  await settle();
  assert.equal(f.form.submitted, true);
  assert.equal(f.fields.admin_password.value, "administrator-test");
  assert.equal(f.fields.root_password.value, "root-test");
  f.window.emit("pagehide");
  assert.equal(f.fields.admin_password.value, "");
  assert.equal(f.fields.root_password.value, "");
});
test("cancel during the second dialog discards both passwords", async () => {
  const f = fixture();
  f.accounts.admin.change.checked = f.accounts.root.change.checked = true;
  f.form.emit("submit");
  f.password.value = f.confirmation.value = "administrator-test";
  f.editor.emit("submit");
  await settle();
  f.cancel.emit("click");
  await settle();
  assert.equal(f.confirmationCalls.length, 0);
  assert.equal(f.fields.admin_password.value, "");
  assert.equal(f.accounts.admin.change.checked, true);
});
test("keep both goes directly to final confirmation", async () => {
  const f = fixture();
  f.form.emit("submit");
  await settle();
  assert.equal(f.dialog.open, undefined);
  assert.equal(f.confirmationCalls.length, 1);
});
