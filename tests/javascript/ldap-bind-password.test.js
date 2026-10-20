const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync("atlaso/app/static/app.js", "utf8");
const start = source.indexOf("function ldapBindPasswordControls(");
const end = source.indexOf("function initializeLdapBindRotationWizard(", start);
assert.ok(start >= 0 && end > start);

class Control {
  constructor(value = "") { this.value = value; this.events = {}; }
  addEventListener(name, callback) { this.events[name] = callback; }
}

function harness() {
  const context = vm.createContext({ HTMLSelectElement: Control, HTMLInputElement: Control, HTMLTextAreaElement: Control, HTMLElement: Control, Event: class {}, window: { requestAnimationFrame: (callback) => callback() } });
  vm.runInContext(source.slice(start, end), context);
  const controls = {
    bind_password_mode: new Control("generated"),
    bind_password: new Control(),
    confirm_bind_password: new Control(),
  };
  const events = {};
  const form = {
    dataset: {},
    elements: { namedItem: (name) => controls[name] },
    addEventListener: (name, callback) => { events[name] = callback; },
  };
  context.initializeLdapBindCredentialFields(form);
  return { context, controls, events, form };
}

test("custom bind credentials require confirmation and never enter review text", () => {
  const { context, controls, form } = harness();
  const mode = controls.bind_password_mode;
  const password = controls.bind_password;
  const confirmation = controls.confirm_bind_password;
  assert.equal(password.disabled, true);
  mode.value = "custom";
  mode.events.change();
  assert.equal(password.disabled, false);
  assert.equal(password.required, true);
  assert.equal(context.validateLdapBindPasswordStep(form, { id: "credential" }).valid, false);
  password.value = "Synthetic-Only-Example42!";
  confirmation.value = "different";
  const mismatch = context.validateLdapBindPasswordStep(form, { id: "credential" });
  assert.equal(mismatch.valid, false);
  assert.equal(mismatch.field, "confirm_bind_password");
  assert.ok(!JSON.stringify(mismatch).includes(password.value));
  confirmation.value = password.value;
  assert.equal(context.validateLdapBindPasswordStep(form, { id: "credential" }).valid, true);
  assert.equal(context.ldapBindPasswordReviewValue(form), "Custom password");
});

test("switching to generation or resetting a wizard removes custom values", () => {
  const { context, controls, form } = harness();
  for (const reset of [
    () => { controls.bind_password_mode.value = "generated"; controls.bind_password_mode.events.change(); },
    () => context.resetLdapBindPasswordFields(form),
  ]) {
    controls.bind_password_mode.value = "custom";
    controls.bind_password_mode.events.change();
    controls.bind_password.value = controls.confirm_bind_password.value = "Synthetic-Only-Example42!";
    reset();
    assert.equal(controls.bind_password.value, "");
    assert.equal(controls.confirm_bind_password.value, "");
    assert.equal(controls.bind_password.disabled, true);
    assert.equal(controls.confirm_bind_password.required, false);
    assert.equal(context.ldapBindPasswordReviewValue(form), "Generated and shown once");
  }
});


test("a rejected bind wizard restores only non-secret values and announces its error", async () => {
  const { context, controls, form } = harness();
  controls.name = new Control();
  controls.description = new Control();
  controls.slug = new Control();
  controls.suffix_dn = new Control();
  controls.enabled = new Control();
  controls.enabled.type = "checkbox";
  controls.bind_password.value = "must be cleared";
  const retry = new Control();
  retry.dataset = {
    retryMode: "custom", retryStep: "credential", retryError: "Password policy rejected this value.",
    retryValues: JSON.stringify({ name: "Keep organization", description: "Keep description", slug: "keep-slug", suffix_dn: "dc=keep", enabled: false, bind_password: "never restore" }),
  };
  let removed = false;
  let dirty = false;
  let opened;
  let error;
  retry.remove = () => { removed = true; };
  form.querySelector = () => retry;
  form.dispatchEvent = () => { dirty = true; };
  const wizard = {
    open: async (options) => { opened = options; context.prepareLdapBindWizardOpen(form, options.context); },
    setError: (message, field) => { error = { message, field }; },
  };
  context.restoreLdapBindWizardError(form, wizard, "launcher");
  await Promise.resolve();
  assert.equal(removed, true);
  assert.equal(opened.step, "credential");
  assert.equal(opened.reset, false);
  assert.equal(controls.name.value, "Keep organization");
  assert.equal(controls.description.value, "Keep description");
  assert.equal(controls.slug.value, "keep-slug");
  assert.equal(controls.suffix_dn.value, "dc=keep");
  assert.equal(controls.enabled.checked, false);
  assert.equal(controls.bind_password_mode.value, "custom");
  assert.equal(controls.bind_password.value, "");
  assert.equal(controls.confirm_bind_password.value, "");
  assert.equal(controls.bind_password.required, true);
  assert.equal(error.field, "bind_password");
  assert.equal(error.message, retry.dataset.retryError);
  assert.equal(dirty, true);
});
