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

test("Source Group wizard draft captures add and edit state without CSRF", () => {
  const context = vm.createContext({ Date });
  vm.runInContext(`${functionSource("captureSourceGroupWizardDraft")}; this.capture = captureSourceGroupWizardDraft;`, context);
  const form = {
    action: { value: "accept" },
    getAttribute: (name) => name === "action" ? "/ui/management/firewall/rules/42/edit" : null,
    elements: [
      { name: "csrf", type: "hidden", value: "secret" },
      { name: "name", type: "text", value: "allow-app" },
      { name: "action", type: "select-one", value: "accept" },
      { name: "source", type: "select-one", value: "group:custom:apps" },
      { name: "enabled", type: "checkbox", checked: false },
    ],
  };

  const draft = context.capture(form);
  assert.equal(draft.editId, "42");
  assert.deepEqual(JSON.parse(JSON.stringify(draft.values)), {
    name: "allow-app",
    action: "accept",
    source: "group:custom:apps",
    enabled: false,
  });
  assert.equal(Object.hasOwn(draft.values, "csrf"), false);
});

test("Source Group draft storage falls back to the same browser tab when Web Storage is unavailable", () => {
  const context = vm.createContext({
    window: {
      name: "",
      sessionStorage: {
        setItem() { throw new Error("disabled"); },
        getItem() { throw new Error("disabled"); },
      },
    },
  });
  vm.runInContext(`
    const SOURCE_GROUP_DRAFT_WINDOW_PREFIX = "atlaso-source-group-draft:";
    ${functionSource("storeSourceGroupWizardDraft")}
    ${functionSource("loadSourceGroupWizardDraft")}
    this.storeDraft = storeSourceGroupWizardDraft;
    this.loadDraft = loadSourceGroupWizardDraft;
  `, context);

  const draft = { values: { name: "branch-web", source: "group:custom:branch" } };
  assert.equal(context.storeDraft("atlaso:source-group-return:firewall-rule", draft), true);
  assert.deepEqual(
    JSON.parse(JSON.stringify(context.loadDraft("atlaso:source-group-return:firewall-rule"))),
    draft,
  );
});

test("Source Group usage formatter renders persisted labels through textContent", () => {
  class FakeElement {
    constructor(tagName) {
      this.tagName = tagName;
      this.className = "";
      this.textContent = "";
      this.children = [];
    }

    append(...children) {
      this.children.push(...children);
    }
  }

  const context = vm.createContext({
    document: { createElement: (tagName) => new FakeElement(tagName) },
  });
  vm.runInContext(`${functionSource("sourceGroupUsageFormatter")}; this.formatter = sourceGroupUsageFormatter;`, context);
  const value = context.formatter({
    getRow: () => ({
      getData: () => ({
        consumer_count: 1,
        usage_summary: '<img src=x onerror="alert(1)">',
      }),
    }),
  });

  assert.equal(value.children[0].textContent, "1 consumer");
  assert.equal(value.children[1].textContent, '<img src=x onerror="alert(1)">');
  assert.equal(value.children[1].children.length, 0);
});

test("Source Group draft restoration rejects a removed server-rendered option and restores focus", () => {
  class FakeSelect {
    constructor(options) {
      this.options = options.map((value) => ({ value }));
      this.value = "any";
      this.validityMessage = "";
      this.listeners = {};
    }

    setCustomValidity(message) {
      this.validityMessage = message;
    }

    addEventListener(name, callback) {
      this.listeners[name] = callback;
    }

    dispatchEvent() {}

    focus() {
      this.focused = true;
    }
  }

  const source = new FakeSelect(["any", "group:custom:current"]);
  const form = {
    querySelectorAll(selector) {
      if (selector === '[name="source"]') return [source];
      if (selector === "select, textarea, input") return [source];
      return [];
    },
    querySelector(selector) {
      return selector === 'select[name="source"]' ? source : null;
    },
  };
  const context = vm.createContext({
    CSS: { escape: (value) => value },
    Event: class Event {},
    HTMLSelectElement: FakeSelect,
    window: { setTimeout: (callback) => callback() },
  });
  vm.runInContext(`${functionSource("applySourceGroupWizardDraft")}; this.applyDraft = applySourceGroupWizardDraft;`, context);

  context.applyDraft(form, { values: { source: "group:custom:removed" } }, 'select[name="source"]');
  assert.equal(source.value, "");
  assert.match(source.validityMessage, /no longer available/i);
  assert.equal(source.focused, true);
});
