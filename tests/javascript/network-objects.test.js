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

test("Source Group reference choices refresh safely after in-page mutations", () => {
  class FakeElement {
    constructor(tagName) {
      this.tagName = tagName;
      this.type = "";
      this.textContent = "";
      this.children = [];
      this.attributes = {};
    }

    append(...children) {
      this.children.push(...children);
    }

    replaceChildren(...children) {
      this.children = children;
    }

    setAttribute(name, value) {
      this.attributes[name] = String(value);
    }
  }

  const container = new FakeElement("div");
  const editor = new FakeElement("div");
  let refreshCount = 0;
  editor.atlasoTagEditor = { refreshMenu: () => { refreshCount += 1; } };
  editor.querySelector = (selector) => selector === "[data-tag-menu]" ? container : null;
  const context = vm.createContext({
    HTMLElement: FakeElement,
    document: {
      createElement: (tagName) => new FakeElement(tagName),
      querySelector: (selector) => selector === "[data-network-object-source-group-tag-editor]" ? editor : null,
    },
  });
  vm.runInContext(`${functionSource("renderNetworkObjectSourceGroupReferences")}; this.renderReferences = renderNetworkObjectSourceGroupReferences;`, context);

  context.renderReferences([
    { id: "any", name: "Any", builtin: true },
    { id: "custom:apps", name: '<img src=x onerror="alert(1)">', builtin: false },
  ]);
  assert.equal(container.children.length, 1);
  assert.equal(container.children[0].type, "button");
  assert.equal(container.children[0].attributes["data-tag-option"], "group:custom:apps");
  assert.equal(container.children[0].children[0].textContent, '<img src=x onerror="alert(1)">');
  assert.equal(container.children[0].children[1].textContent, "group:custom:apps");

  context.renderReferences([{ id: "any", name: "Any", builtin: true }]);
  assert.equal(container.children.length, 0);
  assert.equal(refreshCount, 2);
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

    dispatchEvent(event) {
      this.listeners[event.type]?.();
    }

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
    Event: class Event {
      constructor(type) {
        this.type = type;
      }
    },
    HTMLSelectElement: FakeSelect,
    window: { setTimeout: (callback) => callback() },
  });
  vm.runInContext(`${functionSource("applySourceGroupWizardDraft")}; this.applyDraft = applySourceGroupWizardDraft;`, context);

  context.applyDraft(form, { values: { source: "group:custom:removed" } }, 'select[name="source"]');
  assert.equal(source.value, "");
  assert.match(source.validityMessage, /no longer available/i);
  assert.equal(source.focused, true);
  source.dispatchEvent({ type: "change" });
  assert.equal(source.validityMessage, "");
});

test("Source Group fallback Add control retains a wizard when Tabulator is unavailable", () => {
  const initializer = functionSource("initializeNetworkObjectSourceGroups");
  const adapter = functionSource("initializeAtlasoResourceWizard");

  assert.match(initializer, /addLauncherSelector: "\[data-network-object-source-group-open\]"/);
  assert.match(adapter, /document\.querySelectorAll\(config\.addLauncherSelector\)/);
  assert.match(adapter, /element\.addEventListener\("click"[\s\S]+\[data-atlaso-wizard-add\]/);
  assert.match(adapter, /if \(data\?\.is_new\) return/);
  assert.match(adapter, /if \(!table\) \{\s*window\.location\.reload\(\)/);
  assert.doesNotMatch(adapter, /return \{ grid, table: null, wizard: null \}/);
});

test("Source Group grid uses full panel height and compact shared density", () => {
  const initializer = functionSource("initializeNetworkObjectSourceGroups");
  assert.match(initializer, /height: "100%"/);
  assert.match(initializer, /rowHeight: 28/);
  assert.doesNotMatch(initializer, /ResizeObserver/);
  assert.doesNotMatch(initializer, /existingRows\.length[\s\S]+\* 42/);
});

test("Source Group submission keeps Any exclusive and deduplicates canonical tags", () => {
  class FakeInput {}
  const anySource = new FakeInput();
  anySource.checked = true;
  const tokens = [
    { dataset: { canonicalValue: "192.0.2.0/24" }, getAttribute: () => "192.0.2.9/24" },
    { dataset: { canonicalValue: "192.0.2.0/24" }, getAttribute: () => "192.0.2.0/24" },
    { dataset: { canonicalValue: "group:custom:apps" }, getAttribute: () => "@Apps" },
  ];
  const editor = { querySelectorAll: () => tokens };
  const form = {
    querySelector(selector) {
      if (selector === "[data-network-object-any-source]") return anySource;
      if (selector === "[data-network-object-source-group-tag-editor]") return editor;
      return null;
    },
  };
  const context = vm.createContext({ HTMLElement: class {}, HTMLInputElement: FakeInput });
  vm.runInContext(`
    ${functionSource("networkObjectSourceGroupTagEditor")}
    ${functionSource("networkObjectSourceGroupSubmissionEntries")}
    this.entries = networkObjectSourceGroupSubmissionEntries;
  `, context);

  assert.deepEqual(JSON.parse(JSON.stringify(context.entries(form))), ["any"]);
  anySource.checked = false;
  Object.setPrototypeOf(editor, context.HTMLElement.prototype);
  assert.deepEqual(
    JSON.parse(JSON.stringify(context.entries(form))),
    ["192.0.2.0/24", "group:custom:apps"],
  );
});

test("Source Group enhanced editor uses server validation and non-color tag states", () => {
  const validator = functionSource("validateNetworkObjectSourceGroupEntries");
  const decorator = functionSource("decorateNetworkObjectSourceGroupTag");
  const mode = functionSource("syncNetworkObjectSourceGroupMode");
  const initializer = functionSource("initializeNetworkObjectSourceGroups");
  assert.match(validator, /source-groups\/validate-entries/);
  assert.match(validator, /X-Atlaso-Grid/);
  assert.match(validator, /body\.set\("any_source", usesAny \? "1" : "0"\)/);
  assert.match(validator, /payload\.entries\.filter\(\(result\) => result\.state === "invalid"\)/);
  assert.match(decorator, /✓ Valid/);
  assert.match(decorator, /! Needs attention/);
  assert.match(decorator, /× Invalid/);
  assert.match(decorator, /aria-label/);
  assert.match(mode, /fallback\.classList\.add\("hidden"\)/);
  assert.match(mode, /anySourceField\.classList\.remove\("hidden"\)/);
  assert.match(
    initializer,
    /validateStep: async[\s\S]+window\.clearTimeout\(validationTimer\)[\s\S]+validationTimer = 0[\s\S]+await validateNetworkObjectSourceGroupEntries/,
  );
  assert.match(
    initializer,
    /prepareReview: async[\s\S]+await validateNetworkObjectSourceGroupEntries\(form\)[\s\S]+step: "entries"/,
  );
});

test("editable tags preserve native remove activation and disable every edit path", () => {
  const initializer = functionSource("initializeTagEditors");

  assert.match(initializer, /if \(event\.target !== token\) return/);
  assert.match(initializer, /if \(editorDisabled \|\| !editable \|\| token\.hasAttribute\("data-tag-locked"\)\) return/);
  assert.match(initializer, /if \(nextDisabled && editContext\) restoreEditedValue\(\)/);
  assert.match(initializer, /token\.tabIndex = nextDisabled \? -1 : 0/);
  assert.match(initializer, /token\.setAttribute\("aria-disabled", nextDisabled \? "true" : "false"\)/);
  assert.match(initializer, /if \(!event\.target\.closest\("\[data-tag-remove\]"\)\) beginEdit\(token\)/);
});
