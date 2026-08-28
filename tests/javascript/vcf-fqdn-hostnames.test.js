const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const appSource = fs.readFileSync("atlaso/app/static/app.js", "utf8");

function functionSource(name) {
  const start = appSource.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must exist in app.js`);
  const parametersStart = appSource.indexOf("(", start);
  let parameterDepth = 0;
  let bodyStart = -1;
  for (let index = parametersStart; index < appSource.length; index += 1) {
    if (appSource[index] === "(") parameterDepth += 1;
    if (appSource[index] === ")") {
      parameterDepth -= 1;
      if (parameterDepth === 0) {
        bodyStart = appSource.indexOf("{", index);
        break;
      }
    }
  }
  assert.notEqual(bodyStart, -1, `${name} must have a function body`);
  let depth = 0;
  for (let index = bodyStart; index < appSource.length; index += 1) {
    if (appSource[index] === "{") depth += 1;
    if (appSource[index] === "}") depth -= 1;
    if (depth === 0) return appSource.slice(start, index + 1);
  }
  throw new Error(`Unable to extract ${name}`);
}

class FakeElement {
  constructor() {
    this.dataset = {};
  }
}

class FakeInput extends FakeElement {
  constructor(value = "") {
    super();
    this.value = value;
  }
}

class FakeSelect extends FakeElement {
  constructor(value = "") {
    super();
    this.value = value;
  }
}

function hostnameStateScenario() {
  const rows = new FakeElement();
  rows.dataset.targetComponents = JSON.stringify({
    "vcf-9.1": [
      { host: "vc01", description: "vCenter" },
      { host: "nsx01", description: "NSX Manager" },
    ],
    "vvf-9.1": [
      { host: "vc01", description: "vCenter" },
      { host: "ops01", description: "VCF Operations" },
    ],
  });
  const target = new FakeSelect("vcf-9.1");
  const prefix = new FakeInput("lab-");
  const suffix = new FakeInput("-mgmt");
  const selectors = new Map([
    ["[data-vcf-fqdn-rows]", rows],
    ["[data-vcf-fqdn-target]", target],
    ["[data-vcf-fqdn-prefix]", prefix],
    ["[data-vcf-fqdn-suffix]", suffix],
  ]);
  const context = vm.createContext({
    document: { querySelector: (selector) => selectors.get(selector) || null },
    HTMLElement: FakeElement,
    HTMLInputElement: FakeInput,
    HTMLSelectElement: FakeSelect,
    JSON,
    Map,
    String,
  });
  vm.runInContext(
    `const vcfFqdnHostnameState = new Map();
     ${functionSource("vcfFqdnRowsElement")}
     ${functionSource("vcfFqdnComponents")}
     ${functionSource("vcfFqdnHostLabel")}
     ${functionSource("vcfFqdnPatternValues")}
     ${functionSource("vcfFqdnDefaultHostLabel")}
     ${functionSource("vcfFqdnEnsureHostnameState")}
     ${functionSource("vcfFqdnReviewedHostLabel")}
     globalThis.ensure = vcfFqdnEnsureHostnameState;
     globalThis.reviewed = (host) => vcfFqdnReviewedHostLabel(vcfFqdnComponents().find((row) => row.host === host));
     globalThis.override = (host, value) => vcfFqdnHostnameState.set(host, { value, overridden: true });
     globalThis.clear = () => vcfFqdnHostnameState.clear();`,
    context,
  );
  return { context, target, prefix, suffix };
}

test("VCF hostname defaults follow pattern changes while deliberate overrides survive catalog changes", () => {
  const { context, target, prefix, suffix } = hostnameStateScenario();
  context.ensure();
  assert.equal(context.reviewed("vc01"), "lab-vc01-mgmt");
  assert.equal(context.reviewed("nsx01"), "lab-nsx01-mgmt");

  context.override("vc01", "custom-vcenter");
  prefix.value = "prod-";
  context.ensure({ refreshDefaults: true });
  assert.equal(context.reviewed("vc01"), "custom-vcenter");
  assert.equal(context.reviewed("nsx01"), "prod-nsx01-mgmt");

  target.value = "vvf-9.1";
  context.ensure();
  assert.equal(context.reviewed("vc01"), "custom-vcenter");
  assert.equal(context.reviewed("ops01"), "prod-ops01-mgmt");

  prefix.value = "";
  suffix.value = "";
  context.clear();
  context.ensure();
  assert.equal(context.reviewed("vc01"), "vc01");
  assert.equal(context.reviewed("ops01"), "ops01");
});

test("VCF hostname validation accepts one normalized DNS label and rejects unsafe labels", () => {
  const context = vm.createContext({ String });
  vm.runInContext(
    `${functionSource("vcfFqdnHostnameError")}
     globalThis.validate = vcfFqdnHostnameError;`,
    context,
  );
  assert.equal(context.validate("Custom-VC"), "");
  assert.match(context.validate(""), /required/);
  assert.match(context.validate("bad.name"), /one DNS label/);
  assert.match(context.validate("-bad"), /do not start or end/);
  assert.match(context.validate("a".repeat(64)), /1 to 63/);
});

test("VCF hostname rows submit immutable component keys beside reviewed values", () => {
  assert.match(appSource, /componentInput\.name = "component_key"/);
  assert.match(appSource, /hostnameInput\.name = "hostname"/);
  assert.match(appSource, /hostnameInput\.setAttribute\("aria-invalid", validationError \? "true" : "false"\)/);
  assert.match(appSource, /new FormData\(form\)/);
});
