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
     ${functionSource("vcfFqdnAllComponents")}
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

  suffix.value = "-new";
  context.ensure({ refreshDefaults: true });
  target.value = "vcf-9.1";
  context.ensure();
  assert.equal(context.reviewed("vc01"), "custom-vcenter");
  assert.equal(context.reviewed("nsx01"), "prod-nsx01-new");

  target.value = "vvf-9.1";
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
  assert.match(appSource, /hostnameInput\.setAttribute\("aria-label", `Hostname for \$\{component\.description \|\| component\.host\}`\)/);
  assert.match(appSource, /hostnameInput\.setAttribute\("aria-invalid", validationError \? "true" : "false"\)/);
  assert.match(appSource, /new FormData\(form\)/);
});

test("VCF creation stays disabled until Populate returns an exact review revision", () => {
  assert.match(appSource, /const populateButton = form\.querySelector\("\[data-vcf-fqdn-populate\]"\)/);
  assert.match(appSource, /populatedRevision\.value = String\(payload\.populated_revision \|\| ""\)/);
  assert.match(appSource, /const payload = await submitRequest\(`\$\{form\.action\}\/populate`, "populated"\)/);
  assert.match(appSource, /populatedRevision\.value = ""/);
  assert.match(appSource, /form\.addEventListener\("atlaso:vcf-fqdn-invalidate", \(event\) =>/);
  assert.match(appSource, /!vcfFqdnRowsAreValid\(\) \|\| !vcfFqdnIsPopulated\(\)/);
});

test("VCF planned addresses preview without masquerading as completed creation", () => {
  const context = vm.createContext({ Array, Boolean });
  vm.runInContext(
    `function vcfFqdnExistingData() { return { addressRecords: {} }; }
     function vcfFqdnCurrentFqdns() { return ["vc01.example.internal"]; }
     ${functionSource("vcfFqdnCompletionAddressFor")}
     ${functionSource("vcfFqdnRowsHaveAddresses")}
     globalThis.complete = vcfFqdnRowsHaveAddresses;`,
    context,
  );
  const planned = [{ fqdn: "vc01.example.internal", address: "192.168.50.10" }];
  const created = [{ fqdn: "vc01.example.internal", address: "192.168.50.10" }];
  assert.equal(context.complete({ planned }), false);
  assert.equal(context.complete({ created }), true);
});

test("VCF hostname review invalidation preserves the focused row", () => {
  assert.match(appSource, /detail: \{ preserveRows: true \}/);
  assert.match(appSource, /if \(preserveRows\) \{\s*refreshVcfFqdnRenderedRows\(\)/);
  assert.match(appSource, /const statusPayload = vcfFqdnIsPopulated\(\) \? payload : \{\}/);
});

test("VCF Populate discards responses superseded by later input", () => {
  assert.match(appSource, /let populationGeneration = 0/);
  assert.match(appSource, /populationGeneration \+= 1/);
  assert.match(appSource, /const requestGeneration = populationGeneration/);
  assert.match(appSource, /if \(requestGeneration !== populationGeneration\)/);
  assert.match(appSource, /inputs changed while Populate was running/);
});
