const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync("atlaso/app/static/app.js", "utf8");
function extract(name) {
  const start = source.indexOf(`function ${name}(`);
  assert.ok(start >= 0);
  const body = source.indexOf(") {", start) + 2;
  let depth = 0;
  for (let index = body; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    if (source[index] === "}") depth -= 1;
    if (depth === 0) return source.slice(start, index + 1);
  }
  throw new Error(`Missing function body: ${name}`);
}

test("ingress selection rejects empty, unavailable, and outbound targets", () => {
  const context = vm.createContext({});
  vm.runInContext(extract("routesWanNatIngressError"), context);
  const option = (value, fields = {}) => ({ value, selected: true, disabled: false, dataset: {}, ...fields });
  assert.match(context.routesWanNatIngressError([], "eth1"), /at least one/);
  assert.match(context.routesWanNatIngressError([option("eth1")], "eth1"), /different/);
  assert.match(context.routesWanNatIngressError([option("eth2", { dataset: { unavailable: "true" } })], "eth1"), /available/);
  assert.equal(context.routesWanNatIngressError([option("eth2"), option("eth3")], "eth1"), "");
});

test("inline enable submits every ingress member and the masquerade switch", async () => {
  let submitted;
  const context = vm.createContext({ FormData, fetch: async (_url, options) => { submitted = options.body; return { ok: true }; } });
  vm.runInContext(`async ${extract("postWanAction")}`, context);
  await context.postWanAction("/nat", { id: 3, inbound_interfaces: ["eth2", "eth3"], enabled: true, masquerade: true }, "csrf", { reload: false });
  assert.deepEqual(submitted.getAll("inbound_interfaces"), ["eth2", "eth3"]);
  assert.equal(submitted.get("masquerade"), "on");
  assert.equal(submitted.get("enabled"), "on");
});

test("source-group handoff preserves all selected ingress members", () => {
  const context = vm.createContext({});
  vm.runInContext(extract("captureSourceGroupWizardDraft"), context);
  const draft = context.captureSourceGroupWizardDraft({
    elements: [{ name: "inbound_interfaces", multiple: true, selectedOptions: [{ value: "eth2" }, { value: "eth3" }] }],
    getAttribute: () => "/routes-wan/nat-rules/4/edit",
  });
  assert.deepEqual(Array.from(draft.values.inbound_interfaces), ["eth2", "eth3"]);
  assert.equal(draft.editId, "4");
});
