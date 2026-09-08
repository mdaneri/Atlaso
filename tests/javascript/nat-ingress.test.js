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
  const available = ["eth1", "eth2", "eth3"];
  assert.match(context.routesWanNatIngressError([], "eth1", available), /at least one/);
  assert.match(context.routesWanNatIngressError(["eth1"], "eth1", available), /different/);
  assert.match(context.routesWanNatIngressError(["missing"], "eth1", available), /available/);
  assert.equal(context.routesWanNatIngressError(["eth2", "eth3"], "eth1", available), "");
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
  const context = vm.createContext({ tagEditorValues: () => ["eth2", "eth3"] });
  vm.runInContext(extract("captureSourceGroupWizardDraft"), context);
  const draft = context.captureSourceGroupWizardDraft({
    elements: [{ name: "inbound_interfaces", type: "hidden", value: "eth2" }, { name: "inbound_interfaces", type: "hidden", value: "eth3" }],
    querySelectorAll: () => [{ dataset: { tagName: "inbound_interfaces" } }],
    getAttribute: () => "/routes-wan/nat-rules/4/edit",
  });
  assert.deepEqual(Array.from(draft.values.inbound_interfaces), ["eth2", "eth3"]);
  assert.equal(draft.editId, "4");
});


test("source-group return restores the shared ingress tag editor", () => {
  let restored;
  const editor = { atlasoTagEditor: { setValues: (values) => { restored = values; } } };
  const context = vm.createContext({ CSS: { escape: (name) => name }, window: { setTimeout: () => {} } });
  vm.runInContext(extract("applySourceGroupWizardDraft"), context);
  context.applySourceGroupWizardDraft({ querySelector: () => editor, querySelectorAll: () => [] },
    { values: { inbound_interfaces: ["eth2", "missing_abc.20"] } }, "input");
  assert.deepEqual(restored, ["eth2", "missing_abc.20"]);
});


test("dormant edits preserve missing ingress while enabling requires current targets", () => {
  const context = vm.createContext({});
  vm.runInContext(extract("routesWanNatIngressError"), context);
  assert.equal(context.routesWanNatIngressError([], "eth1", ["eth1"], true), "");
  assert.equal(context.routesWanNatIngressError(["missing_abc.20"], "eth1", ["eth1"], true), "");
  assert.match(context.routesWanNatIngressError([], "eth1", ["eth1"], false), /at least one/);
  assert.match(context.routesWanNatIngressError(["missing_abc.20"], "eth1", ["eth1"], false), /available/);
  assert.match(source, /\["translation", "state"\]\.includes\(step\.id\)/);
});


test("outbound dropdown preserves unavailable saved identities through edit", () => {
  const select = { options: [{ value: "eth1", dataset: {} }], value: "", add(option) { this.options.push(option); },
    querySelectorAll() { return this.options.filter((option) => option.dataset.unavailable); } };
  function Option(label, value) { this.text = label; this.value = value; this.dataset = {}; this.remove = () => { select.options = select.options.filter((option) => option !== this); }; }
  const context = vm.createContext({ Option });
  vm.runInContext(extract("restoreNatOutboundSelection"), context);
  context.restoreNatOutboundSelection(select, "missing_abc.20");
  assert.equal(select.value, "missing_abc.20");
  assert.match(select.options[1].text, /unavailable/);
  context.restoreNatOutboundSelection(select, "eth1");
  assert.equal(select.value, "eth1");
  assert.equal(select.options.length, 1);
  context.restoreNatOutboundSelection(select, "");
  assert.equal(select.value, "");
  assert.equal(select.options[1].text, "Needs outbound review");
});
const natAddressContext = vm.createContext({ Option: function (text, value) { this.text = text; this.value = value; } });
vm.runInContext(extract("syncNatTranslatedAddress"), natAddressContext);
test("fixed SNAT choices follow the egress and family and reject arbitrary values", () => {
  const select = { value: "gibberish", options: [], replaceChildren(...options) { this.options = options; }, add(option) { this.options.push(option); } };
  const outbound = { selectedOptions: [{ dataset: { natIpv4: "198.18.20.1", natIpv6: "fd75:3:20::1" } }] };
  natAddressContext.syncNatTranslatedAddress(select, outbound, "4");
  assert.equal(select.value, "");
  assert.deepEqual(select.options.map((option) => option.value), ["", "198.18.20.1"]);
  natAddressContext.syncNatTranslatedAddress(select, outbound, "6", "fd75:3:20::1");
  assert.equal(select.value, "fd75:3:20::1");
  outbound.selectedOptions[0].disabled = true;
  natAddressContext.syncNatTranslatedAddress(select, outbound, "6");
  assert.equal(select.value, "");
  assert.equal(select.options.length, 1);
});
