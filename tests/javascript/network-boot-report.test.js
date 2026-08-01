const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync("atlaso/app/static/app.js", "utf8");

function loadFunction(name, nextName) {
  const functionSource = source
    .split(`function ${name}`, 2)[1]
    .split(`function ${nextName}`, 1)[0];
  return vm.runInNewContext(`(function ${name}${functionSource})`);
}

const networkBootReportValue = loadFunction(
  "networkBootReportValue",
  "networkBootAddressListOptions",
);
const networkBootAddressListOptions = loadFunction(
  "networkBootAddressListOptions",
  "appendNetworkBootReportFacts",
);

test("Network Boot report distinguishes empty v2 addresses from missing legacy data", () => {
  assert.equal(
    networkBootReportValue([], networkBootAddressListOptions(false)),
    "None",
  );
  assert.equal(
    networkBootReportValue([], networkBootAddressListOptions(true)),
    "Not reported",
  );
  assert.equal(
    networkBootReportValue(undefined, networkBootAddressListOptions(false)),
    "Not reported",
  );
  assert.equal(
    networkBootReportValue(["192.0.2.10", "2001:db8::10"], networkBootAddressListOptions(false)),
    "192.0.2.10, 2001:db8::10",
  );
});

test("Network Boot report applies schema-aware address options to both address surfaces", () => {
  assert.match(
    source,
    /\["Assigned addresses", report\.assigned_addresses, networkBootAddressListOptions\(legacyReport\)\]/,
  );
  assert.match(
    source,
    /\["Addresses", "addresses", networkBootAddressListOptions\(legacyReport\)\]/,
  );
});
