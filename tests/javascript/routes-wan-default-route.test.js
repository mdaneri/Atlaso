const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const appSource = fs.readFileSync("atlaso/app/static/app.js", "utf8");

function functionSource(name) {
  const start = appSource.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must exist in app.js`);
  const bodyStart = appSource.indexOf(") {", start) + 2;
  assert.ok(bodyStart > 1, `${name} must have a function body`);
  let depth = 0;
  for (let index = bodyStart; index < appSource.length; index += 1) {
    if (appSource[index] === "{") depth += 1;
    if (appSource[index] === "}") depth -= 1;
    if (depth === 0) return appSource.slice(start, index + 1);
  }
  throw new Error(`Unable to extract ${name}`);
}

const context = vm.createContext({});
vm.runInContext(
  `${functionSource("routesWanAddressFamily")}
   ${functionSource("routesWanDefaultFamily")}
   ${functionSource("routesWanDestinationLabel")}
   ${functionSource("validateRoutesWanRoutePath")}
   globalThis.routeFamily = routesWanDefaultFamily;
   globalThis.routeLabel = routesWanDestinationLabel;
   globalThis.validatePath = validateRoutesWanRoutePath;`,
  context,
);

test("default destination helpers render semantic IPv4 and IPv6 labels", () => {
  assert.equal(context.routeFamily("0.0.0.0/0"), "4");
  assert.equal(context.routeFamily("192.0.2.42/0"), "4");
  assert.equal(context.routeFamily("::/0"), "6");
  assert.equal(context.routeFamily("2001:db8::42/0"), "6");
  assert.equal(context.routeFamily("10.20.0.0/24"), "");
  assert.equal(context.routeLabel("0.0.0.0/0"), "Default route (IPv4)");
  assert.equal(context.routeLabel("::/0"), "Default route (IPv6)");
});

test("default mode requires a same-family gateway", () => {
  const missingGateway = context.validatePath({
    defaultRouteSelected: true,
    defaultRouteFamily: "4",
    destinationCidr: "",
    gateway: "",
  });
  assert.equal(missingGateway.message, "A next-hop gateway is required for a default route.");
  assert.equal(missingGateway.fieldName, "gateway");
  const familyMismatch = context.validatePath({
    defaultRouteSelected: true,
    defaultRouteFamily: "6",
    destinationCidr: "",
    gateway: "192.168.20.254",
  });
  assert.equal(familyMismatch.message, "Default route gateway must use IPv6.");
  assert.equal(familyMismatch.fieldName, "gateway");
  assert.equal(
    context.validatePath({
      defaultRouteSelected: true,
      defaultRouteFamily: "6",
      destinationCidr: "",
      gateway: "2001:db8:20::fe",
    }),
    null,
  );
});

test("destination mode requires a CIDR but permits a directly connected path", () => {
  const missingDestination = context.validatePath({
    defaultRouteSelected: false,
    defaultRouteFamily: "4",
    destinationCidr: "",
    gateway: "",
  });
  assert.equal(missingDestination.message, "Destination CIDR is required.");
  assert.equal(missingDestination.fieldName, "destination_cidr");
  assert.equal(
    context.validatePath({
      defaultRouteSelected: false,
      defaultRouteFamily: "4",
      destinationCidr: "10.20.0.0/24",
      gateway: "",
    }),
    null,
  );
  assert.match(
    context.validatePath({
      defaultRouteSelected: false,
      defaultRouteFamily: "4",
      destinationCidr: "2001:db8:20::/64",
      gateway: "192.168.20.254",
    }).message,
    /family must match/,
  );
  const manualDefault = context.validatePath({
    defaultRouteSelected: false,
    defaultRouteFamily: "4",
    destinationCidr: "0.0.0.0/0",
    gateway: "192.0.2.1",
  });
  assert.match(manualDefault.message, /Select Default route/);
  assert.equal(manualDefault.fieldName, "default_route");
});

test("gateway family must be configured on the selected target", () => {
  const targetMismatch = context.validatePath({
    defaultRouteSelected: true,
    defaultRouteFamily: "6",
    destinationCidr: "",
    gateway: "2001:db8:20::fe",
    targetFamilies: ["4"],
  });
  assert.match(targetMismatch.message, /does not have a configured IPv6 CIDR/);
  assert.equal(targetMismatch.fieldName, "interface_name");
  assert.equal(
    context.validatePath({
      defaultRouteSelected: true,
      defaultRouteFamily: "6",
      destinationCidr: "",
      gateway: "fe80::1",
      targetFamilies: ["4", "6"],
    }),
    null,
  );
});

test("default-mode synchronization owns mutual exclusion and required state", () => {
  const source = functionSource("syncRoutesWanDefaultRouteMode");
  assert.match(source, /destination\.disabled = selected/);
  assert.match(source, /destination\.required = !selected/);
  assert.match(source, /family\.disabled = !selected/);
  assert.match(source, /family\.required = selected/);
  assert.match(source, /conditional-field-inactive/);
  assert.doesNotMatch(source, /destinationPanel\.hidden = selected/);
  assert.match(source, /gateway\.required = selected/);
});

test("inline Enabled saves submit default-route checkbox state", async () => {
  let submittedBody = null;
  class TestFormData {
    constructor() {
      this.values = new Map();
    }

    set(key, value) {
      this.values.set(key, value);
    }
  }
  const postContext = vm.createContext({
    FormData: TestFormData,
    fetch: async (_url, options) => {
      submittedBody = options.body;
      return { ok: true };
    },
    window: { location: { reload() {} } },
  });
  vm.runInContext(`async ${functionSource("postWanAction")} globalThis.postAction = postWanAction;`, postContext);

  await postContext.postAction(
    "/ui/management/routes-wan/routes/1/edit",
    { id: 1, destination_cidr: "0.0.0.0/0", default_route: true, default_route_family: "4", enabled: false },
    "csrf-token",
    { reload: false },
  );

  assert.equal(submittedBody.values.get("default_route"), "on");
  assert.equal(submittedBody.values.has("destination_cidr"), false);
  assert.equal(submittedBody.values.has("enabled"), false);
});
