const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const appSource = fs.readFileSync("atlaso/app/static/app.js", "utf8");

function functionSource(name) {
  const start = appSource.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must exist in app.js`);
  const bodyStart = appSource.indexOf(") {", start) + 2;
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
  `${functionSource("routesWanFeaturePillClass")}
   globalThis.pillClass = routesWanFeaturePillClass;`,
  context,
);

test("Routes and WAN feature states use truthful status colors", () => {
  assert.equal(context.pillClass("valid"), "good");
  assert.equal(context.pillClass("suspended"), "warn");
  assert.equal(context.pillClass("needs attention"), "warn");
  assert.equal(context.pillClass("disabled"), "muted");
});

test("Routes and WAN settings subscribe to autosave and refresh rendered state", () => {
  const initializer = functionSource("initializeRoutesWanSettings");
  const updater = functionSource("updateRoutesWanSettingsState");
  assert.match(initializer, /atlaso:autosave-success/);
  assert.match(initializer, /updateRoutesWanSettingsState/);
  assert.match(initializer, /natInput\.disabled = !routingInput\.checked/);
  assert.match(initializer, /natFallbackInput\.value = natInput\.checked \? "on" : "off"/);
  assert.match(initializer, /routingInput\.addEventListener\("change", \(\) => \{\s+syncNatFallback\(\)/);
  assert.match(updater, /data-routes-wan-feature-state/);
  assert.match(updater, /data-routes-wan-validation-status/);
  assert.match(updater, /data-routes-wan-config-preview/);
  assert.match(updater, /Suspended until Routing is enabled/);
  assert.match(updater, /natInput\.disabled = !Boolean\(payload\.routing_enabled\)/);
  assert.match(appSource, /DOMContentLoaded", \(\) => initializeRoutesWanSettings\(\)/);
});

test("shared switch fields do not toggle disabled controls", () => {
  const initializer = functionSource("initializeSwitchFields");
  assert.match(initializer, /if \(input\.disabled\)/);
  assert.match(initializer, /return;/);
});
