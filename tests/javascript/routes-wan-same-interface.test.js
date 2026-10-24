const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const appSource = fs.readFileSync("atlaso/app/static/app.js", "utf8");
const templateSource = fs.readFileSync("atlaso/app/templates/routes_wan.html", "utf8");

test("same-interface detection is local to the routing grid initializer", () => {
  assert.match(appSource, /data\.source_interface && data\.source_interface === data\.destination_interface/);
  assert.match(appSource, /source\?\.value && source\.value === destination\?\.value/);
});

test("wizard review describes routed destinations for a same-interface permission", () => {
  assert.match(appSource, /Same-interface gateway · \$\{sourceLabel\} source prefix → any routed destination via \$\{destinationLabel\}/);
  assert.doesNotMatch(appSource, /Routing source and destination must be different/);
});

test("routing table and no-JavaScript view distinguish same-interface gateway intent", () => {
  assert.match(appSource, /same-interface gateway/);
  assert.match(appSource, /Any routed destination via/);
  assert.match(templateSource, /Same-interface gateway/);
  assert.match(templateSource, /any routed destination/);
  assert.match(templateSource, /same interface at both ends/);
});
